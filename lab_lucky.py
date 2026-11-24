"""Independent Lucky adapter. Never return upstream configuration or secrets to clients."""
import copy
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit, quote

import requests
from cryptography.fernet import Fernet
from flask import Blueprint, jsonify, request


class LuckyError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def endpoint(value):
    p = urlsplit(str(value).strip())
    try:
        port = p.port
    except ValueError:
        raise LuckyError('端口须为 1–65535')
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise LuckyError('请输入完整 HTTP/HTTPS 地址，安全入口路径可保留')
    if port is not None and not 1 <= port <= 65535:
        raise LuckyError('端口须为 1–65535')
    return str(value).strip().rstrip('/')


def rule_fields(body):
    try:
        if not re.fullmatch(r'[0-9]+', str(body['port'])):
            raise ValueError()
        port = int(body['port'])
        if not 1 <= port <= 65535:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise LuckyError('监听端口须为 1–65535')
    domain = str(body.get('domain', '')).strip().lower()
    if not re.fullmatch(r'(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', domain) or '.' not in domain:
        raise LuckyError('请输入有效域名')
    backend = str(body.get('backend', '')).strip()
    p = urlsplit(backend)
    try:
        valid = p.scheme in ('http', 'https') and p.hostname and not p.username and not p.password and not p.fragment and (p.port is None or 1 <= p.port <= 65535)
    except ValueError:
        valid = False
    if not valid:
        raise LuckyError('后端须为有效 HTTP/HTTPS URL')
    name = str(body.get('name', '')).strip()
    if not name or len(name) > 120:
        raise LuckyError('请填写服务名称（最多 120 字）')
    return name, domain, backend, port, bool(body.get('tls'))


def subrule_editable(sub):
    return (sub.get('WebServiceType') == 'reverseproxy' and bool(sub.get('Domains'))
            and bool(sub.get('Locations')) and not (sub.get('OtherParams') or {}).get('BackendPool'))


def subrule_dto(sub):
    return {'id': sub.get('Key', ''), 'name': sub.get('Remark', ''),
            'domains': sub.get('Domains') or [], 'backends': sub.get('Locations') or [],
            'type': sub.get('WebServiceType', ''), 'enabled': bool(sub.get('Enable')),
            'editable': subrule_editable(sub)}


def subrule_fields(body):
    name = str(body.get('name', '')).strip()
    if len(name) > 120:
        raise LuckyError('子规则名称最多 120 字')
    domains, backends = body.get('domains'), body.get('backends')
    if (not isinstance(domains, list) or not domains or not isinstance(backends, list)
            or not backends or not all(isinstance(s, str) and s.strip() for s in domains + backends)):
        raise LuckyError('请填写域名和 HTTP/HTTPS 后端地址，每行一个')
    domains = list(dict.fromkeys(s.strip().lower() for s in domains))
    backends = list(dict.fromkeys(s.strip() for s in backends))
    for domain in domains:
        rule_fields(dict(name=name or '子规则', domain=domain, backend=backends[0], port=1))
    for backend in backends:
        rule_fields(dict(name=name or '子规则', domain=domains[0], backend=backend, port=1))
    return name, domains, backends


class LuckyStore:
    def __init__(self, root):
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = root / 'credential.key'
        # Publish a complete key atomically: two forked workers may start together.
        if not key.exists():
            fd, temp = tempfile.mkstemp(dir=root)
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(Fernet.generate_key())
                try:
                    os.link(temp, key)
                except FileExistsError:
                    pass
            finally:
                os.unlink(temp)
        self.cipher = Fernet(key.read_bytes())
        self.path = root / 'connections.db'
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY, name TEXT, url TEXT UNIQUE, secret BLOB)')
            db.execute('CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, digest TEXT, state TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS dns_accounts(id TEXT PRIMARY KEY, instance TEXT, name TEXT, secret BLOB)')
        os.chmod(self.path, 0o600)

    def db(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        return db

    def list(self):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT id,name,url FROM connections ORDER BY name')]

    def get(self, key):
        with self.db() as db:
            r = db.execute('SELECT * FROM connections WHERE id=?', (key,)).fetchone()
        if not r:
            raise LuckyError('Lucky 连接不存在', 404)
        return dict(r)

    def client(self, key):
        r = self.get(key)
        return LuckyClient(r['url'], self.cipher.decrypt(r['secret']).decode())

    def save(self, body):
        url = endpoint(body.get('url', ''))
        key = body.get('id') or str(uuid.uuid4())
        token = str(body.get('token', '')).strip()
        if not token and body.get('id'):
            token = self.cipher.decrypt(self.get(key)['secret']).decode()
        if not token or not str(body.get('name', '')).strip():
            raise LuckyError('请填写连接名称和 OpenToken')
        client = LuckyClient(url, token)
        client.rules()  # auth AND module readiness AND response schema
        client.certificates()
        with self.db() as db:
            try:
                db.execute('INSERT INTO connections VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,secret=excluded.secret',
                           (key, body['name'].strip(), url, self.cipher.encrypt(token.encode())))
            except sqlite3.IntegrityError:
                raise LuckyError('这个 Lucky 地址已经连接，请编辑已有连接')
        return key

    def once(self, operation, body, action):
        if not re.fullmatch(r'[a-zA-Z0-9-]{16,80}', operation or ''):
            raise LuckyError('缺少有效操作标识')
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        with self.db() as db:
            try:
                db.execute('INSERT INTO operations VALUES(?,?,?)', (operation, digest, 'pending'))
            except sqlite3.IntegrityError:
                old = db.execute('SELECT * FROM operations WHERE id=?', (operation,)).fetchone()
                if old['digest'] != digest:
                    raise LuckyError('操作标识已用于其他内容', 409)
                if old['state'] == 'done':
                    return
                raise LuckyError('上次操作结果待核对，请刷新 Lucky 列表后确认，勿重复新建', 409)
        action()
        with self.db() as db:
            db.execute("UPDATE operations SET state='done' WHERE id=?", (operation,))


class LuckyClient:
    def __init__(self, url, token):
        self.url, self.token = endpoint(url), token

    def call(self, method, path, body=None):
        try:
            r = requests.request(method, self.url + path, json=body,
                                 headers={'openToken': self.token}, timeout=(5, 25), allow_redirects=False)
            data = r.json()
        except requests.exceptions.SSLError:
            raise LuckyError('Lucky HTTPS 证书校验失败，请使用证书有效的域名，或 Hub 可达的 HTTP 内网地址', 502)
        except requests.exceptions.Timeout:
            raise LuckyError('Hub 连接 Lucky 超时，请核对管理地址与端口', 502)
        except (requests.RequestException, ValueError):
            raise LuckyError('Lucky 请求未确认，请刷新核对；检查地址、证书及网络', 502)
        if not isinstance(data, dict):
            raise LuckyError('Lucky 响应格式异常，请核对版本', 502)
        if r.status_code == 503 or data.get('ret') == -10:
            raise LuckyError('Lucky 模块正在启动，请稍后刷新', 503)
        if not r.ok or data.get('ret') != 0:
            if data.get('ret') == 4:
                raise LuckyError('规则已被其他操作修改，请刷新后重新编辑', 409)
            if data.get('msgCode') == 'NotMeetCertificateRenewalAdvanceTime':
                raise LuckyError('证书尚未进入续签窗口，无需续签')
            raise LuckyError('Lucky 拒绝操作，请检查 OpenToken、权限或后台日志', 502)
        return data

    def rules(self):
        data = self.call('GET', '/api/webservice/rules')
        if 'ruleList' in data and data['ruleList'] is None:
            data['ruleList'] = []  # Lucky serializes a genuinely empty Go slice as null.
        if not isinstance(data.get('ruleList'), list):
            raise LuckyError('Lucky 规则响应格式异常', 502)
        out = []
        for r in data['ruleList']:
            subs = r.get('ProxyList') or []
            simple = len(subs) == 1 and subs[0].get('WebServiceType') == 'reverseproxy' and len(subs[0].get('Locations') or []) == 1 and len(subs[0].get('Domains') or []) == 1
            routes = [subrule_dto(s) for s in subs]
            out.append({'id': r['RuleKey'], 'name': r.get('RuleName', ''), 'routes': routes,
                        'domain': ', '.join(dict.fromkeys(d for s in subs for d in (s.get('Domains') or []))),
                        'backend': ', '.join(dict.fromkeys(d for s in subs for d in (s.get('Locations') or []))),
                        'port': r.get('ListenPort'), 'tls': bool(r.get('EnableTLS')), 'subruleCount': len(subs),
                        'enabled': bool(r.get('Enable')), 'editable': simple})
        return out

    def certificates(self):
        data = self.call('GET', '/api/ssl')
        if 'list' in data and data['list'] is None:
            data['list'] = []
        if not isinstance(data.get('list'), list):
            raise LuckyError('Lucky 证书响应格式异常', 502)
        return data['list']


def register_lucky(app, root, authorized):
    store = LuckyStore(root)
    bp = Blueprint('lucky', __name__, url_prefix='/api/lucky')

    @bp.before_request
    def auth():
        if not authorized():
            return jsonify(ok=False, error='unauthorized'), 401

    @bp.errorhandler(LuckyError)
    def error(e):
        return jsonify(ok=False, error=str(e)), e.status

    @bp.route('/connections', methods=['GET', 'POST'])
    def connections():
        if request.method == 'POST':
            return jsonify(ok=True, id=store.save(request.get_json() or {}))
        return jsonify(ok=True, items=store.list())

    @bp.route('/connections/<key>', methods=['DELETE'])
    def disconnect(key):
        with store.db() as db:
            db.execute('DELETE FROM connections WHERE id=?', (key,))
            db.execute('DELETE FROM dns_accounts WHERE instance=?', (key,))
        return jsonify(ok=True)

    @bp.route('/connections/test', methods=['POST'])
    def test_connection():
        body = request.get_json() or {}
        token = str(body.get('token', '')).strip()
        if not token and body.get('id'):
            token = store.cipher.decrypt(store.get(body['id'])['secret']).decode()
        if not token:
            raise LuckyError('请填写 OpenToken')
        client = LuckyClient(endpoint(body.get('url', '')), token)
        client.rules()
        client.certificates()
        return jsonify(ok=True)

    @bp.route('/<key>/accounts', methods=['POST'])
    def add_account(key):
        store.get(key)
        body = request.get_json() or {}
        if not all(isinstance(body.get(k), str) and body[k].strip() for k in ('name', 'accessId', 'accessSecret')):
            raise LuckyError('请填写账户名称、AccessKey ID 和 Secret')
        # Only the DNS provider verified against this Lucky version is exposed.
        ext = {'acmeDNSServer': 'alidns', 'acmeDNSID': body['accessId'].strip(), 'acmeDNSSecret': body['accessSecret'].strip(),
               'acmeKeyType': '2048', 'acmeOnlyUseIPv4': True, 'acmeDNSForceIPv4': True,
               'acmePropagationTimeout': 120, 'acmeWaitforcertificateTimeout': 120, 'acmeEmail': ''}
        account = str(uuid.uuid4())
        with store.db() as db:
            db.execute('INSERT INTO dns_accounts VALUES(?,?,?,?)', (account, key, body['name'].strip(), store.cipher.encrypt(json.dumps(ext).encode())))
        return jsonify(ok=True, id=account)

    @bp.route('/<key>/rules', methods=['GET', 'POST'])
    def rules(key):
        client = store.client(key)
        if request.method == 'POST':
            body = request.get_json() or {}
            name, domain, backend, port, tls = rule_fields(body)
            sub = {'Key': '', 'Remark': name, 'Domains': [domain], 'Locations': [backend], 'Enable': True,
                   'WebServiceType': 'reverseproxy', 'OtherParams': {}, 'SafeIPMode': 'disable',
                   'SafeUserAgentMode': 'disable', 'BasicAuthUserList': '', 'SecurityGroupKeys': []}
            raw = {'RuleKey': '', 'RuleName': name, 'Network': 'tcp4', 'ListenIP': '0.0.0.0', 'ListenPort': port,
                   'EnableTLS': tls, 'Enable': True, 'IPFilterRule': 'disable', 'GlobalBasicAuthUserList': '',
                   'GlobalAllowThirdAuthLoginUserList': '', 'ProxyList': [sub],
                   'DefaultProxy': dict(sub, Enable=False, Domains=[], Locations=[])}
            store.once(body.get('operationId'), {'instance': key, 'rule': body}, lambda: client.call('POST', '/api/webservice/rules', raw))
            rows = client.rules()
            if not any(r['name'] == name and r['domain'] == domain and r['backend'] == backend and r['port'] == port and r['tls'] == tls for r in rows):
                raise LuckyError('新建回读尚未确认，请在 Lucky 后台核对，勿重复创建', 502)
            return jsonify(ok=True, items=rows)
        return jsonify(ok=True, items=client.rules())

    @bp.route('/<key>/rules/<rid>', methods=['GET', 'PUT', 'DELETE'])
    def rule(key, rid):
        client = store.client(key)
        path = '/api/webservice/rule/' + quote(rid, safe='')
        if request.method == 'DELETE':
            client.call('DELETE', path)
            if any(r['id'] == rid for r in client.rules()):
                raise LuckyError('删除尚未确认，请刷新核对', 502)
            return jsonify(ok=True)
        detail = client.call('GET', path)
        raw, version = detail['rule'], detail['version']
        if request.method == 'PUT':
            body = request.get_json() or {}
            if body.get('version') != version:
                raise LuckyError('规则已更新，请重新打开编辑', 409)
            if 'enabled' in body:
                raw['Enable'] = bool(body['enabled'])
            else:
                row = next(r for r in client.rules() if r['id'] == rid)
                if not row['editable']:
                    raise LuckyError('复杂规则请在 Lucky 后台编辑')
                name, domain, backend, port, tls = rule_fields(body)
                raw.update(RuleName=name, ListenPort=port, EnableTLS=tls)
                raw['ProxyList'][0].update(Domains=[domain], Locations=[backend])
            raw['ExpectedVersion'] = version
            client.call('PUT', path, raw)
            after = client.call('GET', path)
            expected = {k: v for k, v in raw.items() if k != 'ExpectedVersion'}
            if any(after['rule'].get(k) != v for k, v in expected.items() if k in ('RuleName', 'ListenPort', 'EnableTLS', 'Enable', 'ProxyList')):
                raise LuckyError('保存回读不一致，请在 Lucky 后台核对', 502)
            version = after['version']
        return jsonify(ok=True, version=version)

    @bp.route('/<key>/rules/<rid>/subrules/<sid>', methods=['GET', 'PUT', 'DELETE'])
    def subrule(key, rid, sid):
        client = store.client(key)
        parent_path = '/api/webservice/rule/' + quote(rid, safe='')
        detail = client.call('GET', parent_path)
        parent, rule_version = detail['rule'], detail['version']
        target = next((s for s in parent.get('ProxyList') or [] if s.get('Key') == sid), None)
        if target is None:
            raise LuckyError('子规则已不存在，请刷新列表', 404)
        body = request.get_json(silent=True) or {}
        if request.method == 'DELETE':
            if body.get('ruleVersion') != rule_version:
                raise LuckyError('规则组已被修改，请刷新后重新删除', 409)
            parent['ProxyList'] = [s for s in parent['ProxyList'] if s.get('Key') != sid]
            parent['ExpectedVersion'] = rule_version
            client.call('PUT', parent_path, parent)
            after = client.call('GET', parent_path)['rule']
            if any(s.get('Key') == sid for s in after.get('ProxyList') or []):
                raise LuckyError('子规则删除尚未确认，请刷新核对', 502)
            return jsonify(ok=True)
        prefix = '/api/webservice/' + quote(rid, safe='') + '/' + quote(sid, safe='')
        snapshot = client.call('GET', prefix + '/edit-snapshot')['snapshot']
        sub, version = snapshot['SubRule'], snapshot['Version']
        if sub.get('Key') != sid or snapshot.get('RuleKey', rid) != rid:
            raise LuckyError('Lucky 返回的子规则身份不匹配', 502)
        if request.method == 'PUT':
            if body.get('version') != version:
                raise LuckyError('子规则已被其他操作修改，请重新打开编辑', 409)
            if 'enabled' in body:
                if not isinstance(body['enabled'], bool):
                    raise LuckyError('启停状态必须为布尔值')
                expected = {'Enable': body['enabled']}
            else:
                if not subrule_editable(sub):
                    raise LuckyError('此子规则使用高级服务或后端池，请在 Lucky 后台编辑')
                name, domains, backends = subrule_fields(body)
                expected = {'Remark': name, 'Domains': domains, 'Locations': backends}
            sub.update(expected)
            # Full snapshot stays in Hub memory. Patch only the requested subrule fields.
            client.call('PUT', prefix + '/config', {'Version': version, 'SubRule': sub})
            after = client.call('GET', prefix + '/edit-snapshot')['snapshot']
            if any(after['SubRule'].get(k) != v for k, v in expected.items()):
                raise LuckyError('子规则保存回读不一致，请在 Lucky 后台核对', 502)
            sub, version = after['SubRule'], after['Version']
            rule_version = client.call('GET', parent_path)['version']
        return jsonify(ok=True, item=subrule_dto(sub), version=version, ruleVersion=rule_version)

    @bp.route('/<key>/certificates', methods=['GET', 'POST'])
    def certificates(key):
        client = store.client(key)
        raw = client.certificates()
        with store.db() as db:
            saved_accounts = [dict(r) for r in db.execute('SELECT * FROM dns_accounts WHERE instance=?', (key,))]
        if request.method == 'POST':
            body = request.get_json() or {}
            source = next((r for r in raw if r['Key'] == body.get('accountId') and (r.get('ExtParams') or {}).get('acmeDNSServer')), None)
            saved = next((a for a in saved_accounts if a['id'] == body.get('accountId')), None)
            if not source and not saved:
                raise LuckyError('请选择 Lucky 中已有的 DNS 账户；新账户请先在后台配置')
            domains = [s.strip().lower() for s in str(body.get('domains', '')).split(',') if s.strip()]
            if not domains or any(not re.fullmatch(r'(?:\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z0-9-]+', s) for s in domains):
                raise LuckyError('请输入有效域名，多个域名用英文逗号隔开')
            ext = json.loads(store.cipher.decrypt(saved['secret'])) if saved else copy.deepcopy(source['ExtParams'])
            ext.update(acmeDomains=domains, acmeCADirURL='https://acme-v02.api.letsencrypt.org/directory', acmeUseGlobalPrivateKey=False)
            for field in ('acmeKid', 'acmeHMAC', 'acmeProxyPassword', 'acmeProxyUser', 'acmeProxyAddr'):
                ext[field] = ''
            cert = {'Key': '', 'Remark': domains[0], 'Enable': True, 'AddFrom': 'acme', 'CertBase64': '', 'KeyBase64': '',
                    'IssuerCertificate': '', 'MappingToPath': False, 'MappingPath': '', 'MappingChangeScript': '',
                    'ExtParams': ext, 'AllSyncClient': False, 'SyncClientList': []}
            store.once(body.get('operationId'), {'instance': key, 'certificate': body}, lambda: client.call('POST', '/api/ssl', cert))
            raw = client.certificates()
            if not any(set((r.get('ExtParams') or {}).get('acmeDomains') or []) == set(domains) for r in raw):
                raise LuckyError('证书订单回读未确认，请刷新核对，勿重复申请', 502)
        items = []
        accounts = [{'id': a['id'], 'name': a['name'], 'provider': 'alidns'} for a in saved_accounts]
        for r in raw:
            info, ext = r.get('CertsInfo') or {}, r.get('ExtParams') or {}
            items.append({'id': r['Key'], 'name': r.get('Remark', ''), 'domains': info.get('Domains') or ext.get('acmeDomains') or [],
                          'expires': info.get('NotAfterTime', ''), 'enabled': bool(r.get('Enable')),
                          'issuing': bool(r.get('ACMEing')), 'failed': bool(r.get('ACMEErrMsg')), 'automatic': r.get('AddFrom') == 'acme'})
            if ext.get('acmeDNSServer'):
                accounts.append({'id': r['Key'], 'name': r.get('Remark') or ext['acmeDNSServer'], 'provider': ext['acmeDNSServer']})
        return jsonify(ok=True, items=items, accounts=accounts)

    @bp.route('/<key>/certificates/<cid>/<action>', methods=['POST'])
    def cert_action(key, cid, action):
        client = store.client(key)
        q = quote(cid, safe='')
        if action == 'renew':
            client.call('PUT', '/api/ssl/flush?key=' + q)
        elif action == 'enabled':
            enabled = (request.get_json() or {}).get('enabled') is True
            client.call('PUT', '/api/ssl/' + q + '?enable=' + str(enabled).lower())
            if not any(r['Key'] == cid and bool(r.get('Enable')) == enabled for r in client.certificates()):
                raise LuckyError('证书状态回读未确认，请刷新', 502)
        elif action == 'delete':
            client.call('DELETE', '/api/ssl?key=' + q)
            if any(r['Key'] == cid for r in client.certificates()):
                raise LuckyError('删除未确认，请刷新', 502)
        else:
            raise LuckyError('不支持的操作')
        return jsonify(ok=True)

    app.register_blueprint(bp)

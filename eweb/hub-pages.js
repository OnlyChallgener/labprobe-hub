/* Native Vue 2 / Element UI extension. Hub service credentials stay on the router. */
(function (root) {
  'use strict';
  function alignHubMenu() {
    if (!root.document) return;
    var icon = root.document.querySelector('.labprobe-hub-icon');
    if (!icon) return;
    var title = icon.closest('.el-submenu__title');
    if (title) title.classList.add('labprobe-hub-nav');
    var menu = icon.closest('.el-menu'), reference = menu && Array.prototype.find.call(menu.querySelectorAll('.el-menu-item i, .el-submenu__title i'), function (node) { return !node.classList.contains('labprobe-hub-icon') && !node.classList.contains('el-submenu__icon-arrow'); });
    if (reference && root.getComputedStyle) {
      var style = root.getComputedStyle(reference), width = reference.getBoundingClientRect().width;
      if (width > 0) { icon.style.width = width + 'px'; icon.style.height = style.fontSize; icon.style.fontSize = style.fontSize; icon.style.marginLeft = style.marginLeft; icon.style.marginRight = style.marginRight; }
    }
  }
  if (root.document) {
    alignHubMenu();
    if (root.MutationObserver && !root.LabProbeEwebNavObserver) { root.LabProbeEwebNavObserver = new root.MutationObserver(alignHubMenu); root.LabProbeEwebNavObserver.observe(root.document.documentElement, {childList: true, subtree: true}); }
  }
  var ACTIVE = ['queued', 'accepted', 'running', 'stop_requested', 'releasing'];
  var PROVIDERS = {
    alidns: ['阿里云 (aliyun.com)', ['AccessKeyId', 'AccessKeySecret', 'zone']],
    dnspod: ['腾讯云 (dnspod.cn)', ['SecretId', 'SecretKey', 'zone']],
    cloudflare: ['Cloudflare', ['apiToken', 'zoneId']], dynv6: ['Dynv6', ['token']],
    duckdns: ['Duck DNS', ['token']], desec: ['deSEC', ['token']],
    dynu: ['Dynu', ['username', 'password']], ipv64: ['IPv64', ['token']]
  };
  var LABELS = {AccessKeyId: 'Access Key ID', AccessKeySecret: 'Access Key Secret', zone: '主域名',
    SecretId: 'Secret ID', SecretKey: 'Secret Key', apiToken: 'API Token', zoneId: 'Zone ID',
    token: 'Token', username: '账号', password: '密码'};
  var STATUS = {waiting: '等待地址', detected: '已检测地址', stable: '地址已稳定', updating: '更新中',
    success: '成功', updated: '成功', published: '成功', noop: '无需更新', error: '更新失败', failed: '更新失败',
    disabled: '已停用', waiting_for_stability: '等待地址稳定', credential_error: '请检查服务商凭据',
    retry_backoff: '等待重试', stale_address: '等待最新地址', queued: '等待开始', accepted: '准备测试',
    running: '测试中', stop_requested: '正在停止', releasing: '正在释放连接', completed: '测试完成',
    stopped: '已停止', interrupted: '测试已中断'};
  function clone(x) { return JSON.parse(JSON.stringify(x)); }
  function targetList(value) { return String(value || '').split(/[,，;；\s]+/).filter(Boolean); }
  function canonicalTargetGroup(value) {
    var items = targetList(value), hosts = [];
    if (!items.length || items.some(function (v) { var host = canonicalHost(v); if (!host) return true; if (hosts.indexOf(host) < 0) hosts.push(host); return false; }) || hosts.length > 8) return '';
    return hosts.join(',');
  }
  function number(x) { return Number(x) || 0; }
  function time(x) { return x ? new Date(number(x) * 1000).toLocaleTimeString('zh-CN', {hour12: false}) : '--'; }
  function bytes(x) { var n = number(x), units = ['B', 'KB', 'MB', 'GB']; var k = 0; while (n >= 1024 && k < 3) { n /= 1024; k++; } return n.toFixed(k ? 2 : 0) + ' ' + units[k]; }
  function profileIdentity(p) {
    var source = p.endpointSource;
    return JSON.stringify([source, source === 'stun' ? p.stunRuleId : source === 'ddns' ? String(p.hostname || '').toLowerCase().replace(/\.$/, '') : p.resolvedEndpoint, number(p.port), p.enabled !== false]);
  }
  // APP profiles can independently reference one shared STUN rule. Group them
  // for display without deleting their IDs or breaking the APP's references.
  function groupedProfiles(rows) {
    var groups = [];
    rows.forEach(function (p) {
      var key = profileIdentity(p), group = groups.find(function (g) { return profileIdentity(g) === key; });
      if (!group) { group = Object.assign({}, p, {_profileIds: []}); groups.push(group); }
      group._profileIds.push(p.id);
      if (number(p.endpointRevision) >= number(group.endpointRevision) && p.resolvedEndpoint) {
        group.resolvedEndpoint = p.resolvedEndpoint; group.endpointRevision = p.endpointRevision;
      }
    });
    return groups;
  }
  function recordValue(r) {
    return (r.recordTypes || []).map(function (type) {
      return type === 'A' ? r.publishedIpv4 : type === 'AAAA' ? r.publishedIpv6 : (r.publishedValues || {})[type];
    }).filter(Boolean).join(' / ') || '--';
  }
  function canonicalHost(value) {
    var host = String(value || '').trim().toLowerCase().replace(/\.$/, '');
    if (!host || /\s|:\/\//.test(host)) return '';
    if (host.indexOf(':') >= 0 && root.URL) {
      try { host = new root.URL('http://[' + host.replace(/^\[|\]$/g, '') + ']').hostname.replace(/^\[|\]$/g, ''); }
      catch (_) { return ''; }
    }
    return host;
  }
  function message(result) {
    if (result.httpStatus === 409 && (/revision conflict/.test(result.error || '') || result.currentRevision !== undefined)) return '配置已发生变化，请刷新后再操作';
    var text = result.message || result.error || '';
    return /[\u4e00-\u9fff]/.test(text) ? text : '操作失败，请检查参数后重试';
  }
  // Native eWeb replaces Promise.prototype.finally with a handler that drops
  // fulfillment values and consumes rejections. Keep cleanup local to HUB.
  function complete(promise, cleanup) {
    return promise.then(function (value) { cleanup(); return value; }, function (error) { cleanup(); throw error; });
  }
  function api(op, payload, id, signal) {
    var sn = root.sn || (root.Cookie && root.Cookie.get('SN'));
    var sid = root.sid || (sn && root.Cookie && root.Cookie.get(sn));
    return root.fetch('/cgi-bin/luci/api/labprobe' + (sid ? '?auth=' + encodeURIComponent(sid) : ''), {
      method: 'POST', credentials: 'same-origin', signal: signal,
      headers: {'Content-Type': 'application/json', 'X-LabProbe-Eweb': '1'},
      body: JSON.stringify({id: 1, method: 'request', params: {op: op, payload: payload || {}, id: id}})
    }).then(function (r) {
      if (r.status === 403 || r.status === 401) throw new Error('登录已过期，请重新登录路由器');
      if (!r.ok) throw new Error('路由器暂时无法响应，请重试');
      return r.json();
    }).then(function (r) {
      var value = r.data;
      if (!value || !value.ok) throw new Error(message(value || {}));
      return value;
    });
  }
  function metric(h, title, value) { return h('div', {class: 'hub-metric'}, [title, h('strong', value)]); }
  function button(h, label, action, options) {
    return h('el-button', {props: Object.assign({type: 'primary'}, options || {}), on: {click: action}}, label);
  }
  function field(h, vm, model, key, label, type, opts) {
    opts = opts || {};
    var control = type === 'select' ? 'el-select' : type === 'number' ? 'el-input-number' : type === 'switch' ? 'el-switch' : 'el-input';
    var props = Object.assign({value: model[key], disabled: vm.busy || !vm.loaded || vm.kind === 'tcp' && vm.active}, opts.props || {});
    if (type === 'password') { props.type = 'password'; props.showPassword = true; props.autocomplete = 'new-password'; }
    if (model === vm.editor.credentials && vm.editor.loading) props.disabled = true;
    var children = type === 'select' ? (opts.items || []).map(function (row) {
      return h('el-option', {key: row[0], props: {value: row[0], label: row[1]}});
    }) : [];
    return h('el-form-item', {props: {label: label, required: !!opts.required}}, [h(control, {props: props, on: {input: function (v) {
      if (model[key] === v) return;
      vm.$set(model, key, v); if (model === vm.draft && vm.loaded && !vm._resettingDraft) vm.dirty = true;
      if (model === vm.editor && key === 'provider') { vm.$set(model, 'credentials', {}); vm.$set(model, 'credentialsConfigured', false); }
    }}}, children), opts.note ? h('div', {class: 'hub-note'}, opts.note) : null]);
  }
  function table(h, rows, columns, selection, emptyText, centered) {
    var cols = selection ? [h('el-table-column', {props: {type: 'selection', width: 46}})] : [];
    columns.forEach(function (col) { cols.push(h('el-table-column', {props: {label: col[0], prop: col[1], minWidth: col[2] || 120, align: centered ? 'center' : 'left', headerAlign: centered ? 'center' : 'left'}, scopedSlots: col[3] ? {default: function (s) { return col[3](s.row); }} : undefined})); });
    return h('el-table', {props: {data: rows, emptyText: emptyText || '暂无配置', stripe: true}, on: selection ? {'selection-change': selection} : {}}, cols);
  }
  function chartOption(samples, first, second, unit) {
    return {animation: false, color: ['#0095D8', '#00c783'],
      tooltip: {trigger: 'axis', formatter: /^(Kbps|Mbps)$/.test(unit) ? function (items) {
        return items.length ? items[0].axisValueLabel + '<br>' + items.map(function (item) { return item.marker + item.seriesName + '：' + number(item.value).toFixed(unit === 'Kbps' ? 1 : 2) + ' ' + unit; }).join('<br>') : '';
      } : undefined}, grid: {top: 32, left: 20, right: 24, bottom: 24, containLabel: true},
      xAxis: {type: 'category', boundaryGap: false, data: samples.map(function (s) { return time(s.at); }), axisLine: {lineStyle: {color: '#555962'}}},
      yAxis: {type: 'value', name: unit, min: 0, max: unit === '连接数' ? function (range) { return Math.max(5, Math.ceil(range.max)); } : undefined, minInterval: unit === '连接数' ? 1 : undefined, splitNumber: 5, splitLine: {lineStyle: {color: '#292c32'}}, axisLine: {lineStyle: {color: '#555962'}}},
      series: [{name: first, type: 'line', symbol: 'none', areaStyle: {opacity: 0.15}, data: samples.map(function (s) { return s.a; })},
        {name: second, type: 'line', symbol: 'none', areaStyle: {opacity: 0.1}, data: samples.map(function (s) { return s.b; })}]};
  }
  function createComponent(kind, charts) {
    return {
      name: 'LabProbeHub' + kind,
      data: function () { return {kind: kind, busy: false, reading: false, loaded: false, disposed: false, error: '', timer: null,
        snapshot: {}, draft: {enabled: false, interfaceName: 'labwg0', address: '10.77.0.1/24', listenPort: 51820, mtu: 1420, peers: [], endpointProfiles: []}, draftRevision: 0, dirty: false, dialog: '', editor: {}, selection: [], providers: [], stunRules: [],
        wgTab: 'server', wgPeers: {}, wgPeerStatusAt: 0, wgInterfaceName: '', tcpHistory: [], tcpResults: [], task: {}, samples: [], counter: null, tcpForm: {host: '', port: 443, family: 'both', targetConnections: 10000, cps: 500,
          extremeMode: false, connectTimeoutMs: 1500, maxDurationSeconds: 180}}; },
      computed: {
        active: function () { return ACTIVE.indexOf(this.task.state) >= 0; },
        wgStatus: function () {
          var s = this.snapshot.agentStatus || {}, reported = s.capability || s.wireguard || s.status || s;
          if (!this.snapshot.localWireguard) return reported;
          var latest = Math.max.apply(null, this.wgUserRows.map(function (p) { return number(p.latestHandshakeAt); }).concat([0]));
          return Object.assign({}, reported, this.snapshot.localWireguard, {latestHandshakeAt: latest || null});
        },
        title: function () { return kind === 'wireguard' ? 'WireGuard' : kind === 'tcp' ? 'TCP 峰值测试' : kind === 'stun' ? 'STUN 穿透' : kind === 'portmaps' ? 'IPv6 映射' : '动态域名解析 (DDNS)'; },
        peerRows: function () { return this.draft.peers || []; },
        profileRows: function () { return groupedProfiles(this.draft.endpointProfiles || []); },
        wgUserRows: function () {
          var self = this, now = Date.now() / 1000, fresh = this.wgPeerStatusAt && now >= this.wgPeerStatusAt && now - this.wgPeerStatusAt <= 90;
          // Configuration is the membership list. A telemetry gap never deletes
          // a user, and the same public key reconnects to the same row.
          return ((this.snapshot.server || {}).peers || []).map(function (c) {
            var p = self.wgPeers[c.publicKey] || {};
            return Object.assign({}, p, {publicKey: c.publicKey, name: c.name || '未命名客户端', allowedIps: c.allowedIps || p.allowedIps || [],
              connectionState: fresh && p.connectionState ? p.connectionState : 'unknown'});
          });
        },
        onlineRows: function () { return this.wgUserRows.filter(function (p) { return p.connectionState === 'online'; }); },
        ddnsRows: function () { return this.snapshot.records || []; }
      },
      mounted: function () {
        this._chart = null; this._gauge = null; this._controllers = [];
        if (kind === 'tcp') this.loadTcpHistory();
        root.addEventListener('resize', this.resizeCharts); this.refresh(false);
      },
      beforeDestroy: function () {
        this.disposed = true; clearTimeout(this.timer); this._controllers.forEach(function (c) { c.abort(); });
        root.removeEventListener('resize', this.resizeCharts); if (this._chart) this._chart.dispose(); if (this._gauge) this._gauge.dispose();
      },
      beforeRouteLeave: function (to, from, next) {
        if (!this.dirty) return next();
        this.$confirm('有尚未保存的配置，确定离开吗？', '提示', {confirmButtonText: '离开', cancelButtonText: '继续编辑', type: 'warning'}).then(function () { next(); }).catch(function () { next(false); });
      },
      methods: {
        tcpHistoryKey: function () {
          var sn = root.sn;
          try { sn = sn || root.Cookie && root.Cookie.get('SN'); } catch (_) {}
          return 'labprobe.tcp.hosts.v1:' + (sn || root.location && root.location.host || 'router');
        },
        loadTcpHistory: function () {
          try {
            var saved = JSON.parse(root.localStorage.getItem(this.tcpHistoryKey() + ':groups') || root.localStorage.getItem(this.tcpHistoryKey()) || '[]'), unique = [];
            if (Array.isArray(saved)) saved.forEach(function (v) { var host = canonicalTargetGroup(v); if (host && unique.indexOf(host) < 0) unique.push(host); });
            this.tcpHistory = unique.slice(0, 5);
          } catch (_) { this.tcpHistory = []; }
          if (!this.tcpForm.host && this.tcpHistory.length) this.tcpForm.host = this.tcpHistory[0];
        },
        persistTcpHistory: function () { try { root.localStorage.setItem(this.tcpHistoryKey() + ':groups', JSON.stringify(this.tcpHistory)); } catch (_) {} },
        rememberTcpHost: function (value) {
          var host = canonicalTargetGroup(typeof value === 'string' ? value : this.tcpForm.host); if (!host) return;
          this.tcpHistory = [host].concat(this.tcpHistory.filter(function (v) { return v !== host; })).slice(0, 5);
          this.persistTcpHistory();
        },
        rememberCompletedTcp: function (task) {
          var target = task.target || task.config || {}, hosts = targetList(target.host).map(canonicalHost).filter(Boolean);
          if (!task.id || ['completed', 'stopped', 'failed', 'interrupted'].indexOf(task.state) < 0 || !hosts.length || number((task.ipv4 || {}).success) + number((task.ipv6 || {}).success) <= 0) return;
          var key = this.tcpHistoryKey() + ':last-success-group', previous = this._rememberedTcpTask;
          try { previous = root.localStorage.getItem(key) || previous; } catch (_) {}
          if (previous === task.id) return;
          this.rememberTcpHost(hosts.join(',')); this._rememberedTcpTask = task.id;
          if (!this.tcpForm.host) this.tcpForm.host = hosts.join(',');
          try { root.localStorage.setItem(key, task.id); } catch (_) {}
        },
        tcpSuggestions: function (query, callback) {
          var q = String(query || '').trim().toLowerCase(), all = this.tcpHistory.indexOf(canonicalTargetGroup(q)) >= 0;
          callback(this.tcpHistory.filter(function (v) { return all || v.indexOf(q) >= 0; }).map(function (v) { return {value: v, host: v}; }));
        },
        removeTcpHost: function (host) {
          this.tcpHistory = this.tcpHistory.filter(function (v) { return v !== host; });
          if (canonicalTargetGroup(this.tcpForm.host) === host) this.tcpForm.host = '';
          this.persistTcpHistory();
        },
        ddnsValue: recordValue,
        handshakeText: function (value) { return value ? time(value) : this.wgPeerStatusAt ? '未握手' : '--'; },
        acceptWgTelemetry: function (r) {
          var local = r.localWireguard || {}, name = (r.server || {}).interfaceName;
          if (this.wgInterfaceName && name !== this.wgInterfaceName) { this.wgPeers = {}; this.wgPeerStatusAt = 0; }
          this.wgInterfaceName = name;
          if (!local.peerStatusAvailable || !Array.isArray(local.peers) || !number(local.receivedEpoch)) return;
          var self = this, at = number(local.receivedEpoch), next = {};
          ((r.server || {}).peers || []).forEach(function (c) {
            var old = self.wgPeers[c.publicKey] || {}, current = local.peers.find(function (p) { return p.publicKey === c.publicKey; });
            if (current && current.rxBytes !== undefined && old.rxBytes !== undefined && number(current.rxBytes) < number(old.rxBytes)) old = {};
            var p = Object.assign({}, old, current || {});
            // Preserve an actual previous handshake through a partial report;
            // a counter reset above explicitly clears that session history.
            p.latestHandshakeAt = Math.max(number(old.latestHandshakeAt), number(current && current.latestHandshakeAt)) || null;
            var seen = Math.max(number(p.latestHandshakeAt), number(p.lastActivityAt));
            var recent = seen > 0 && at >= seen && at - seen <= 300;
            var grace = old.connectionState === 'online' && seen > 0 && at >= seen && at - seen <= 330;
            p.connectionState = !local.running ? 'offline' : recent || grace ? 'online' : 'offline';
            next[c.publicKey] = p;
          });
          this.wgPeers = next; this.wgPeerStatusAt = at;
        },
        request: function (op, body, id) {
          var self = this;
          // A synchronous initialization failure must also release the page's
          // reading/busy state. Read deadlines exceed the router bridge's 8s.
          return Promise.resolve().then(function () {
            if (self.disposed) { var cancelled = new Error('Page closed'); cancelled.name = 'AbortError'; throw cancelled; }
            var c = new root.AbortController(), expired = false;
            self._controllers.push(c);
            var deadline = setTimeout(function () { expired = true; c.abort(); }, /^(ddns|stun|portmaps)\.(add|save|remove|update|start|stop)$/.test(op) ? 35000 : 12000);
            var pending = Promise.resolve().then(function () { return api(op, body, id, c.signal); }).catch(function (error) {
              if (expired && !self.disposed) throw new Error('请求超时，请点击刷新重试');
              throw error;
            });
            return complete(pending, function () {
              clearTimeout(deadline); var i = self._controllers.indexOf(c); if (i >= 0) self._controllers.splice(i, 1);
            });
          });
        },
        schedule: function () {
          var self = this; clearTimeout(this.timer);
          if (!this.disposed) this.timer = setTimeout(function () { self.refresh(false); }, kind === 'tcp' && this.active ? 1200 : kind === 'ddns' ? 15000 : 5000);
        },
        resetDraft: function (data) {
          var self = this; this._resettingDraft = true;
          this.draft = clone(data.server || {enabled: false, interfaceName: 'labwg0', address: '10.77.0.1/24', listenPort: 51820, mtu: 1420, peers: [], endpointProfiles: []});
          this.draftRevision = number(data.revision); this.dirty = false;
          this.$nextTick(function () { self._resettingDraft = false; });
        },
        refresh: function (explicit) {
          var self = this;
          if (this.disposed || this.reading || this.busy) { this.schedule(); return Promise.resolve(); }
          if (explicit && this.dirty) return this.$confirm('刷新将重新读取配置，放弃尚未保存的修改吗？', '提示', {confirmButtonText: '刷新', cancelButtonText: '取消'})
            .then(function () { self.dirty = false; return self.refresh(true); }).catch(function () {});
          this.reading = true; var epoch = this._readEpoch || 0;
          return complete(this.request(kind === 'wireguard' ? 'wg.get' : kind === 'tcp' ? 'tcp.get' : kind === 'stun' ? 'stun.get' : kind === 'portmaps' ? 'portmaps.get' : 'ddns.get').then(function (r) {
            if (self.disposed || epoch !== (self._readEpoch || 0)) return;
            self.error = ''; self.snapshot = r;
            if (kind === 'wireguard') { if (!self.loaded || explicit || !self.dirty && number(r.revision) !== self.draftRevision) self.resetDraft(r); self.acceptWgTelemetry(r); self.sampleWg(r); }
            if (kind === 'tcp') { self.acceptTask(r.task || {}); self.tcpResults = r.history || []; }
            if (kind === 'stun') self.stunRules = r.rules || [];
            if (kind === 'ddns') self.providers = r.providers || [];
            self.loaded = true; self.$nextTick(self.drawCharts);
          }).catch(function (e) { if (!self.disposed && epoch === (self._readEpoch || 0) && e.name !== 'AbortError') self.error = /[\u4e00-\u9fff]/.test(e.message || '') ? e.message : '读取失败，请重试'; }),
            function () { self.reading = false; self.schedule(); });
        },
        mutate: function (op, body, id) {
          var self = this; if (this.busy) return Promise.resolve(null); this._readEpoch = (this._readEpoch || 0) + 1; this.busy = true; clearTimeout(this.timer); this.error = '';
          return complete(this.request(op, body, id).then(function (r) { return self.disposed ? null : r; })
            .catch(function (e) { if (!self.disposed) self.error = /[\u4e00-\u9fff]/.test(e.message || '') ? e.message : '操作失败，请重试'; return null; }),
            function () { self.busy = false; self.schedule(); });
        },
        saveWg: function () {
          var self = this, body = clone(this.draft); body.expectedRevision = this.draftRevision;
          this.mutate('wg.save', body).then(function (r) { if (r) { self.resetDraft(r); self.snapshot = Object.assign({}, self.snapshot, r); self.$message.success('配置已保存，等待路由器应用'); self.refresh(false); } });
        },
        removePeer: function (row) {
          var self = this;
          this.$confirm('删除此客户端会断开它的 WireGuard 连接，确定删除吗？', '删除客户端', {confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning'})
            .then(function () { return self.mutate('wg.remove', {expectedRevision: self.draftRevision}, row.id); })
            .then(function (r) { if (r) { self.resetDraft(r); self.snapshot = Object.assign({}, self.snapshot, r); self.$message.success('删除已提交，正在同步到路由器'); self.refresh(false); } }).catch(function () {});
        },
        newPeer: function () { this.editor = {name: '', publicKey: '', ips: '', persistentKeepaliveSeconds: 25}; this.dialog = 'peer'; },
        newProfile: function () { this.editor = {name: '', endpointSource: 'manual', resolvedEndpoint: '', hostname: '', stunRuleId: '', enabled: true, port: this.draft.listenPort}; this.dialog = 'profile';
          var self = this; this.request('stun.get').then(function (r) { self.stunRules = r.rules || []; }).catch(function () { self.stunRules = []; }); },
        commitEditor: function () {
          if (this.dialog === 'portmap') return this.savePortmap();
          if (this.dialog === 'stun') return this.saveStun();
          if (this.dialog === 'ddns') return this.saveDdns();
          var row = clone(this.editor);
          if (this.dialog === 'peer') {
            if (!/^[A-Za-z0-9+/]{43}=$/.test(row.publicKey) || !row.ips.trim()) { this.$message.error('请填写有效的公钥和客户端地址'); return; }
            row.allowedIps = row.ips.split(/[,，\s]+/).filter(Boolean); delete row.ips;
            row.id = 'peer-' + root.crypto.getRandomValues(new Uint32Array(2)).join(''); this.draft.peers.push(row);
          } else {
            if (row.endpointSource === 'manual' && !row.resolvedEndpoint || row.endpointSource === 'ddns' && !row.hostname || row.endpointSource === 'stun' && !row.stunRuleId) { this.$message.error('请填写连接地址'); return; }
            if (row.endpointSource !== 'ddns') row.hostname = ''; if (row.endpointSource !== 'stun') row.stunRuleId = '';
            var ids = row._profileIds; delete row._profileIds;
            if (ids) {
              var vm = this; this.draft.endpointProfiles.forEach(function (p, i) {
                if (ids.indexOf(p.id) >= 0) vm.$set(vm.draft.endpointProfiles, i, Object.assign({}, p, row, {id: p.id, endpointRevision: p.endpointRevision}));
              });
            } else {
              var existing = this.draft.endpointProfiles.find(function (p) { return profileIdentity(p) === profileIdentity(row); });
              row.id = existing ? existing.id : 'endpoint-' + root.crypto.getRandomValues(new Uint32Array(2)).join('');
              var index = this.draft.endpointProfiles.findIndex(function (p) { return p.id === row.id; });
              if (index < 0) this.draft.endpointProfiles.push(row); else this.$set(this.draft.endpointProfiles, index, row);
            }
          }
          this.dirty = true; this.dialog = '';
        },
        editProfile: function (r) { this.editor = clone(r); this.dialog = 'profile'; var self = this; this.request('stun.get').then(function (s) { self.stunRules = s.rules || []; }).catch(function () {}); },
        removeProfile: function (r) { var self = this; this.$confirm('删除此连接地址？保存配置后生效。', '删除', {confirmButtonText: '删除', cancelButtonText: '取消'})
          .then(function () { var ids = r._profileIds || [r.id]; self.draft.endpointProfiles = self.draft.endpointProfiles.filter(function (p) { return ids.indexOf(p.id) < 0; }); self.dirty = true; }).catch(function () {}); },
        sampleWg: function (r) {
          var s = this.wgStatus, i = (s.interfaces || []).find(function (x) { return x.name === (r.server || {}).interfaceName; });
          var at = number((r.localWireguard || r.agentStatus || {}).receivedEpoch);
          if (!i || !at || this.counter && at <= this.counter.at) return;
          if (this.counter && this.counter.name === i.name && at - this.counter.at <= 120 && i.rxBytes >= this.counter.rx && i.txBytes >= this.counter.tx) {
            this.samples.push({at: at, a: (i.rxBytes - this.counter.rx) * 8 / (at - this.counter.at) / 1000000, b: (i.txBytes - this.counter.tx) * 8 / (at - this.counter.at) / 1000000}); this.samples = this.samples.slice(-180);
          }
          this.counter = {at: at, name: i.name, rx: number(i.rxBytes), tx: number(i.txBytes)};
        },
        acceptTask: function (t) {
          var terminal = ['completed', 'stopped', 'failed', 'interrupted'].indexOf(t.state) >= 0;
          if (this.task.id !== t.id) {
            this.samples = []; this._frozenTcpTask = null;
            try {
              var saved = JSON.parse(root.localStorage.getItem(this.tcpHistoryKey() + ':curve') || '{}');
              if (saved.id === t.id && Array.isArray(saved.samples)) this.samples = saved.samples.slice(-240).filter(function (s) { return s && isFinite(s.at) && s.at > 0 && isFinite(s.a) && isFinite(s.b); });
              if (saved.id === t.id && saved.finished) this._frozenTcpTask = t.id;
            } catch (_) {}
          }
          this.task = t;
          this.rememberCompletedTcp(t);
          var at = number(terminal ? t.finishedEpoch || t.updatedEpoch : t.updatedEpoch);
          if (t.id && this._frozenTcpTask !== t.id && at > 0 && (!this.samples.length || at > this.samples[this.samples.length - 1].at)) {
            this.samples.push({at: at, a: number((t.ipv4 || {}).current), b: number((t.ipv6 || {}).current)}); this.samples = this.samples.slice(-240);
          }
          if (terminal && t.id) this._frozenTcpTask = t.id;
          if (t.id) {
            try { root.localStorage.setItem(this.tcpHistoryKey() + ':curve', JSON.stringify({id: t.id, finished: terminal, samples: this.samples})); } catch (_) {}
          }
        },
        startTcp: function () {
          var self = this, form = clone(this.tcpForm);
          var query = this.$refs.tcpHost && this.$refs.tcpHost.query;
          var values = targetList(form.host).concat(targetList(query)), hosts = [];
          if (!values.length || values.some(function (value) { var host = canonicalHost(value); if (!host) return true; if (hosts.indexOf(host) < 0) hosts.push(host); return false; }) || hosts.length > 8) { this.$message.error('请填写最多 8 个目标 IP 或域名，不含协议头、端口和路径'); return; }
          form.host = hosts.join(','); this.tcpForm.host = form.host;
          this.$confirm('测试由当前路由器建立 TCP 连接，可能影响现有网络连接。确定开始吗？', '开始 TCP 峰值测试', {confirmButtonText: '开始测试', cancelButtonText: '取消', type: 'warning'})
            .then(function () { return self.mutate('tcp.start', form); }).then(function (r) { if (r) { self.acceptTask(r.task); self.drawCharts(); } }).catch(function () {});
        },
        stopTcp: function () { var self = this; this.mutate('tcp.stop', {taskId: this.task.id}).then(function (r) { if (r) { self.acceptTask(r.task); self.drawCharts(); } }); },
        removeTcpResult: function (row) {
          var self = this;
          return this.$confirm('删除这条 TCP 测试历史？', '删除测试历史', {confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning'}).then(function () {
            return self.mutate('tcp.history.remove', {taskId: row.id}).then(function (r) { if (r) { self.tcpResults = r.history || []; self.$message.success('测试历史已删除'); } });
          }).catch(function () {});
        },
        resultTarget: function (row) { var t = row.target || row.config || {}; return t.host ? targetList(t.host).map(function (host) { return (host.indexOf(':') >= 0 ? '[' + host + ']' : host) + ':' + (t.port || 443); }).join('，') : '未记录目标'; },
        resultTime: function (row) { return row.finishedEpoch || row.createdEpoch ? new Date(number(row.finishedEpoch || row.createdEpoch) * 1000).toLocaleString('zh-CN', {hour12: false}) : '--'; },
        showTcpResult: function (row) { this.editor = clone(row); this.dialog = 'tcp-result'; },
        stunPublic: function (row) { return ((row.addresses || {}).public || {}).endpoint || (row.runtime || {}).publicEndpoint || ''; },
        stunStatus: function (row) {
          if (!row.enabled) return '已停用';
          return {mapped: '已获取地址', mapping: '获取中', stopped: '已停止', error: '异常', router_mapping: '映射准备中', router_mapping_error: '映射异常', firewall_error: '防火墙异常'}[row.actualState] || '等待更新';
        },
        copyAddress: function (value) {
          if (!value) return;
          var self = this;
          if (root.navigator && root.navigator.clipboard && root.isSecureContext) return root.navigator.clipboard.writeText(value).then(function () { self.$message.success('地址已复制'); }).catch(function () { self.$message.error('复制失败，请选择地址复制'); });
          var input = root.document.createElement('textarea'); input.value = value; input.style.position = 'fixed'; input.style.opacity = '0'; root.document.body.appendChild(input); input.select();
          try { if (!root.document.execCommand('copy')) throw new Error('copy'); this.$message.success('地址已复制'); } catch (_) { this.$message.error('复制失败，请选择地址复制'); } finally { root.document.body.removeChild(input); }
        },
        editPortmap: function (row) {
          var rules = this.snapshot.rules || [], range = this.snapshot.portRange || {min: 20000, max: 20020}, port = range.min;
          while (port <= range.max && rules.some(function (r) { return number(r.listenPort) === port; })) port++;
          if (!row && port > range.max) { this.$message.error('监听端口已用完，请先删除不再使用的映射'); return; }
          this.editor = row ? clone(row) : {name: '', mode: '6to4', listenPort: port, transportProtocol: 'TCP', targetType: 'manual', targetMode: 'ipv6_full', targetIpv4: '', targetIpv6: '', targetIpv6Suffix: '', targetPort: 80, enabled: true}; this.dialog = 'portmap';
        },
        portmapTarget: function (row) {
          var address = row.targetType === 'router_self' ? row.mode === '6to4' ? '127.0.0.1' : '::1' : row.mode === '6to4' ? row.targetIpv4 : row.targetMode === 'ipv6_suffix' ? row.targetIpv6Suffix : row.targetIpv6;
          return (row.mode === '6to6' ? '[' + (address || '--') + ']' : address || '--') + ':' + row.targetPort;
        },
        portmapStatus: function (row) {
          if (row.syncState === 'error' || row.firewallState === 'error') return '同步异常';
          if (row.syncState === 'syncing') return '同步中';
          var state = (row.runtime || {}).state;
          return {running: '运行中', starting: '启动中', waiting_target: '等待目标', waiting_agent: '等待路由器', draining: '停止中', error: '运行异常', stopped: '已停止', expired: '已到期'}[state] || (row.enabled ? '等待路由器确认' : '已停用');
        },
        savePortmap: function () {
          var self = this, e = this.editor, range = this.snapshot.portRange || {min: 20000, max: 20020};
          if (!String(e.name || '').trim() || number(e.listenPort) < range.min || number(e.listenPort) > range.max || number(e.targetPort) < 1 || number(e.targetPort) > 65535) { this.$message.error('请填写规则名称及有效端口'); return; }
          var body = {name: String(e.name).trim(), mode: e.mode, listenPort: number(e.listenPort), transportProtocol: e.transportProtocol, targetType: e.targetType, targetMode: e.mode === '6to4' ? 'ipv4' : e.targetMode, targetPort: number(e.targetPort), enabled: e.enabled};
          if (e.targetType !== 'device') body.targetMac = '';
          if (e.mode === '6to4') body.targetIpv4 = e.targetType === 'router_self' ? '127.0.0.1' : String(e.targetIpv4 || '').trim();
          else if (e.targetType === 'router_self') { body.targetMode = 'ipv6_full'; body.targetIpv6 = '::1'; }
          else if (e.targetMode === 'ipv6_suffix') body.targetIpv6Suffix = String(e.targetIpv6Suffix || '').trim();
          else body.targetIpv6 = String(e.targetIpv6 || '').trim().replace(/^\[|\]$/g, '');
          this.mutate(e.id ? 'portmaps.save' : 'portmaps.add', body, e.id).then(function (r) { if (r) { self.dialog = ''; self.$message.success('映射已保存，等待路由器应用'); self.refresh(false); } });
        },
        portmapAction: function (row, action) {
          var self = this, perform = function () { return self.mutate('portmaps.' + action, {}, row.id).then(function (r) { if (r) { self.$message.success(action === 'remove' ? '映射已删除' : '操作已提交'); self.refresh(false); } }); };
          if (action !== 'remove') return perform();
          return this.$confirm('删除映射“' + row.name + '”？', '删除 IPv6 映射', {confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning'}).then(perform).catch(function () {});
        },
        editStun: function (row) { this.editor = row ? clone(row) : {name: '', serviceType: 'HTTP', transportProtocol: 'TCP', targetType: 'manual', targetIpv4: '', targetPort: 80, enabled: true}; this.dialog = 'stun'; },
        serviceChanged: function (value) {
          var preset = {HTTP: [80, 'TCP'], HTTPS: [443, 'TCP'], SSH: [22, 'TCP'], RDP: [3389, 'TCP'], Telnet: [23, 'TCP'], WireGuard: [51820, 'UDP'], OpenVPN: [1194, 'UDP'], DNS: [53, 'UDP']}[value];
          if (preset) { this.editor.targetPort = preset[0]; this.editor.transportProtocol = preset[1]; }
        },
        saveStun: function () {
          var self = this, e = this.editor;
          if (e.targetType !== 'router_self' && !/^(\d{1,3}\.){3}\d{1,3}$/.test(e.targetIpv4 || '') || number(e.targetPort) < 1 || number(e.targetPort) > 65535) { this.$message.error('请填写有效的目标 IPv4 和端口'); return; }
          var body = {name: String(e.name || '').trim(), serviceType: e.serviceType, transportProtocol: e.transportProtocol, targetType: e.targetType, targetIpv4: e.targetType === 'router_self' ? '127.0.0.1' : e.targetIpv4, targetPort: number(e.targetPort), enabled: e.enabled};
          this.mutate(e.id ? 'stun.save' : 'stun.add', body, e.id).then(function (r) { if (r) { self.dialog = ''; self.$message.success('规则已保存'); self.refresh(false); } });
        },
        stunAction: function (row, action) {
          var self = this;
          var perform = function () { return self.mutate('stun.' + action, {}, row.id).then(function (r) { if (r) { self.$message.success(action === 'remove' ? '规则已删除' : '操作已提交'); self.refresh(false); } }); };
          if (action !== 'remove') return perform();
          return this.$confirm('删除规则“' + row.name + '”及其地址记录？', '删除 STUN 规则', {confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning'}).then(perform).catch(function () {});
        },
        showStunHistory: function (row) {
          var self = this, id = row.id; this.editor = {id: id, name: row.name, addresses: [], loading: true}; this.dialog = 'stun-history';
          complete(this.request('stun.addresses', {}, id).then(function (r) { if (self.dialog === 'stun-history' && self.editor.id === id) self.editor.addresses = r.addresses || []; }).catch(function (e) { self.error = e.message; }), function () { if (self.editor.id === id) self.editor.loading = false; });
        },
        editDdns: function (row) { this.editor = row ? clone(row) : {provider: 'alidns', hostname: '', recordTypes: ['A'], ttl: 600, enabled: true, recordValues: {}};
          this.editor.credentials = {}; this.editor.originalProvider = this.editor.provider; this.editor.type = this.editor.recordTypes.join(','); this.dialog = 'ddns';
          if (row) {
            var self = this, id = row.id; this.$set(this.editor, 'loading', true);
            complete(this.request('ddns.credentials', {}, id).then(function (r) {
              if (!self.disposed && self.dialog === 'ddns' && self.editor.id === id && self.editor.provider === row.provider) self.$set(self.editor, 'credentials', r.credentials || {});
            }).catch(function () { if (!self.disposed) self.error = '已保存的凭据读取失败，请重新打开修改弹窗'; }),
              function () { if (self.editor.id === id) self.$set(self.editor, 'loading', false); });
          }
        },
        saveDdns: function () {
          var self = this, r = clone(this.editor); r.recordTypes = r.type.split(','); delete r.type;
          if (!r.hostname.trim()) { this.$message.error('请填写域名'); return; }
          var credentialKeys = (PROVIDERS[r.provider] || ['', []])[1], changingCredentials = credentialKeys.some(function (key) { return String(r.credentials[key] || '').trim(); });
          if ((!r.id || r.provider !== r.originalProvider || changingCredentials) && !credentialKeys.every(function (key) { return String(r.credentials[key] || '').trim(); })) { this.$message.error('请填写完整的服务商凭据；保留原凭据时请全部留空'); return; }
          if (!changingCredentials) delete r.credentials;
          else r.credentials = Object.fromEntries(credentialKeys.map(function (key) { return [key, r.credentials[key]]; }));
          delete r.originalProvider; delete r.loading;
          this.mutate(r.id ? 'ddns.save' : 'ddns.add', r, r.id).then(function (v) { if (v) { self.editor = {}; self.dialog = ''; self.$message.success('DDNS 配置已保存'); self.refresh(false); } });
        },
        ddnsAction: function (row, action) {
          var self = this;
          if (action === 'remove') return this.$confirm('删除此 DDNS 配置？', '删除', {confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning'})
            .then(function () { return self.mutate('ddns.remove', {}, row.id); }).then(function (r) { if (r) self.refresh(false); }).catch(function () {});
          return this.mutate(action === 'update' ? 'ddns.update' : 'ddns.save', action === 'update' ? {} : Object.assign({}, row, {enabled: action === 'enable'}), row.id)
            .then(function (r) { if (r) self.refresh(false); return r; });
        },
        batchDdns: function (action) {
          var self = this, rows = this.selection.slice(); if (!rows.length) return;
          this.$confirm('对选中的 ' + rows.length + ' 条配置执行' + ({remove: '删除', enable: '启用', disable: '停用'}[action]) + '？', '批量操作', {confirmButtonText: '确定', cancelButtonText: '取消'})
            .then(async function () { var failed = 0; for (var i = 0; i < rows.length && !self.disposed; i++) { var r = await self.mutate(action === 'remove' ? 'ddns.remove' : 'ddns.save', action === 'remove' ? {} : Object.assign({}, rows[i], {enabled: action === 'enable'}), rows[i].id); if (!r) failed++; }
              if (failed) self.$message.error(failed + ' 条操作失败，请核对列表'); else self.$message.success('批量操作完成'); self.refresh(false); }).catch(function () {});
        },
        resizeCharts: function () { if (this._chart) this._chart.resize(); if (this._gauge) this._gauge.resize(); },
        drawCharts: function () {
          if (this.disposed || !charts || !this.$refs.trend) return;
          if (this._chart && this._chart.getDom() !== this.$refs.trend) { this._chart.dispose(); this._chart = null; }
          if (!this._chart) this._chart = charts.init(this.$refs.trend);
          var unit = kind === 'tcp' ? '连接数' : this.samples.some(function (s) { return Math.max(number(s.a), number(s.b)) > 1; }) ? 'Mbps' : 'Kbps';
          var plotted = unit === 'Kbps' ? this.samples.map(function (s) { return {at: s.at, a: number(s.a) * 1000, b: number(s.b) * 1000}; }) : this.samples;
          this._chart.setOption(chartOption(plotted, kind === 'tcp' ? 'IPv4' : '接收', kind === 'tcp' ? 'IPv6' : '发送', unit));
          if (this.$refs.gauge) {
            if (!this._gauge) this._gauge = charts.init(this.$refs.gauge);
            var current = number((this.task.ipv4 || {}).current) + number((this.task.ipv6 || {}).current);
            this._gauge.setOption({animation: false, series: [{type: 'gauge', min: 0, max: Math.max(100, number((this.task.config || this.tcpForm).targetConnections)), splitNumber: 5,
              startAngle: 225, endAngle: -45, axisLine: {lineStyle: {width: 18, color: [[0.5, '#60d9dc'], [0.85, '#329bd1'], [1, '#ff626a']]}},
              axisLabel: {color: '#939aaa', fontSize: 11}, axisTick: {lineStyle: {color: '#939aaa'}}, splitLine: {length: 12, lineStyle: {color: '#939aaa'}},
              pointer: {width: 5}, detail: {formatter: '{value}', color: '#329bd1', fontSize: 36}, title: {color: '#939aaa', fontSize: 14},
              data: [{name: '当前连接数', value: current}]}]});
          }
          this.resizeCharts();
        },
        renderDialog: function (h) {
          var self = this, e = this.editor, fields = [], title;
          if (this.dialog === 'tcp-result' || this.dialog === 'stun-history') {
            var results = this.dialog === 'tcp-result';
            var body = results ? [h('div', {class: 'hub-result-meta'}, [h('strong', this.resultTarget(e)), h('span', this.resultTime(e)), h('span', STATUS[e.state] || e.state)]),
              table(h, ['ipv4', 'ipv6'].map(function (key) { return Object.assign({family: key.toUpperCase()}, e[key] || {}); }), [['协议', 'family'], ['峰值连接', 'peak'], ['累计成功', 'success'], ['累计失败', 'failure']]),
              h('div', {class: 'hub-metrics'}, [metric(h, 'CPU 峰值', number(e.cpuPeak).toFixed(1) + '%'), metric(h, '最低可用内存', number(e.memoryMinAvailableMb) + ' MB'), metric(h, '连接释放', e.resourcesReleased ? '已释放' : '未确认')]), h('div', {class: 'hub-note'}, e.finishReason || '')] :
              [table(h, e.addresses || [], [['公网地址', '', 240, function (r) { return h('span', {class: 'hub-endpoint'}, [r.endpoint || r.publicEndpoint || '--', button(h, '复制', function () { self.copyAddress(r.endpoint || r.publicEndpoint); }, {type: 'text'})]); }], ['记录时间', '', 180, function (r) { return r.at || r.updatedAt || r.mappingUpdatedAt ? new Date(number(r.at || r.updatedAt || r.mappingUpdatedAt) * 1000).toLocaleString('zh-CN', {hour12: false}) : r.changedAt || '--'; }]], null, e.loading ? '正在读取' : '暂无地址记录')];
            return h('el-dialog', {class: 'labprobe-hub-dialog', props: {visible: true, title: results ? 'TCP 测试详情' : '地址记录 · ' + e.name, width: '740px', closeOnClickModal: false}, on: {'update:visible': function (v) { if (!v) self.dialog = ''; }}}, body.concat([h('div', {slot: 'footer'}, [button(h, '关闭', function () { self.dialog = ''; }, {type: 'default'})])]));
          }
          if (this.dialog === 'peer') {
            title = '添加客户端'; fields = [field(h, this, e, 'name', '名称'), field(h, this, e, 'publicKey', '公钥', 'text', {required: true}),
              field(h, this, e, 'ips', '客户端地址', 'text', {required: true, note: '例如 10.77.0.2/32，多条地址用逗号分隔'}), field(h, this, e, 'persistentKeepaliveSeconds', '保活间隔 / 秒', 'number', {props: {min: 0, max: 600}})];
          } else if (this.dialog === 'profile') {
            title = e.id ? '修改连接地址' : '添加连接地址';
            fields = [field(h, this, e, 'name', '名称'), field(h, this, e, 'endpointSource', '地址来源', 'select', {items: [['manual', '手动地址'], ['ddns', 'DDNS 域名'], ['stun', 'STUN 穿透']]})];
            if (e.endpointSource === 'manual') fields.push(field(h, this, e, 'resolvedEndpoint', '连接地址', 'text', {required: true, note: '例如 vpn.example.com:51820 或 [IPv6地址]:51820'}));
            if (e.endpointSource === 'ddns') fields.push(field(h, this, e, 'hostname', '域名', 'text', {required: true, note: 'UDP 端口使用服务端监听端口'}));
            if (e.endpointSource === 'stun') fields.push(field(h, this, e, 'stunRuleId', 'UDP 穿透规则', 'select', {required: true, items: this.stunRules.filter(function (r) { return String(r.protocol || r.transportProtocol || '').toUpperCase() === 'UDP'; }).map(function (r) { return [r.id, r.name || r.id]; }), note: '使用当前路由器已有的 UDP 穿透规则'}));
          } else if (this.dialog === 'portmap') {
            title = e.id ? '修改 IPv6 映射' : '新增 IPv6 映射';
            var portRange = this.snapshot.portRange || {min: 20000, max: 20020};
            fields = [field(h, this, e, 'name', '规则名称', 'text', {required: true, props: {maxlength: 64}}),
              field(h, this, e, 'mode', '映射类型', 'select', {items: [['6to4', 'IPv6 → IPv4'], ['6to6', 'IPv6 → IPv6']]}),
              field(h, this, e, 'transportProtocol', '协议', 'select', {items: [['TCP', 'TCP'], ['UDP', 'UDP']]}),
              field(h, this, e, 'listenPort', '外部端口', 'number', {required: true, props: {min: portRange.min, max: portRange.max}, note: '可用范围：' + portRange.min + '–' + portRange.max}),
              field(h, this, e, 'targetType', '目标类型', 'select', {items: [['manual', '手动地址'], ['router_self', '路由器本机']].concat(e.targetType === 'device' ? [['device', '已关联设备']] : [])})];
            if (e.targetType !== 'router_self') {
              if (e.mode === '6to4') fields.push(field(h, this, e, 'targetIpv4', '内网 IPv4', 'text', {required: true, props: {placeholder: '192.168.110.100'}}));
              else {
                fields.push(field(h, this, e, 'targetMode', '地址方式', 'select', {items: [['ipv6_full', '完整 IPv6 地址'], ['ipv6_suffix', 'IPv6 后缀 · 跟随前缀']]}));
                fields.push(field(h, this, e, e.targetMode === 'ipv6_suffix' ? 'targetIpv6Suffix' : 'targetIpv6', e.targetMode === 'ipv6_suffix' ? 'IPv6 后缀' : '目标 IPv6', 'text', {required: true, props: {placeholder: e.targetMode === 'ipv6_suffix' ? '::1234:5678' : '2001:db8::100'}}));
              }
            }
            fields.push(field(h, this, e, 'targetPort', '内部端口', 'number', {required: true, props: {min: 1, max: 65535}}), field(h, this, e, 'enabled', '启用规则', 'switch'));
          } else if (this.dialog === 'stun') {
            title = e.id ? '修改 STUN 规则' : '新建 STUN 规则';
            fields = [field(h, this, e, 'name', '规则名称', 'text', {props: {maxlength: 64, placeholder: '例如 NAS 管理'}}),
              h('el-form-item', {props: {label: '服务类型'}}, [h('el-select', {props: {value: e.serviceType}, on: {input: function (value) { e.serviceType = value; self.serviceChanged(value); }}}, ['HTTP', 'HTTPS', 'SSH', 'RDP', 'Telnet', 'WireGuard', 'OpenVPN', 'DNS', 'Custom'].map(function (v) { return h('el-option', {props: {value: v, label: v === 'Custom' ? '自定义' : v}}); }))]),
              field(h, this, e, 'transportProtocol', '传输协议', 'select', {items: (['WireGuard'].indexOf(e.serviceType) >= 0 ? ['UDP'] : ['HTTP', 'HTTPS', 'SSH', 'RDP', 'Telnet'].indexOf(e.serviceType) >= 0 ? ['TCP'] : ['TCP', 'UDP']).map(function (v) { return [v, v]; })}),
              field(h, this, e, 'targetType', '目标类型', 'select', {items: [['manual', '内网 IPv4'], ['router_self', '路由器本机']].concat(e.targetType === 'device' ? [['device', '已关联内网设备']] : [])})];
            if (e.targetType !== 'router_self') fields.push(field(h, this, e, 'targetIpv4', '目标 IPv4', 'text', {required: true, props: {placeholder: '192.168.110.100'}}));
            fields.push(field(h, this, e, 'targetPort', '目标端口', 'number', {required: true, props: {min: 1, max: 65535}}), field(h, this, e, 'enabled', '启用规则', 'switch'));
          } else if (this.dialog === 'ddns') {
            title = e.id ? '修改 DDNS' : '添加 DDNS';
            var provider = PROVIDERS[e.provider] || ['', []], available = this.providers.find(function (p) { return p.id === e.provider; });
            fields = [field(h, this, e, 'provider', '服务商', 'select', {required: true, items: this.providers.map(function (p) { return [p.id, (PROVIDERS[p.id] || [p.id])[0]]; })}),
              field(h, this, e, 'hostname', '域名', 'text', {required: true, props: {placeholder: 'home.example.com'}}),
              field(h, this, e, 'type', '记录类型', 'select', {items: (available && available.recordTypes || ['A', 'AAAA']).map(function (t) { return [t, {A: 'A 记录 (IPv4)', AAAA: 'AAAA 记录 (IPv6)', CNAME: 'CNAME 记录', TXT: 'TXT 记录'}[t] || t]; }).concat(available && available.supportsA && available.supportsAAAA ? [['A,AAAA', 'A + AAAA 记录']] : [])}),
              field(h, this, e, 'ttl', 'TTL / 秒', 'number', {props: {min: 60, max: 86400}}), field(h, this, e, 'enabled', '启用', 'switch')];
            provider[1].forEach(function (key) { fields.push(field(h, self, e.credentials, key, LABELS[key] || key, /Secret|Key$|Token|token|password/.test(key) ? 'password' : 'text')); });
            if (e.type === 'CNAME' || e.type === 'TXT') fields.push(field(h, this, e.recordValues, e.type, '记录值', 'text', {required: true}));
          }
          return h('el-dialog', {class: ['labprobe-hub-dialog', this.dialog === 'ddns' ? 'hub-ddns-dialog' : ''], props: {visible: !!this.dialog, title: title, width: this.dialog === 'ddns' ? '740px' : '680px', closeOnClickModal: false, closeOnPressEscape: !this.busy, showClose: !this.busy}, on: {'update:visible': function (v) { if (!v && !self.busy) { self.dialog = ''; self.editor = {}; } }}}, [
            h('el-form', {props: {labelWidth: '112px'}}, fields), h('div', {slot: 'footer'}, [button(h, '取消', function () { self.dialog = ''; self.editor = {}; }, {type: 'default', disabled: this.busy}), button(h, '确定', this.commitEditor, {loading: this.busy, disabled: !!this.editor.loading})])]);
        }
      },
      render: function (h) {
        var self = this, content = [], controls = {disabled: this.busy || !this.loaded};
        content.push(h('help-alert', {props: {title: this.title}}));
          if (this.error) content.push(h('div', {class: 'hub-error', attrs: {role: 'alert'}}, (this.loaded ? '已保留上次数据 · ' : '') + this.error));
        if (kind === 'wireguard') {
          content.unshift(h('el-tabs', {props: {value: this.wgTab}, on: {input: function (value) { self.wgTab = value; self.$nextTick(self.drawCharts); }}}, [
            h('el-tab-pane', {props: {label: 'WireGuard', name: 'server'}}), h('el-tab-pane', {props: {label: '在线用户', name: 'users'}})]));
          var status = this.wgStatus, now = Date.now() / 1000, agent = this.snapshot.agentStatus || {}, updatedEpoch = (this.snapshot.localWireguard || agent).receivedEpoch, fresh = updatedEpoch && now - updatedEpoch < 90;
          var connected = fresh && status.running && this.onlineRows.length > 0;
          var info = (status.interfaces || []).find(function (i) { return i.name === self.draft.interfaceName; }) || {};
          var applied = fresh && number(agent.revision) === number(this.snapshot.revision) && agent.applyResult && agent.applyResult.ok;
          var recovering = this.error || this.snapshot.hubReadStale || this.loaded && (!this.snapshot.localWireguard || !this.snapshot.localWireguard.peerStatusAvailable);
          var state = !this.loaded ? '正在读取' : recovering ? '数据恢复中，已保留上次数据' : !fresh ? '等待路由器更新' : number(agent.revision) < number(this.snapshot.revision) ? '配置应用中' : agent.applyResult && agent.applyResult.ok === false ? '配置应用失败' : connected ? '已连接' : status.running ? '服务已启用' : this.draft.enabled ? '等待服务状态' : '未启用';
          content.push(h('div', {class: 'hub-status'}, [h('span', {class: ['hub-dot', connected ? 'online' : '']}), !connected ? h('i', {class: 'el-icon-time'}) : null, state,
            h('span', {class: 'hub-note'}, '更新于 ' + time(updatedEpoch)), button(h, '刷新', function () { self.refresh(true); }, {type: 'default', loading: this.reading})]));
          if (this.wgTab === 'users') {
            var available = this.snapshot.localWireguard && this.snapshot.localWireguard.peerStatusAvailable;
            content[1] = h('help-alert', {props: {title: '在线用户'}});
            content.push(table(h, this.wgUserRows, [['名称', 'name', 150], ['状态', '', 100, function (r) { return h('span', {style: {color: r.connectionState === 'online' ? '#00a58c' : '#939aaa'}}, {online: '在线', offline: '离线', unknown: '待更新'}[r.connectionState]); }],
              ['实际地址', '', 190, function (r) { return r.endpoint || '--'; }], ['隧道地址', '', 160, function (r) { return (r.allowedIps || []).join(', '); }],
              ['最近握手', '', 120, function (r) { return self.handshakeText(r.latestHandshakeAt); }], ['接收流量', '', 120, function (r) { return r.rxBytes === undefined ? '--' : bytes(r.rxBytes); }], ['发送流量', '', 120, function (r) { return r.txBytes === undefined ? '--' : bytes(r.txBytes); }]], null,
              this.loaded ? '暂无客户端配置' : '等待路由器用户数据'));
          } else {
          content.push(h('el-form', {class: 'hub-form', props: {labelWidth: '140px'}}, [field(h, this, this.draft, 'enabled', '启用服务', 'switch'),
            field(h, this, this.draft, 'address', '服务端地址', 'text'), field(h, this, this.draft, 'listenPort', 'UDP 监听端口', 'number', {props: {min: 1, max: 65535}}),
            field(h, this, this.draft, 'mtu', 'MTU', 'number', {props: {min: 1280, max: 1500}}), h('el-form-item', {props: {label: '服务端公钥'}}, [h('span', {class: 'hub-public-key'}, info.publicKey || applied && agent.applyResult.publicKey || '等待路由器上报')]),
            h('el-form-item', [button(h, '保存配置', this.saveWg, {loading: this.busy, disabled: !this.loaded}), this.dirty ? h('span', {class: 'hub-note'}, '  有未保存的修改') : null])]));
          content.push(h('div', {class: 'hub-metrics hub-wg-metrics'}, [metric(h, '接收流量', info.rxBytes === undefined ? '--' : bytes(info.rxBytes)), metric(h, '发送流量', info.txBytes === undefined ? '--' : bytes(info.txBytes)), metric(h, '客户端', this.loaded ? String(this.peerRows.length) : '--'), metric(h, '最近握手', this.handshakeText(status.latestHandshakeAt))]));
          content.push(h('div', {class: 'hub-chart-header'}, [h('span', '隧道流量'), h('div', {class: 'hub-legend'}, [h('span', {style: {color: '#0095D8'}}, '● 接收'), h('span', {style: {color: '#00c783'}}, '● 发送')])]));
          content.push(h('div', {class: 'hub-chart', ref: 'trend'}));
          content.push(h('div', {class: 'hub-note'}, '曲线按路由器实际采样间隔更新。客户端私钥保留在客户端。'));
          content.push(h('div', {class: 'hub-section hub-wg-clients'}, [h('div', {class: 'hub-toolbar'}, [h('h3', {class: 'hub-note'}, '客户端管理'), button(h, '添加', this.newPeer, controls)]),
            table(h, this.peerRows, [['名称', 'name'], ['客户端地址', '', 180, function (r) { return (r.allowedIps || []).join(', '); }], ['公钥', 'publicKey', 300], ['操作', '', 90, function (r) { return button(h, '删除', function () { self.removePeer(r); }, {type: 'text', disabled: self.dirty || self.busy}); }]])]));
          content.push(h('div', {class: 'hub-section'}, [h('div', {class: 'hub-toolbar'}, [h('h3', {class: 'hub-note'}, '连接地址'), button(h, '添加', this.newProfile, controls)]),
            table(h, this.profileRows, [['名称', 'name'], ['来源', '', 120, function (r) { return {manual: '手动地址', ddns: 'DDNS', stun: 'STUN'}[r.endpointSource]; }], ['地址', '', 230, function (r) { return r.resolvedEndpoint || r.hostname || '等待解析'; }], ['操作', '', 120, function (r) { return h('span', [button(h, '修改', function () { self.editProfile(r); }, {type: 'text', disabled: self.busy}), button(h, '删除', function () { self.removeProfile(r); }, {type: 'text', disabled: self.busy})]); }]])]));
          }
        } else if (kind === 'tcp') {
          content.push(h('el-form', {class: 'hub-form hub-tcp-form', props: {labelWidth: '150px'}}, [
            h('el-form-item', {props: {label: '目标 IP / 域名', required: true}}, [h('el-autocomplete', {
              ref: 'tcpHost', class: 'hub-tcp-targets', props: {value: this.tcpForm.host, fetchSuggestions: this.tcpSuggestions, placeholder: 'www.taobao.com,www.baidu.com', clearable: true, disabled: this.busy || !this.loaded || this.active, popperClass: 'hub-tcp-history'},
              on: {input: function (v) { self.tcpForm.host = v; }},
              scopedSlots: {default: function (scope) { var host = scope.item.host; return h('div', {class: 'hub-tcp-history-row'}, [h('span', host), h('button', {class: 'hub-tcp-history-remove', attrs: {type: 'button', 'aria-label': '删除地址 ' + host}, on: {mousedown: function (event) { event.preventDefault(); event.stopPropagation(); }, click: function (event) { event.stopPropagation(); event.preventDefault(); self.removeTcpHost(host); self.$refs.tcpHost.close(); }}}, '×')]); }}
            })]), field(h, this, this.tcpForm, 'port', '目标端口', 'number', {props: {min: 1, max: 65535}}),
            h('el-form-item', [h('span', {class: 'hub-note'}, '最多 8 个目标；逗号、空格或换行分隔，共用端口和总连接数，轮流建连。')]),
            field(h, this, this.tcpForm, 'family', '测试协议', 'select', {items: [['ipv4', 'IPv4'], ['ipv6', 'IPv6'], ['both', 'IPv4 / IPv6 分别测试']]}),
            field(h, this, this.tcpForm, 'targetConnections', '目标连接数', 'number', {props: {min: 1, max: 131072}}), field(h, this, this.tcpForm, 'cps', '每秒新建连接', 'number', {props: {min: 1, max: this.tcpForm.extremeMode ? 10000 : 2000}}),
            field(h, this, this.tcpForm, 'maxDurationSeconds', '测试时长 / 秒', 'number', {props: {min: 10, max: 300}}), field(h, this, this.tcpForm, 'extremeMode', '极限模式', 'switch'),
            h('el-form-item', [this.active ? button(h, '停止测试', this.stopTcp, {loading: this.busy, type: 'danger'}) : button(h, '开始测试', this.startTcp, {loading: this.busy, disabled: !this.loaded})]) ]));
          content.push(h('div', {class: 'hub-status'}, [h('span', {class: ['hub-dot', this.active ? 'online' : '']}), this.task.state === 'failed' ? '测试未完成' : STATUS[this.task.state] || '待测试', h('span', {class: 'hub-note'}, '路由器端测试 · 更新于 ' + time(this.task.updatedEpoch)), button(h, '刷新', function () { self.refresh(false); }, {type: 'default', loading: this.reading})]));
          content.push(h('div', {class: 'hub-split'}, [h('div', {class: 'hub-chart', ref: 'gauge'}), h('div', [h('div', {class: 'hub-chart-header'}, [h('span', '连接数趋势'), h('div', {class: 'hub-legend'}, [h('span', {style: {color: '#0095D8'}}, '● IPv4'), h('span', {style: {color: '#00c783'}}, '● IPv6')])]), h('div', {class: 'hub-chart', ref: 'trend'})])]));
          if (this.task.state === 'releasing') content.push(h('div', {class: 'hub-note'}, '当前协议已停止新增连接，正在确认资源回收（最长 15 秒），期间计数可能保持不变。'));
          content.push(table(h, ['ipv4', 'ipv6'].map(function (key) { return Object.assign({family: key.toUpperCase()}, self.task[key] || {}); }), [['协议', 'family'], ['当前连接', 'current'], ['峰值连接', 'peak'], ['累计成功', 'success'], ['累计失败', 'failure'], ['每秒新建', 'cps']]));
          content.push(h('div', {class: 'hub-note'}, this.task.finishReason || '失败数为累计值；连续失败 200 次或触发其他保护条件时停止新增连接。'));
          content.push(h('div', {class: 'hub-metrics'}, [metric(h, 'CPU 峰值', this.task.id ? number(this.task.cpuPeak).toFixed(1) + '%' : '--'), metric(h, '最低可用内存', this.task.id ? number(this.task.memoryMinAvailableMb) + ' MB' : '--'), metric(h, '连接释放', this.task.id ? this.task.resourcesReleased ? '已释放' : this.active ? '测试进行中' : '等待确认' : '--')]));
          content.push(h('div', {class: 'hub-note'}, this.task.finishReason || '页面重新打开后会读取当前任务。测试结束或停止后，由路由器释放测试连接。'));
          content.push(h('div', {class: 'hub-section'}, [h('div', {class: 'hub-chart-header'}, [h('h3', '测试历史'), h('span', {class: 'hub-note'}, '最近 5 条 · 保存在 HUB')]),
            table(h, this.tcpResults, [['测试时间', '', 175, this.resultTime], ['目标地址', '', 210, this.resultTarget], ['协议', '', 100, function (r) { return {ipv4: 'IPv4', ipv6: 'IPv6', both: 'IPv4 / IPv6'}[(r.target || {}).family] || '--'; }],
              ['IPv4 峰值', '', 110, function (r) { return number((r.ipv4 || {}).peak); }], ['IPv6 峰值', '', 110, function (r) { return number((r.ipv6 || {}).peak); }], ['结束状态', '', 110, function (r) { return STATUS[r.state] || r.state; }],
              ['操作', '', 120, function (r) { return h('span', {class: 'hub-row-actions'}, [button(h, '详情', function () { self.showTcpResult(r); }, {type: 'text'}), button(h, '删除', function () { self.removeTcpResult(r); }, {type: 'text', disabled: self.busy})]); }]], null, '完成测试后会自动保存记录') ]));
        } else if (kind === 'portmaps') {
          var mappings = this.snapshot.rules || [];
          content.push(h('div', {class: 'hub-toolbar'}, [h('span', {class: 'hub-note'}, mappings.length + ' 条映射'), button(h, '刷新', function () { self.refresh(false); }, {type: 'default', loading: this.reading}), button(h, '新增映射', function () { self.editPortmap(); }, controls)]));
          content.push(table(h, mappings, [['规则名称', 'name', 160], ['映射类型', '', 115, function (r) { return r.mode === '6to4' ? 'IPv6 → IPv4' : 'IPv6 → IPv6'; }], ['协议', 'transportProtocol', 80], ['外部端口', 'listenPort', 100],
            ['内网目标', '', 240, function (r) { return h('span', {attrs: {title: self.portmapTarget(r)}, style: {overflowWrap: 'anywhere'}}, self.portmapTarget(r)); }],
            ['运行状态', '', 145, function (r) { return h('span', {attrs: {title: r.firewallMessage || (r.runtime || {}).lastError || ''}}, self.portmapStatus(r)); }],
            ['启用', '', 80, function (r) { return h('el-switch', {props: {value: !!r.enabled, disabled: self.busy || !self.loaded}, on: {input: function (v) { self.portmapAction(r, v ? 'start' : 'stop'); }}}); }],
            ['操作', '', 115, function (r) { return h('span', {class: 'hub-row-actions'}, [button(h, '修改', function () { self.editPortmap(r); }, {type: 'text', disabled: self.busy}), button(h, '删除', function () { self.portmapAction(r, 'remove'); }, {type: 'text', disabled: self.busy})]); }]], null, this.loaded ? '暂无 IPv6 映射，点击“新增映射”添加' : '正在读取映射'));
          content.push(h('div', {class: 'hub-note hub-stun-footnote'}, '通过路由器 IPv6 访问内网服务；外部端口范围为 20000–20020。'));
        } else if (kind === 'stun') {
          var rules = this.stunRules, ready = rules.filter(function (r) { return r.actualState === 'mapped' && (r.runtime || {}).mappingFresh; }).length;
          content.push(h('div', {class: 'hub-toolbar hub-stun-toolbar'}, [h('div', {class: 'hub-stun-summary'}, [h('span', {class: ['hub-dot', this.snapshot.agentOnline ? 'online' : '']}),
            h('span', this.snapshot.agentOnline ? '路由器在线' : this.loaded ? '等待路由器上报' : '正在读取'), h('span', {class: 'hub-note'}, rules.length + ' 条规则 · ' + ready + ' 条已获取地址')]),
            button(h, '刷新', function () { self.refresh(false); }, {type: 'default', loading: this.reading}), button(h, '新建规则', function () { self.editStun(); }, controls)]));
          content.push(table(h, rules, [['规则名称', '', 170, function (r) { return h('div', [h('span', {class: 'hub-rule-name'}, r.name), h('div', {class: 'hub-note'}, r.serviceType === 'Custom' ? '自定义' : r.serviceType)]); }],
            ['协议', 'transportProtocol', 75], ['内网目标', '', 185, function (r) { return ((r.addresses || {}).target || {}).endpoint || r.targetIpv4 + ':' + r.targetPort; }],
            ['公网地址', '', 210, function (r) { var endpoint = self.stunPublic(r); return endpoint ? h('span', {class: 'hub-endpoint'}, [h('span', endpoint), button(h, '复制', function () { self.copyAddress(endpoint); }, {type: 'text'})]) : h('span', {class: 'hub-note'}, '等待获取'); }],
            ['运行状态', '', 145, function (r) { var error = r.syncError || (r.runtime || {}).lastError || r.nativeMappingMessage; return h('span', {attrs: {title: error || ''}, style: {color: r.actualState === 'mapped' ? '#00c783' : /error/.test(r.actualState) ? '#ff6969' : '#939aaa'}}, self.stunStatus(r)); }],
            ['启用', '', 70, function (r) { return h('el-switch', {props: {value: !!r.enabled, disabled: self.busy || !self.loaded}, on: {input: function (v) { self.stunAction(r, v ? 'start' : 'stop'); }}}); }],
            ['操作', '', 205, function (r) { return h('span', {class: 'hub-row-actions'}, [button(h, '修改', function () { self.editStun(r); }, {type: 'text', disabled: self.busy}), button(h, '地址记录', function () { self.showStunHistory(r); }, {type: 'text', disabled: self.busy}), button(h, '删除', function () { self.stunAction(r, 'remove'); }, {type: 'text', disabled: self.busy})]); }]], null, this.loaded ? '暂无 STUN 规则，点击“新建规则”添加' : '正在读取规则'));
          content.push(h('div', {class: 'hub-note hub-stun-footnote'}, '公网地址会随网络变化自动更新；已获取地址不代表外网一定可达。'));
        } else {
          var address = this.snapshot.address || {};
          content.push(h('div', {class: 'hub-toolbar'}, [h('div', {class: 'hub-addresses'}, [h('span', ['IPv4  ', h('strong', address.detectedIpv4 || '--')]), h('span', ['IPv6  ', h('strong', address.detectedIpv6 || '--')])]), button(h, '刷新', function () { self.refresh(false); }, {type: 'default', loading: this.reading}), button(h, '添加', function () { self.editDdns(); }, controls),
            h('el-dropdown', {props: {trigger: 'click'}, on: {command: this.batchDdns}}, [button(h, '批量操作 ﹀', function () {}, {disabled: this.busy || !this.selection.length}), h('el-dropdown-menu', {slot: 'dropdown'}, ['remove', 'enable', 'disable'].map(function (a) { return h('el-dropdown-item', {props: {command: a}}, {remove: '批量删除', enable: '批量启用', disable: '批量停用'}[a]); }))]) ]));
          content.push(table(h, this.ddnsRows, [['服务商', '', 160, function (r) { return (PROVIDERS[r.provider] || [r.provider])[0]; }], ['域名', 'hostname', 200],
            ['解析网卡', '', 110, function () { return 'WAN'; }], ['更新结果', '', 140, function (r) { return STATUS[r.status] || '等待更新'; }],
            ['解析值', '', 260, this.ddnsValue],
            ['记录类型', '', 140, function (r) { return (r.recordTypes || []).join(' / '); }], ['状态', '', 90, function (r) { return h('span', {style: {color: r.enabled ? '#00a58c' : '#939aaa'}}, r.enabled ? '已启用' : '已停用'); }],
            ['操作', '', 215, function (r) { return h('span', [button(h, r.enabled ? '停用' : '启用', function () { self.ddnsAction(r, r.enabled ? 'disable' : 'enable'); }, {type: 'text', disabled: self.busy}), button(h, '修改', function () { self.editDdns(r); }, {type: 'text', disabled: self.busy}), button(h, '更新', function () { self.ddnsAction(r, 'update'); }, {type: 'text', disabled: self.busy || !r.enabled}), button(h, '删除', function () { self.ddnsAction(r, 'remove'); }, {type: 'text', disabled: self.busy})]); }]], function (rows) { self.selection = rows; }, null, true));
        }
        if (this.dialog) content.push(this.renderDialog(h));
        return h('div', {class: ['labprobe-hub-page', kind === 'stun' ? 'hub-stun-page' : '']}, content);
      }
    };
  }
  root.LabProbeEweb = {createComponent: createComponent, chartOption: chartOption, api: api};
})(typeof window !== 'undefined' ? window : globalThis);

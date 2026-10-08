// Stateful client tests: prevent stale polls from overwriting edits/commands.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const crypto = require('node:crypto').webcrypto;

test('STUN rows group only the same binding and retain every APP profile ID', () => {
  const {state} = setup('wireguard');
  state.draft.endpointProfiles = [
    {id:'app-1',endpointSource:'stun',stunRuleId:'udp-1',port:51820,resolvedEndpoint:'1.2.3.4:1234',endpointRevision:1},
    {id:'app-2',endpointSource:'stun',stunRuleId:'udp-1',port:51820,resolvedEndpoint:'1.2.3.4:1234',endpointRevision:2},
    {id:'app-3',endpointSource:'stun',stunRuleId:'udp-2',port:51820,resolvedEndpoint:'1.2.3.4:1234'},
    {id:'ddns',endpointSource:'ddns',hostname:'vpn.example',port:51820}
  ];
  assert.equal(state.profileRows.length,3);
  assert.equal(JSON.stringify(state.profileRows[0]._profileIds),JSON.stringify(['app-1','app-2']));
  state.editor={...state.profileRows[0],name:'Changed'};state.dialog='profile';
  state.commitEditor();
  assert.equal(state.draft.endpointProfiles.length,4);
  assert.equal(state.draft.endpointProfiles[1].name,'Changed');
  assert.equal(state.draft.endpointProfiles[1].id,'app-2');
  assert.equal(state.draft.endpointProfiles[1].endpointRevision,2);
  assert.equal(state.draft.endpointProfiles[0]._profileIds,undefined);
});

test('DDNS selected types exclude stale A and AAAA values from a TXT row', () => {
  const {state} = setup('ddns');
  const row={recordTypes:['TXT'],publishedIpv4:'1.2.3.4',publishedIpv6:'2001:db8::1',publishedValues:{TXT:'1.2.3.4:4321',CNAME:'old.example'}};
  assert.equal(state.ddnsValue(row),'1.2.3.4:4321');
  assert.equal(state.ddnsValue({...row,recordTypes:['AAAA']}),'2001:db8::1');
  assert.equal(state.ddnsValue({...row,recordTypes:['TXT'],publishedValues:{}}),'--');
});

test('TCP history caps at five, merges canonical duplicates, survives reload and deletes', () => {
  const {state,root}=setup('tcp');const storage={};
  root.sn='BE72-test';root.URL=URL;root.localStorage={getItem:k=>storage[k],setItem:(k,v)=>{storage[k]=v;}};
  for(let i=0;i<6;i++){state.tcpForm.host='host'+i+'.example';state.rememberTcpHost();}
  assert.equal(state.tcpHistory.length,5);assert.equal(state.tcpHistory.includes('host0.example'),false);
  state.tcpForm.host=' HOST2.EXAMPLE. ';state.rememberTcpHost();
  assert.equal(state.tcpHistory.length,5);assert.equal(state.tcpHistory[0],'host2.example');
  state.tcpHistory=[];state.loadTcpHistory();assert.equal(state.tcpHistory.length,5);
  state.$refs={};state.removeTcpHost('host2.example');assert.equal(state.tcpHistory.length,4);
  assert.equal(state.tcpForm.host,'');state.loadTcpHistory();assert.equal(state.tcpHistory.includes('host2.example'),false);
  state.tcpForm.host='https://bad.example';state.rememberTcpHost();assert.equal(state.tcpHistory.length,4);
  root.sn='BE50-test';state.loadTcpHistory();assert.equal(state.tcpHistory.length,0);
});

test('WG membership survives idle periods and failed samples without claiming historical traffic is online', () => {
  const {state,root}=setup('wireguard');const now=Math.floor(Date.now()/1000);root.testNow=now;
  state.snapshot={server:{interfaceName:'labwg0',peers:[{name:'Phone',publicKey:'phone-key'},{name:'Idle',publicKey:'idle-key'},{name:'Never',publicKey:'never-key'}]},localWireguard:{peerStatusAvailable:true,running:true,receivedEpoch:now,latestHandshakeAt:now-30,peers:[
    {publicKey:'phone-key',latestHandshakeAt:now-30,rxBytes:12},
    {publicKey:'idle-key',latestHandshakeAt:now-600,rxBytes:1000000},
    {publicKey:'never-key',latestHandshakeAt:null,rxBytes:1000000}
  ]}};
  state.acceptWgTelemetry(state.snapshot);
  assert.equal(state.wgUserRows.length,3);
  assert.equal(state.onlineRows.length,1);assert.equal(state.onlineRows[0].name,'Phone');
  assert.equal(state.wgStatus.latestHandshakeAt,now-30);
  assert.equal(state.wgUserRows[1].connectionState,'offline');
  state.snapshot.localWireguard={running:true,peerStatusAvailable:false,receivedEpoch:now+5,interfaces:[]};
  root.testNow=now+5;state.acceptWgTelemetry(state.snapshot);
  assert.equal(state.onlineRows.length,1);assert.equal(state.wgStatus.latestHandshakeAt,now-30);
  root.testNow=now+120;assert.equal(state.wgUserRows.length,3);
  assert.equal(state.wgUserRows[0].connectionState,'unknown');
  assert.equal(state.wgUserRows[0].rxBytes,12);
});
test('a disconnected WG user becomes offline in place and reconnects by the same public key', () => {
  const {state,root}=setup('wireguard');const now=Math.floor(Date.now()/1000);root.testNow=now;
  const response={server:{interfaceName:'labwg0',peers:[{name:'Phone',publicKey:'same-key'}]},localWireguard:{peerStatusAvailable:true,running:true,receivedEpoch:now,peers:[{publicKey:'same-key',latestHandshakeAt:now,rxBytes:12}]}};
  state.snapshot=response;state.acceptWgTelemetry(response);assert.equal(state.onlineRows.length,1);
  root.testNow=now+305;response.localWireguard.receivedEpoch=root.testNow;state.acceptWgTelemetry(response);
  assert.equal(state.onlineRows.length,1,'quiet grace prevents a boundary flap');
  root.testNow=now+340;response.localWireguard.receivedEpoch=root.testNow;state.acceptWgTelemetry(response);
  assert.equal(state.wgUserRows.length,1);assert.equal(state.wgUserRows[0].connectionState,'offline');
  response.localWireguard.peers[0].latestHandshakeAt=root.testNow;state.acceptWgTelemetry(response);
  assert.equal(state.wgUserRows.length,1);assert.equal(state.onlineRows[0].publicKey,'same-key');
  response.localWireguard.peers[0]={publicKey:'same-key',latestHandshakeAt:null,rxBytes:0};state.acceptWgTelemetry(response);
  assert.equal(state.wgUserRows[0].latestHandshakeAt,null,'kernel counter reset clears old session data');
  response.server.peers=[];state.acceptWgTelemetry(response);assert.equal(state.wgUserRows.length,0,'only a confirmed configuration removal removes membership');
});
test('WG read failure retains the configuration and real handshake; a confirmed key change creates a different identity', async () => {
  const {state,root}=setup('wireguard');const now=Math.floor(Date.now()/1000);root.testNow=now;
  state.request=async()=>({ok:true,revision:1,server:{interfaceName:'labwg0',peers:[{name:'Phone',publicKey:'old-key'}]},localWireguard:{running:true,peerStatusAvailable:true,receivedEpoch:now,peers:[{publicKey:'old-key',latestHandshakeAt:now,rxBytes:12}]}});
  await state.refresh(false);
  state.request=async()=>{throw new Error('HUB 暂时未返回可用数据');};await state.refresh(false);
  assert.equal(state.loaded,true);assert.equal(state.wgUserRows.length,1);assert.equal(state.wgStatus.latestHandshakeAt,now);
  state.request=async()=>({ok:true,revision:2,server:{interfaceName:'labwg0',peers:[{name:'Phone',publicKey:'new-key'}]},localWireguard:{running:true,peerStatusAvailable:true,receivedEpoch:now,peers:[{publicKey:'new-key',latestHandshakeAt:null,rxBytes:0}]}});
  await state.refresh(false);
  assert.equal(state.wgUserRows[0].publicKey,'new-key');assert.equal(state.wgUserRows[0].connectionState,'offline');assert.equal(state.wgUserRows[0].latestHandshakeAt,null);
});
function setup(kind, nativeFinally = false) {
  const root = {AbortController, crypto, addEventListener() {}, removeEventListener() {}};
  let timers = [];
  class Clock extends Date { static now() { return typeof root.testNow==='number' ? root.testNow*1000 : Date.now(); } }
  const context = vm.createContext({window: root, setTimeout(f) { timers.push(f); return 1; }, clearTimeout() {}, Date:Clock, Uint32Array});
  if (nativeFinally) vm.runInContext(`
    // Exact behavior of the native NHnr entry module (missing outer returns).
    Promise.prototype.finally = function (cb) {
      return this.then(function(value) { Promise.resolve(cb()).then(function() { return value; }); },
                       function(error) { Promise.resolve(cb()).then(function() { return error; }); });
    };
    window.sid = 'test-only-session';
    window.fetch = function () { return Promise.resolve({ok: true, status: 200, json: function () { return Promise.resolve(window.testResponse); }}); };
  `, context);
  vm.runInContext(fs.readFileSync('eweb/hub-pages.js', 'utf8'), context);
  const component = root.LabProbeEweb.createComponent(kind, null);
  const state = component.data();
  state.$set = (target, key, value) => { target[key] = value; };
  state.$nextTick = () => {};
  state.$message = {success() {}, error() {}};
  state._controllers = [];
  for (const [name, fn] of Object.entries(component.methods)) state[name] = fn.bind(state);
  for (const [name, fn] of Object.entries(component.computed)) Object.defineProperty(state, name, {get: fn.bind(state)});
  const realRequest = state.request;
  state.request = async () => ({ok: true, revision: 1, server: {peers: [], endpointProfiles: [], address: '10.77.0.1/24'}});
  return {state, component, root, realRequest, context, timers};
}
test('real requests retain all three page payloads under the native broken finally implementation', async () => {
  for (const kind of ['wireguard', 'tcp', 'ddns']) {
    const {state, root, realRequest} = setup(kind, true);
    root.testResponse = {data: {ok: true, revision: 7, server: {address: '10.77.3.1/24', peers: [], endpointProfiles: []}, task: {state: 'stopped'}, records: [{id: 'saved-ddns'}], providers: [{id: 'alidns'}]}};
    state.request = realRequest;
    await state.refresh(false);
    assert.equal(state.loaded, true, kind); assert.equal(state.reading, false, kind);
    assert.equal(state.error, '', kind); assert.equal(state.snapshot.ok, true, kind);
    assert.equal(state._controllers.length, 0, kind);
    if (kind === 'wireguard') assert.equal(state.draftRevision, 7);
    if (kind === 'tcp') assert.equal(state.task.state, 'stopped');
    if (kind === 'ddns') assert.equal(state.ddnsRows[0].id, 'saved-ddns');
  }
});
test('authentication failures are preserved and refresh can recover under native finally', async () => {
  const {state, root, realRequest, context} = setup('ddns', true);
  state.request = realRequest;
  vm.runInContext('window.fetch = function () { return Promise.resolve({status:403,ok:false}); };', context);
  await state.refresh(false);
  assert.equal(state.loaded, false); assert.match(state.error, /登录已过期/);
  assert.equal(state.reading, false); assert.equal(state._controllers.length, 0);
  root.testResponse = {data:{ok:true,records:[],providers:[]}};
  vm.runInContext('window.fetch = function () { return Promise.resolve({status:200,ok:true,json:function(){return Promise.resolve(window.testResponse);}}); };', context);
  await state.refresh(false); assert.equal(state.loaded, true); assert.equal(state.error, '');
});
test('synchronous initialization failures release loading state and request resources', async () => {
  const {state, root, realRequest} = setup('wireguard', true);
  delete root.sid; root.Cookie = {get(){throw new Error('cookie initialization failed');}};
  state.request = realRequest;
  await state.refresh(false);
  assert.equal(state.reading, false); assert.equal(state._controllers.length, 0);
  assert.equal(state.loaded, false); assert.match(state.error, /读取失败/);
});
test('a stalled read times out and releases disabled-page loading state', async () => {
  const {state, realRequest, context, timers} = setup('tcp', true);
  vm.runInContext(`window.fetch = function (url, options) {
    return new Promise(function (resolve, reject) {
      options.signal.addEventListener('abort', function () { var e = new Error('aborted'); e.name = 'AbortError'; reject(e); });
    });
  };`, context);
  state.request = realRequest;
  const read = state.refresh(false);
  await new Promise(setImmediate);
  assert.equal(state.reading, true); assert.equal(state._controllers.length, 1);
  timers[0](); await read;
  assert.equal(state.reading, false); assert.equal(state._controllers.length, 0);
  assert.match(state.error, /请求超时/); assert.equal(state.loaded, false);
});
test('mutations retain results and reject errors despite the native finally override', async () => {
  const {state, root, realRequest} = setup('ddns', true);
  root.testResponse = {data:{ok:true,record:{id:'test-record'}}}; state.request = realRequest;
  const saved = await state.mutate('ddns.save',{});
  assert.equal(saved.record.id, 'test-record'); assert.equal(state.busy,false);
  root.testResponse = {data:{ok:false,error:'记录已变化，请刷新'}};
  assert.equal(await state.mutate('ddns.save',{}),null); assert.match(state.error,/记录已变化/);
  assert.equal(state.busy,false); assert.equal(state._controllers.length,0);
});
test('router-local WG interface counters take precedence over a missing CLI capability', () => {
  const {state} = setup('wireguard');
  state.snapshot = {server:{interfaceName:'labwg0'}, agentStatus:{receivedEpoch:9,capability:{running:false,interfaces:[],latestHandshakeAt:8}},
    localWireguard:{receivedEpoch:10,running:true,interfaces:[{name:'labwg0',rxBytes:100,txBytes:200}]}};
  assert.equal(state.wgStatus.running,true); assert.equal(state.wgStatus.latestHandshakeAt,null);
  state.sampleWg(state.snapshot);
  state.snapshot.localWireguard = {receivedEpoch:12,running:true,interfaces:[{name:'labwg0',rxBytes:200,txBytes:500}]};
  state.sampleWg(state.snapshot);
  assert.equal(state.samples.length,1); assert.equal(state.samples[0].at,12);
  assert.equal(state.samples[0].a,400/1000000); assert.equal(state.samples[0].b,1200/1000000);
});
test('poll refresh never overwrites unsaved WG edits or silently advances their revision', async () => {
  const {state} = setup('wireguard');
  await state.refresh(false);
  state.draft.address = '10.77.9.1/24'; state.dirty = true;
  state.request = async () => ({ok: true, revision: 3, server: {address: '10.77.8.1/24'}});
  await state.refresh(false);
  assert.equal(state.draft.address, '10.77.9.1/24');
  assert.equal(state.draftRevision, 1);
  assert.equal(state.snapshot.revision, 3);
});
test('an old read resolving after a mutation is ignored', async () => {
  const {state} = setup('tcp'); let resolveRead;
  state.request = () => new Promise(r => { resolveRead = r; });
  const read = state.refresh(false);
  state.request = async () => ({ok: true, task: {id: 'new', state: 'running'}});
  await state.mutate('tcp.start', {});
  state.acceptTask({id: 'new', state: 'running', updatedEpoch: 10});
  resolveRead({ok: true, task: {id: 'old', state: 'stopped', updatedEpoch: 9}});
  await read;
  assert.equal(state.task.id, 'new');
});
test('destroyed page aborts requests, cancels polling and ignores late results', async () => {
  const {state, component} = setup('ddns'); let resolveRead; let aborted = false;
  state.request = () => new Promise(r => { resolveRead = r; });
  state._controllers = [{abort() { aborted = true; }}];
  const read = state.refresh(false);
  component.beforeDestroy.call(state);
  resolveRead({ok: true, records: [{id: 'other-router'}]});
  await read;
  assert.equal(aborted, true); assert.equal(state.loaded, false);
  assert.equal(state.snapshot.records, undefined);
});
test('credentials cannot be partly replaced when backend replaces the whole credential document', async () => {
  const {state} = setup('ddns'); let sent = false;
  state.editor = {id: 'existing', originalProvider: 'alidns', provider: 'alidns', hostname: 'home.example.com', type: 'A', credentials: {AccessKeyId: 'replacement'}};
  state.mutate = async () => { sent = true; };
  state.saveDdns();
  assert.equal(sent, false);
});
test('revision sent with a WG save is the edit baseline, preserving optimistic locking', () => {
  const {state} = setup('wireguard'); let body;
  state.draft = {address: '10.77.0.1/24', peers: [], endpointProfiles: []}; state.draftRevision = 4;
  state.snapshot = {revision: 8}; state.mutate = async (op, payload) => { body = payload; return null; };
  state.saveWg(); assert.equal(body.expectedRevision, 4);
});
test('TCP stop button remains enabled during a running test', () => {
  const {state, component} = setup('tcp');
  state.loaded = true; state.task = {id: 'tcp-live', state: 'running'};
  const h = (tag, options, children) => { if (children === undefined && (Array.isArray(options) || typeof options === 'string')) { children = options; options = {}; } return {tag, options, children}; };
  const tree = component.render.call(state, h);
  const form = tree.children.find(x => x && x.tag === 'el-form');
  assert.equal(form.options.props.disabled, undefined);
  const actions = form.children[form.children.length - 1];
  assert.equal(actions.children[0].children, '停止测试');
  assert.notEqual(actions.children[0].options.props.disabled, true);
});
test('DDNS existing credentials stay absent from update payload when fields are blank', async () => {
  const {state} = setup('ddns'); let body;
  state.editor = {id: 'existing', provider: 'alidns', originalProvider: 'alidns', hostname: 'home.example.com', type: 'A', credentials: {AccessKeyId: '', AccessKeySecret: '', zone: ''}};
  state.mutate = async (op, value) => { body = value; return null; };
  state.saveDdns();
  assert.equal(body.credentials, undefined); assert.equal(body.originalProvider, undefined);
});

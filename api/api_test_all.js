const https = require('https');
const GibberishAES = require('./aes.js');

const ROUTER_IP = process.env.ROUTER_IP;
const PASSWORD = process.env.ROUTER_PASSWORD;
const USERNAME = process.env.ROUTER_USERNAME || 'admin';

if (!ROUTER_IP || !PASSWORD) {
  console.error('Error: ROUTER_IP and ROUTER_PASSWORD environment variables are required.');
  console.error('Usage: ROUTER_IP=192.168.110.1 ROUTER_PASSWORD=your_password node api/api_test_all.js');
  process.exit(1);
}

function requestPromise(options, payload) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body
        });
      });
    });
    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function run() {
  console.log('1. Fetching login page to get dynamic encryption key...');
  const getRes = await requestPromise({
    hostname: ROUTER_IP,
    port: 443,
    path: '/cgi-bin/luci/',
    method: 'GET',
    rejectUnauthorized: false
  });
  
  const keyRegex = /GibberishAES\.enc\(passwordEl.value,\s*"([a-f0-9]+)"\)/;
  const match = getRes.body.match(keyRegex);
  if (!match) {
    console.error('Could not find GibberishAES key in login HTML.');
    return;
  }
  const encryptionKey = match[1];
  console.log('Extracted key:', encryptionKey);

  console.log('\n2. Logging in...');
  const encryptedPassword = GibberishAES.enc(PASSWORD, encryptionKey).replace(/\s+/g, '');
  const timestamp = (new Date().getTime() / 1000).toFixed(0);
  const loginPayload = JSON.stringify({
    method: 'login',
    params: {
      username: USERNAME,
      time: timestamp,
      encry: true,
      pwd: encryptedPassword,
      isCheckReadAgreement: 'true'
    }
  });

  const loginRes = await requestPromise({
    hostname: ROUTER_IP,
    port: 443,
    path: '/cgi-bin/luci/api/auth',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(loginPayload)
    },
    rejectUnauthorized: false
  }, loginPayload);

  const loginData = JSON.parse(loginRes.body);
  if (!loginData.data || !loginData.data.token) {
    console.error('Login failed:', loginRes.body);
    return;
  }

  const { token, sid } = loginData.data;
  const cookieHeader = loginRes.headers['set-cookie'] ? loginRes.headers['set-cookie'][0].split(';')[0] : '';
  console.log('Login successful! token:', token, 'sid:', sid);

  const callApi = async (endpoint, method, params = null) => {
    const path = `/cgi-bin/luci${endpoint}?auth=${sid}`;
    const payload = JSON.stringify({ method, params });
    console.log(`\nCalling ${endpoint} [method: ${method}]...`);
    const res = await requestPromise({
      hostname: ROUTER_IP,
      port: 443,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Cookie': cookieHeader
      },
      rejectUnauthorized: false
    }, payload);
    console.log('Status:', res.statusCode);
    console.log('Body:', res.body);
  };

  // Test various API endpoints and methods discovered in app.js
  await callApi('/api/overview', 'getDeviceInfo');
  await callApi('/api/overview', 'getHostName');
  await callApi('/api/overview', 'getUptime');
  await callApi('/api/system', 'getVersion');
  await callApi('/api/system', 'getSessiontime');
}

run().catch(console.error);

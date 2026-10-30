/**
 * Automated Unit & Integration Test Suite for Link Shield (detector.js + background.js)
 * Run via: npm test  (or: node tests/detector.test.js)
 */
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const extDir = path.resolve(__dirname, '..');
const Detector = require(path.join(extDir, 'detector.js'));

console.log('=== 1. Running Detection Engine Unit Tests ===');

// Test 1: Safe URL (www.google.com)
const googleRes = Detector.analyzeUrl('https://www.google.com/');
assert.strictEqual(googleRes.status, 'safe', 'Google should be safe');
assert.strictEqual(googleRes.badgeText, 'OK', 'Google badgeText should be OK');
assert.strictEqual(googleRes.badgeColor, '#10B981', 'Google badgeColor should be #10B981');
assert.strictEqual(googleRes.label, 'Safe', 'Google label should be Safe');
assert.strictEqual(googleRes.headline, 'No threats found');
assert.strictEqual(googleRes.displayHost, 'www.google.com');
assert.strictEqual(googleRes.domain, 'google.com');
assert.strictEqual(googleRes.httpsStatus, 'Secure');
assert.strictEqual(googleRes.location, 'United States');
assert.strictEqual(googleRes.ip, '142.250.72.14');
console.log('  [PASS] Safe URL (https://www.google.com/) -> Badge: OK, IP: 142.250.72.14, Location: United States');

// Test 2: Typosquatting / Brand Spoofing (g00gle.com)
const typoRes = Detector.analyzeUrl('https://www.g00gle.com/login');
assert.strictEqual(typoRes.status, 'danger', 'g00gle.com should be flagged as danger');
assert.strictEqual(typoRes.badgeText, 'RISK', 'g00gle.com badgeText should be RISK');
assert.ok(typoRes.riskScore >= 60, 'g00gle.com riskScore >= 60');
console.log(`  [PASS] Typosquatting URL (g00gle.com) -> Badge: ${typoRes.badgeText}, Score: ${typoRes.riskScore}/100`);

// Test 3: Subdomain Brand Deception + High-risk TLD + Executable
const phishRes = Detector.analyzeUrl('http://paypal.com.secure-login-update.tk/verify-account.exe');
assert.strictEqual(phishRes.status, 'danger');
assert.strictEqual(phishRes.badgeText, 'RISK');
assert.strictEqual(phishRes.isHttps, false);
assert.strictEqual(phishRes.httpsStatus, 'Insecure');
console.log(`  [PASS] Phishing + Malware URL -> Badge: ${phishRes.badgeText}, Score: ${phishRes.riskScore}/100`);

// Test 4: IDN Punycode Homograph Attack
const idnRes = Detector.analyzeUrl('https://xn--80ak6aa92e.com/');
assert.strictEqual(idnRes.badgeText !== 'OK', true, 'Punycode domain should not be OK');
assert.ok(idnRes.riskScore >= 50, 'Punycode domain should have elevated risk score');
console.log(`  [PASS] IDN Homograph URL (xn--80ak6aa92e.com) -> Badge: ${idnRes.badgeText}, Score: ${idnRes.riskScore}/100`);

// Test 5: Suspicious URL Shortener + HTTP
const shortRes = Detector.analyzeUrl('http://bit.ly/3xYzAbC-redirect');
assert.strictEqual(shortRes.status, 'suspicious', 'HTTP bit.ly link should be suspicious');
assert.strictEqual(shortRes.badgeText, 'WARN', 'Suspicious link badge should be WARN');
assert.strictEqual(shortRes.badgeColor, '#F59E0B');
console.log(`  [PASS] Suspicious Shortener URL (http://bit.ly/3xYzAbC-redirect) -> Badge: ${shortRes.badgeText}, Score: ${shortRes.riskScore}/100`);

// Test 6: Direct IP Host over HTTP
const ipRes = Detector.analyzeUrl('http://192.168.1.1/admin');
assert.strictEqual(ipRes.isHttps, false);
assert.ok(ipRes.riskScore >= 50, 'Direct HTTP IP host should be high risk');
console.log(`  [PASS] Direct IP Host (http://192.168.1.1/admin) -> Badge: ${ipRes.badgeText}, Score: ${ipRes.riskScore}/100`);

// Test 7: Executable javascript: URI scheme
const jsRes = Detector.analyzeUrl('javascript:alert(document.cookie)');
assert.strictEqual(jsRes.status, 'danger');
assert.strictEqual(jsRes.badgeText, 'RISK');
assert.strictEqual(jsRes.riskScore, 98);
console.log(`  [PASS] Executable URI (javascript:) -> Badge: ${jsRes.badgeText}, Score: ${jsRes.riskScore}/100`);

// Test 8: Custom Allowlist & Blocklist
const customBlocked = Detector.analyzeUrl('https://example.com', { customBlocklist: ['example.com'] });
assert.strictEqual(customBlocked.status, 'danger');
assert.strictEqual(customBlocked.badgeText, 'RISK');
const customAllowed = Detector.analyzeUrl('http://192.168.1.1/admin', { customAllowlist: ['192.168.1.1'] });
assert.strictEqual(customAllowed.status, 'safe');
assert.strictEqual(customAllowed.badgeText, 'OK');
console.log('  [PASS] Custom Allowlist & Blocklist overrides verified');

console.log('\n=== 2. Running Background Service Worker & Badge Integration Tests ===');

const badgeCalls = [];
const bgColorCalls = [];
const storageData = { settings: { protectionEnabled: true, strictMode: false, inPageBanner: true } };
let messageListener = null;

const sandbox = {
  LinkShieldDetector: Detector,
  importScripts: () => {},
  fetch: async () => ({ ok: false }),
  console,
  setTimeout,
  clearTimeout,
  AbortController,
  Map,
  Set,
  Date,
  URL,
  Math,
  Number,
  Array,
  Object,
  Promise,
  chrome: {
    storage: {
      local: {
        get: (keys, cb) => cb(storageData),
        set: (obj, cb) => {
          Object.assign(storageData, obj);
          if (cb) cb();
        }
      }
    },
    action: {
      setBadgeText: async (opts) => { badgeCalls.push(opts); },
      setBadgeBackgroundColor: async (opts) => { bgColorCalls.push(opts); },
      setBadgeTextColor: async () => {},
      setTitle: async () => {}
    },
    runtime: {
      onInstalled: { addListener: () => {} },
      onStartup: { addListener: () => {} },
      onMessage: {
        addListener: (fn) => { messageListener = fn; }
      }
    },
    tabs: {
      onUpdated: { addListener: () => {} },
      onActivated: { addListener: () => {} },
      onRemoved: { addListener: () => {} },
      get: async (id) => ({ id, url: 'https://www.google.com/' })
    }
  }
};

vm.createContext(sandbox);
const bgCode = fs.readFileSync(path.join(extDir, 'background.js'), 'utf8');
vm.runInContext(bgCode, sandbox);

(async () => {
  assert.ok(typeof messageListener === 'function', 'background.js should register chrome.runtime.onMessage listener');

  // Simulate SCAN_URL for Safe site
  await new Promise((resolve) => {
    messageListener({ type: 'SCAN_URL', url: 'https://www.google.com/', tabId: 10 }, {}, (res) => {
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.result.badgeText, 'OK');
      resolve();
    });
  });
  assert.strictEqual(badgeCalls[badgeCalls.length - 1].text, 'OK');
  assert.strictEqual(bgColorCalls[bgColorCalls.length - 1].color, '#10B981');
  console.log('  [PASS] Background Worker sets badge text "OK" (#10B981) for Safe URL');

  // Simulate SCAN_URL for Suspicious site
  await new Promise((resolve) => {
    messageListener({ type: 'SCAN_URL', url: 'http://bit.ly/3xYzAbC-redirect', tabId: 10 }, {}, (res) => {
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.result.badgeText, 'WARN');
      resolve();
    });
  });
  assert.strictEqual(badgeCalls[badgeCalls.length - 1].text, 'WARN');
  assert.strictEqual(bgColorCalls[bgColorCalls.length - 1].color, '#F59E0B');
  console.log('  [PASS] Background Worker sets badge text "WARN" (#F59E0B) for Suspicious URL');

  // Simulate SCAN_URL for Malicious site
  await new Promise((resolve) => {
    messageListener({ type: 'SCAN_URL', url: 'http://paypal.com.login-verify.tk/mal.exe', tabId: 10 }, {}, (res) => {
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.result.badgeText, 'RISK');
      resolve();
    });
  });
  assert.strictEqual(badgeCalls[badgeCalls.length - 1].text, 'RISK');
  assert.strictEqual(bgColorCalls[bgColorCalls.length - 1].color, '#EF4444');
  console.log('  [PASS] Background Worker sets badge text "RISK" (#EF4444) for Malicious URL');

  // Simulate Protection Paused -> OFF badge
  await new Promise((resolve) => {
    messageListener({ type: 'UPDATE_SETTINGS', settings: { protectionEnabled: false }, tabId: 10, currentUrl: 'https://www.google.com/' }, {}, (res) => {
      assert.strictEqual(res.ok, true);
      resolve();
    });
  });
  assert.strictEqual(badgeCalls[badgeCalls.length - 1].text, 'OFF');
  console.log('  [PASS] Background Worker sets badge text "OFF" (#64748B) when protection is paused');

  console.log('\nALL UNIT & INTEGRATION TESTS PASSED SUCCESSFULLY!');
})();

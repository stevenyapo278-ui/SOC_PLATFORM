'use strict';

/* Capture d'écran des pages via Chrome DevTools Protocol (headless).
   Usage : node .verify/screenshot.js [thème] [page,...]
   Expects : mock S1 sur 3211, app sur 3212 (dev / devpass). */

const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const CHROME = '/usr/bin/google-chrome';
const DEBUG_PORT = 9224;
const APP = 'http://127.0.0.1:3212';
const PROFILE = path.join(__dirname, 'chrome-profile-shots');
const OUT = path.join(__dirname, 'shots');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ALL_PAGES = [
  ['login', '/login'],
  ['dashboard', '/'],
  ['threats', '/threats'],
  ['alerts', '/alerts'],
  ['activities', '/activities'],
  ['agents', '/agents'],
  ['applications', '/applications'],
  ['incidents', '/incidents'],
  ['settings', '/settings'],
  ['api-docs', '/api-docs'],
  ['chat', '/chat'],
];

async function main() {
  const themes = (process.argv[2] || 'light,dark').split(',').map((t) => t.trim());
  const wanted = (process.argv[3] || '').split(',').map((t) => t.trim()).filter(Boolean);
  const pages = wanted.length ? ALL_PAGES.filter(([name]) => wanted.includes(name)) : ALL_PAGES;

  fs.rmSync(PROFILE, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });

  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--remote-allow-origins=*',
      `--remote-debugging-port=${DEBUG_PORT}`,
      `--user-data-dir=${PROFILE}`,
      '--window-size=1440,900',
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  const getJson = (url) =>
    new Promise((resolve, reject) => {
      fetch(url).then((r) => r.json()).then(resolve).catch(reject);
    });

  let target;
  for (let i = 0; i < 60; i += 1) {
    try {
      target = await getJson(`http://127.0.0.1:${DEBUG_PORT}/json/version`);
      break;
    } catch {
      await sleep(250);
    }
  }
  if (!target) {
    chrome.kill('SIGKILL');
    throw new Error('Chrome DevTools indisponible');
  }

  const { webSocketDebuggerUrl } = await (
    await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/new?about:blank`, { method: 'PUT' })
  ).json();

  const ws = new WebSocket(webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res, { once: true });
    ws.addEventListener('error', rej, { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const exceptions = [];
  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
      return;
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      const d = msg.params.exceptionDetails;
      exceptions.push(d.exception?.description || d.text);
    }
  });

  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };

  const navigate = async (url) => {
    await send('Page.navigate', { url });
    await sleep(1400);
  };

  const shot = async (name) => {
    const { data } = await send('Page.captureScreenshot', { format: 'png' });
    const file = path.join(OUT, `${name}.png`);
    fs.writeFileSync(file, Buffer.from(data, 'base64'));
    return file;
  };

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false,
  });

  // Login once (skip if the login page is all we shoot).
  if (!pages.every(([n]) => n === 'login')) {
    await navigate(`${APP}/login`);
    await evaluate(`(() => {
      document.getElementById('username').value = 'dev';
      document.getElementById('password').value = 'devpass';
      document.querySelector('form').requestSubmit();
      return true;
    })()`);
    await sleep(1800);
  }

  const results = [];
  for (const theme of themes) {
    for (const [name, route] of pages) {
      // Choisir le thème AVANT la navigation pour que theme.js l'applique au chargement.
      await evaluate(`window.localStorage.setItem('soc-theme', '${theme}'); true`);
      await navigate(`${APP}${route}`);
      await evaluate(`(() => {
        document.documentElement.setAttribute('data-bs-theme', '${theme}');
        return true;
      })()`);
      await sleep(700);
      const file = await shot(`${name}-${theme}`);
      results.push(path.relative(process.cwd(), file));
    }
  }

  console.log(JSON.stringify({ shots: results, exceptions }, null, 2));
  ws.close();
  chrome.kill('SIGKILL');
  await sleep(400);
  fs.rmSync(PROFILE, { recursive: true, force: true });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

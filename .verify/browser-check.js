'use strict';

const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

const CHROME = '/usr/bin/google-chrome';
const PORT = 9223;
const PROFILE = path.join(__dirname, 'chrome-profile');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function getJson(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (error) {
            reject(error);
          }
        });
      })
      .on('error', reject);
  });
}

async function waitForChrome() {
  for (let i = 0; i < 60; i += 1) {
    try {
      return await getJson(`http://127.0.0.1:${PORT}/json/version`);
    } catch {
      await sleep(250);
    }
  }
  throw new Error('Chrome DevTools endpoint unavailable');
}

async function main() {
  fs.rmSync(PROFILE, { recursive: true, force: true });
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--remote-allow-origins=*',
      `--remote-debugging-port=${PORT}`,
      `--user-data-dir=${PROFILE}`,
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  const exceptions = [];
  const consoleErrors = [];

  try {
    await waitForChrome();
    const target = await (
      await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`, { method: 'PUT' })
    ).json();

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', reject, { once: true });
    });

    let nextId = 0;
    const pending = new Map();
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id && pending.has(message.id)) {
        const { resolve, reject } = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) reject(new Error(JSON.stringify(message.error)));
        else resolve(message.result);
        return;
      }
      if (message.method === 'Runtime.exceptionThrown') {
        const details = message.params.exceptionDetails;
        exceptions.push(details.exception?.description || details.text);
      }
      if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') {
        consoleErrors.push(`${message.params.entry.source}: ${message.params.entry.text}`);
      }
    });

    const send = (method, params = {}) =>
      new Promise((resolve, reject) => {
        const id = ++nextId;
        pending.set(id, { resolve, reject });
        ws.send(JSON.stringify({ id, method, params }));
      });

    await send('Page.enable');
    await send('Runtime.enable');
    await send('Log.enable');

    const evaluate = async (expression) => {
      const result = await send('Runtime.evaluate', {
        expression,
        returnByValue: true,
        awaitPromise: true,
      });
      if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
      return result.result.value;
    };

    await send('Page.navigate', { url: 'http://127.0.0.1:3212/login' });
    await sleep(1500);

    const loginSnapshot = await evaluate(`JSON.stringify({
      title: document.title,
      path: location.pathname,
      stylesheets: document.styleSheets.length,
      background: getComputedStyle(document.body).backgroundColor,
      form: !!document.getElementById('login-form'),
      year: document.querySelector('[data-soc-year]')?.textContent || ''
    })`);

    await evaluate(`(() => {
      document.getElementById('username').value = 'dev';
      document.getElementById('password').value = 'devpass';
      document.getElementById('login-form').requestSubmit();
      return true;
    })()`);

    await sleep(3500);

    const dashboardSnapshot = await evaluate(`JSON.stringify({
      path: location.pathname,
      title: document.title,
      stylesheets: document.styleSheets.length,
      background: getComputedStyle(document.body).backgroundColor,
      kpiAgents: document.querySelector('[data-kpi="agentsTotal"]')?.textContent.trim() || '',
      kpiThreats: document.querySelector('[data-kpi="threatsTotal"]')?.textContent.trim() || '',
      kpiAlerts: document.querySelector('[data-kpi="alertsTotal"]')?.textContent.trim() || '',
      kpiInfected: document.querySelector('[data-kpi="agentsInfected"]')?.textContent.trim() || '',
      agentSub: document.querySelector('[data-kpi-sub="agents"]')?.textContent.trim() || '',
      threatRows: document.querySelectorAll('#recent-threats-body tr').length,
      alertItems: document.querySelectorAll('#recent-alerts-list .list-group-item').length,
      activityRows: document.querySelectorAll('#recent-activities-body tr').length,
      sidebarLinks: document.querySelectorAll('#soc-sidebar .side-nav-link').length,
      trendChart: !!document.querySelector('#threat-trend-chart svg'),
      severityChart: !!document.querySelector('#severity-chart svg'),
      user: document.querySelector('[data-soc-user]')?.textContent.trim() || '',
      error: document.querySelector('#dashboard-error')?.textContent.trim() || '',
      warning: document.querySelector('#dashboard-warning')?.textContent.trim() || ''
    })`);

    await send('Page.navigate', { url: 'http://127.0.0.1:3212/agents' });
    await sleep(2000);

    const agentsSnapshot = await evaluate(`JSON.stringify({
      path: location.pathname,
      rows: document.querySelectorAll('#agents-table-body tr').length,
      total: document.querySelector('[data-agents-total]')?.textContent.trim() || '',
      firstName: document.querySelector('#agents-table-body tr td')?.textContent.trim() || '',
      statusBadge: document.querySelector('#agents-table-body tr td:nth-child(5) .badge')?.textContent.trim() || '',
      error: document.querySelector('#agents-error')?.textContent.trim() || ''
    })`);

    console.log(
      JSON.stringify(
        {
          login: JSON.parse(loginSnapshot),
          dashboard: JSON.parse(dashboardSnapshot),
          agents: JSON.parse(agentsSnapshot),
          exceptions,
          consoleErrors,
        },
        null,
        2,
      ),
    );

    ws.close();
  } finally {
    chrome.kill('SIGKILL');
    await sleep(500);
    fs.rmSync(PROFILE, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

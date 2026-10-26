'use strict';

// Vérification navigateur du suivi collaboratif (dossiers d'incident) :
//   1. base PostgreSQL jetable `soc_verify` (recréée à chaque exécution)
//   2. mock SentinelOne sur 3211 + application sur 3212
//   3. Chrome headless (CDP) : login dev, attribution depuis /threats,
//      journal/commentaire/modification de statut depuis /incidents, badge de
//      suivi dans l'enquête.
//
//   node .verify/collab-check.js
//
// Renvoie un JSON { …, exceptions: [], consoleErrors: [] } et code 0 si tout
// est au vert. Pas de dépendance : CDP en WebSocket natif (Node >= 22) comme
// browser-check.js.

const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

const CHROME = '/usr/bin/google-chrome';
const CDP_PORT = 9223;
const APP_PORT = 3212;
const MOCK_PORT = 3211;
const DB_URL = process.env.VERIFY_DATABASE_URL || 'postgresql://soc:soc@127.0.0.1:5435/soc_verify';
const ROOT = path.join(__dirname, '..');
const PROFILE = path.join(__dirname, 'chrome-profile-collab');
const appLog = [];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function getJson(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
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

// Attend une réponse HTTP quelconque (la page /login est du HTML, pas du JSON).
async function waitForHttp(url, tries = 80) {
  for (let i = 0; i < tries; i += 1) {
    try {
      await new Promise((resolve, reject) => {
        const request = http.get(url, (res) => {
          res.resume();
          if (res.statusCode && res.statusCode < 500) resolve();
          else reject(new Error(`status ${res.statusCode}`));
        });
        request.on('error', reject);
      });
      return;
    } catch {
      await sleep(400);
    }
  }
  throw new Error(`Serveur indisponible : ${url}`);
}

// La première synchro complète remplit `threats` : on attend les lignes avant
// d'ouvrir le navigateur (sinon la page Menaces est légitimement vide).
async function waitForThreatsInDb() {
  const { Client } = require('pg');
  for (let i = 0; i < 80; i += 1) {
    const client = new Client({ connectionString: DB_URL, connectionTimeoutMillis: 2000 });
    try {
      await client.connect();
      const { rows } = await client.query('SELECT count(*)::int AS n FROM threats');
      await client.end();
      if (rows[0].n > 0) return rows[0].n;
    } catch {
      try {
        await client.end();
      } catch {
        /* déjà fermé */
      }
    }
    await sleep(500);
  }
  throw new Error('Aucune menace synchronisée depuis le mock SentinelOne.');
}

async function resetDatabase() {
  const { Client } = require('pg');
  const target = new URL(DB_URL);
  const dbName = target.pathname.replace(/^\//, '');
  if (!/^[a-z_][a-z0-9_]*$/i.test(dbName)) throw new Error('Nom de base invalide.');

  const admin = new URL(DB_URL);
  admin.pathname = '/postgres';
  const bootstrap = new Client({ connectionString: admin.toString(), connectionTimeoutMillis: 3000 });
  await bootstrap.connect();
  await bootstrap
    .query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`)
    .catch(() => bootstrap.query(`DROP DATABASE IF EXISTS "${dbName}"`));
  await bootstrap.query(`CREATE DATABASE "${dbName}"`);
  await bootstrap.end();
}

async function waitForChrome() {
  for (let i = 0; i < 60; i += 1) {
    try {
      return await getJson(`http://127.0.0.1:${CDP_PORT}/json/version`);
    } catch {
      await sleep(250);
    }
  }
  throw new Error('Chrome DevTools endpoint unavailable');
}

async function main() {
  await resetDatabase();

  const mock = spawn('node', [path.join(__dirname, 'mock-s1.js')], { stdio: 'ignore' });
  const app = spawn('node', ['server.js'], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: 'development',
      HOST: '127.0.0.1',
      PORT: String(APP_PORT),
      SESSION_SECRET: 'verify-collab-secret-0123456789',
      DATABASE_URL: DB_URL,
      DB_ENABLED: 'true',
      DB_SYNC_ENABLED: 'true',
      DB_SYNC_INTERVAL_MIN: '60',
      AI_RAG_INDEX_ENABLED: 'false',
      S1_URL: `http://127.0.0.1:${MOCK_PORT}`,
      S1_API_TOKEN: 'test-token',
      AUTH_DEV_LOGIN: 'true',
      AUTH_DEV_USER: 'dev',
      AUTH_DEV_PASSWORD: 'devpass',
      AUTH_DEV_NAME: 'Développeur local',
      LOG_LEVEL: 'error',
    },
  });

  fs.rmSync(PROFILE, { recursive: true, force: true });
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--remote-allow-origins=*',
      `--remote-debugging-port=${CDP_PORT}`,
      `--user-data-dir=${PROFILE}`,
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  const exceptions = [];
  const consoleErrors = [];
  const report = {};

  try {
    await waitForHttp(`http://127.0.0.1:${APP_PORT}/login`);
    const threatsSeeded = await waitForThreatsInDb();
    report.threatsSeeded = threatsSeeded;

    await waitForChrome();
    const target = await (
      await fetch(`http://127.0.0.1:${CDP_PORT}/json/new?about:blank`, { method: 'PUT' })
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

    /* ── login ── */
    await send('Page.navigate', { url: `http://127.0.0.1:${APP_PORT}/login` });
    await sleep(1500);
    await evaluate(`(() => {
      document.getElementById('username').value = 'dev';
      document.getElementById('password').value = 'devpass';
      document.getElementById('login-form').requestSubmit();
      return true;
    })()`);
    await sleep(3000);

    /* ── menaces : colonne suivi + attribution ── */
    await send('Page.navigate', { url: `http://127.0.0.1:${APP_PORT}/threats` });
    await sleep(3000);

    report.threats = JSON.parse(
      await evaluate(`JSON.stringify({
        path: location.pathname,
        rows: document.querySelectorAll('#threats-table-body tr.soc-threat-row').length,
        headers: [...document.querySelectorAll('thead th')].map((th) => th.textContent.trim()),
        suiviCells: document.querySelectorAll('#threats-table-body [data-assign-case]').length,
        error: document.querySelector('#threats-error')?.textContent.trim() || '',
        sidebarIncidents: !!document.querySelector('#soc-sidebar a[href="/incidents"]')
      })`),
    );

    await evaluate(`document.querySelector('#threats-table-body [data-assign-case]').click()`);
    await sleep(1500);

    report.assignModal = JSON.parse(
      await evaluate(`JSON.stringify({
        open: document.getElementById('threat-assign-modal').classList.contains('show'),
        title: document.getElementById('threat-assign-title').textContent.trim(),
        existing: document.getElementById('threat-assign-existing').textContent.trim(),
        assignee: document.getElementById('threat-assign-assignee').value,
        assigneeOptions: document.getElementById('threat-assign-assignee').options.length,
        priority: document.getElementById('threat-assign-priority').value
      })`),
    );

    await evaluate(`(() => {
      document.getElementById('threat-assign-comment').value = 'Isoler SRV-BETA puis analyser le binaire.';
      document.getElementById('threat-assign-submit').click();
      return true;
    })()`);
    await sleep(2500);

    report.afterAssign = JSON.parse(
      await evaluate(`JSON.stringify({
        modalOpen: document.getElementById('threat-assign-modal').classList.contains('show'),
        alert: document.querySelector('#threats-error')?.textContent.trim() || '',
        firstRowSuivi: document.querySelector('#threats-table-body tr.soc-threat-row td:nth-child(7)')?.textContent.trim() || '',
        error: document.querySelector('#threat-assign-error')?.textContent.trim() || ''
      })`),
    );

    /* ── incidents : compteurs, détail, journal, statut ── */
    await send('Page.navigate', { url: `http://127.0.0.1:${APP_PORT}/incidents` });
    await sleep(3000);

    report.incidents = JSON.parse(
      await evaluate(`JSON.stringify({
        path: location.pathname,
        rows: document.querySelectorAll('#incidents-table-body tr.soc-case-row').length,
        kpiTotal: document.querySelector('[data-kpi-total]')?.textContent.trim() || '',
        kpiOpen: document.querySelector('[data-kpi-open]')?.textContent.trim() || '',
        kpiMine: document.querySelector('[data-kpi-mine]')?.textContent.trim() || '',
        filters: [...document.querySelectorAll('#incidents-search select')].map((s) => s.options.length),
        error: document.querySelector('#incidents-error')?.textContent.trim() || ''
      })`),
    );

    await evaluate(`document.querySelector('#incidents-table-body [data-open-case]').click()`);
    await sleep(2500);

    report.caseDetail = JSON.parse(
      await evaluate(`JSON.stringify({
        open: document.getElementById('case-modal').classList.contains('show'),
        title: document.getElementById('case-modal-title').textContent.trim(),
        status: document.getElementById('case-status')?.value || '',
        assignee: document.getElementById('case-assignee')?.value || '',
        priority: document.getElementById('case-priority')?.value || '',
        journalItems: document.querySelectorAll('#case-journal-body .soc-list-item').length,
        journalText: document.querySelector('#case-journal-body')?.textContent.replace(/\\s+/g, ' ').trim().slice(0, 240) || ''
      })`),
    );

    // Commentaire d'équipe.
    await evaluate(`(() => {
      document.getElementById('case-comment').value = 'Binaire envoyé au sandbox.';
      document.getElementById('case-comment-form').requestSubmit();
      return true;
    })()`);
    await sleep(2000);

    report.afterComment = JSON.parse(
      await evaluate(`JSON.stringify({
        journalItems: document.querySelectorAll('#case-journal-body .soc-list-item').length,
        comment: document.querySelector('#case-journal-body .soc-case-comment')?.textContent.trim() || '',
        error: document.querySelector('#case-error')?.textContent.trim() || ''
      })`),
    );

    // Changement de statut via le sélecteur partagé.
    await evaluate(`(() => {
      const select = document.getElementById('case-status');
      select.value = 'en_cours';
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`);
    await sleep(2500);

    report.afterStatus = JSON.parse(
      await evaluate(`JSON.stringify({
        status: document.getElementById('case-status')?.value || '',
        journalItems: document.querySelectorAll('#case-journal-body .soc-list-item').length,
        journalText: document.querySelector('#case-journal-body')?.textContent.replace(/\\s+/g, ' ').trim().slice(0, 320) || '',
        error: document.querySelector('#case-error')?.textContent.trim() || ''
      })`),
    );

    // Pièce jointe : un petit PDF envoyé par le formulaire.
    await evaluate(`(async () => {
      const file = new File(['%PDF-1.4 rapport de confir\\n'], 'rapport.pdf', { type: 'application/pdf' });
      const input = document.getElementById('case-file');
      const transfer = new DataTransfer();
      transfer.items.add(file);
      input.files = transfer.files;
      document.getElementById('case-upload-form').requestSubmit();
      return true;
    })()`);
    await sleep(2500);

    report.afterUpload = JSON.parse(
      await evaluate(`JSON.stringify({
        count: document.getElementById('case-attachment-count')?.textContent.trim() || '0',
        rows: document.querySelectorAll('#case-attachments-body tbody tr').length,
        status: document.querySelector('#case-upload-status')?.textContent.trim() || '',
        error: document.querySelector('#case-error')?.textContent.trim() || ''
      })`),
    );

    /* ── enquête menace : badge de suivi ── */
    await send('Page.navigate', { url: `http://127.0.0.1:${APP_PORT}/threats?investigate=t1` });
    await sleep(4000);

    report.investigate = JSON.parse(
      await evaluate(`JSON.stringify({
        open: document.getElementById('threat-investigate-modal').classList.contains('show'),
        badges: [...document.querySelectorAll('#threat-investigate-badges .badge')].map((b) => b.textContent.replace(/\\s+/g, ' ').trim()),
        caseHref: document.querySelector('#threat-investigate-badges a[href^="/incidents?case="]')?.getAttribute('href') || '',
        error: document.querySelector('#threat-investigate-error')?.textContent.trim() || ''
      })`),
    );

    /* ── page Incidents approfondie ?case= ── */
    const deepHref = report.investigate.caseHref;
    if (deepHref) {
      await send('Page.navigate', { url: `http://127.0.0.1:${APP_PORT}${deepHref}` });
      await sleep(3000);
      report.deepLink = JSON.parse(
        await evaluate(`JSON.stringify({
          path: location.pathname,
          open: document.getElementById('case-modal').classList.contains('show'),
          title: document.getElementById('case-modal-title').textContent.trim()
        })`),
      );
    }

    report.exceptions = exceptions;
    report.consoleErrors = consoleErrors;
    console.log(JSON.stringify(report, null, 2));

    const failures = [];
    if (report.threats.rows < 1) failures.push('aucune ligne de menace');
    if (!report.threats.headers.includes('Suivi')) failures.push('colonne Suivi absente');
    if (!report.assignModal.open) failures.push("modale d'attribution non ouverte");
    if (report.assignModal.assigneeOptions < 1) failures.push('roster vide dans la modale');
    if (!report.afterAssign.alert) failures.push('pas de confirmation après attribution');
    if (!/dev/.test(report.afterAssign.firstRowSuivi)) failures.push('suivi non visible dans le tableau');
    if (report.incidents.rows !== 1) failures.push(`attendu 1 dossier, obtenu ${report.incidents.rows}`);
    if (report.incidents.kpiTotal !== '1') failures.push('KPI dossiers != 1');
    if (!report.caseDetail.open) failures.push('détail de dossier non ouvert');
    if (report.caseDetail.assignee !== 'dev') failures.push('technicien absent des contrôles');
    if (report.afterComment.journalItems <= report.caseDetail.journalItems) failures.push('commentaire absent du journal');
    if (report.afterStatus.status !== 'en_cours') failures.push('statut non appliqué');
    if (report.afterUpload.rows < 1) failures.push('pièce jointe non listée');
    if (!report.investigate.caseHref) failures.push('badge de suivi absent de l\u2019enquête');
    if (exceptions.length) failures.push(`${exceptions.length} exception(s) JS`);
    if (consoleErrors.length) failures.push(`${consoleErrors.length} erreur(s) console`);

    if (failures.length) {
      console.error(`\nÉCHEC : ${failures.join(' — ')}`);
      process.exitCode = 1;
    } else {
      console.log('\nOK — parcours collaboratif vérifié dans le navigateur.');
    }

    ws.close();
  } finally {
    chrome.kill('SIGKILL');
    app.kill('SIGKILL');
    mock.kill('SIGKILL');
    await sleep(600);
  fs.rmSync(PROFILE, { recursive: true, force: true });
  app.stdout.on('data', (chunk) => appLog.push(String(chunk)));
  app.stderr.on('data', (chunk) => appLog.push(String(chunk)));
  }
}

main().catch((error) => {
  console.error(error);
  if (appLog.length) {
    console.error('\n--- journal application (fin) ---');
    console.error(appLog.join('').split('\n').slice(-30).join('\n'));
  }
  process.exit(1);
});

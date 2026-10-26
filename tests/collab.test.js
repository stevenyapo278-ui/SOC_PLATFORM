'use strict';

// Collaboration (dossiers d'incident) : attribution d'une menace à un
// technicien, journal d'équipe, rapports joints — tout passe par PostgreSQL
// locale, SentinelOne n'est jamais contacté.
//
// Base dédiée `soc_test_collab` : tests/store.test.js recrée `soc_test` à chaque
// exécution (DROP SCHEMA) et node --test lance les fichiers en parallèle.
// Sans PostgreSQL joignable, la suite est sautée — `npm test` reste vert.
//   TEST_DATABASE_URL_COLLAB=postgresql://user:pass@host:port/soc_collab npm test

const http = require('node:http');
const { once } = require('node:events');
const test = require('node:test');
const assert = require('node:assert/strict');
const { Client } = require('pg');

const TEST_URL =
  process.env.TEST_DATABASE_URL_COLLAB ||
  'postgresql://soc:soc@127.0.0.1:5435/soc_test_collab';

let ready = false;
let appServer = null;
let baseUrl = '';
let cookie = '';
let closePool = null;
let db = null;
let store = null;

const DEV = { username: 'dev', displayName: 'Développeur local' };

/* ───────────────────────────── helpers HTTP ──────────────────────────────── */

function request(path, { method = 'GET', body, headers = {} } = {}) {
  return fetch(`${baseUrl}${path}`, {
    method,
    headers: { Cookie: cookie, ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function json(path, options) {
  const response = await request(path, options);
  return { status: response.status, body: await response.json() };
}

async function login() {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'dev', password: 'dev-password' }),
  });
  assert.equal(response.status, 200);
  cookie = response.headers.getSetCookie()[0].split(';')[0];
}

/* ──────────────────────────── base PostgreSQL ────────────────────────────── */

async function probe(connectionString) {
  const candidate = new Client({ connectionString, connectionTimeoutMillis: 2000 });
  try {
    await candidate.connect();
    await candidate.end();
    return true;
  } catch {
    try {
      await candidate.end();
    } catch {
      /* déjà fermé */
    }
    return false;
  }
}

async function ensureDatabase() {
  if (await probe(TEST_URL)) return true;

  const target = new URL(TEST_URL);
  const dbName = target.pathname.replace(/^\//, '');
  if (!/^[a-z_][a-z0-9_]*$/i.test(dbName)) return false;

  const admin = new URL(TEST_URL);
  admin.pathname = '/postgres';
  try {
    const clientDb = new Client({ connectionString: admin.toString(), connectionTimeoutMillis: 2000 });
    await clientDb.connect();
    await clientDb.query(`CREATE DATABASE "${dbName}"`);
    await clientDb.end();
  } catch {
    return false;
  }
  return probe(TEST_URL);
}

function maybe(t) {
  if (ready) return false;
  t.skip('PostgreSQL indisponible — suite de collaboration ignorée');
  return true;
}

async function seedThreat(id, name) {
  const raw = {
    threatInfo: { threatId: id, threatName: name, severity: 'high', agentId: 'a1' },
    agentRealtimeInfo: { agentId: 'a1', agentComputerName: 'PC-ALPHA', siteName: 'Siège' },
  };
  await db.query(
    `INSERT INTO threats (id, name, severity, agent_id, agent_name, site, raw, created_at, updated_at)
     VALUES ($1, $2, 'high', 'a1', 'PC-ALPHA', 'Siège', $3::jsonb, now(), now())`,
    [id, name, JSON.stringify(raw)],
  );
}

/* ────────────────────────────────── suite ────────────────────────────────── */

test.before(async () => {
  ready = await ensureDatabase();
  if (!ready) return;

  process.env.NODE_ENV = 'test';
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.AUTH_DEV_LOGIN = 'true';
  process.env.AUTH_DEV_USER = 'dev';
  process.env.AUTH_DEV_PASSWORD = 'dev-password';
  process.env.AUTH_RATE_LIMIT_MAX = '100';
  process.env.LOG_LEVEL = 'error';
  process.env.DATABASE_URL = TEST_URL;
  process.env.DB_ENABLED = 'true';
  process.env.DB_SYNC_ENABLED = 'false'; // aucune synchro : on ne teste que le local
  process.env.AI_RAG_INDEX_ENABLED = 'false';

  db = require('../src/db');
  closePool = db.closePool;
  await db.query('DROP SCHEMA public CASCADE');
  await db.query('CREATE SCHEMA public');
  await db.migrateOnce();

  store = require('../src/db/store');

  await seedThreat('th-1', 'Trojan.FakeAlert');
  await seedThreat('th-2', 'Worm.LateralMove');

  const { createApp } = require('../src/app');
  // Pas de client S1 injecté : toute lecture passée par PostgreSQL doit marcher
  // seule (sinon la route retomberait sur une console non configurée).
  const app = createApp();
  appServer = app.listen(0, '127.0.0.1');
  await once(appServer, 'listening');
  baseUrl = `http://127.0.0.1:${appServer.address().port}`;
  await login();
});

test.after(async () => {
  if (appServer) {
    appServer.close();
    await once(appServer, 'close');
  }
  if (closePool) await closePool().catch(() => {});
});

test('roster : la connexion alimente /api/users', async (t) => {
  if (maybe(t)) return;
  const { status, body } = await json('/api/users');
  assert.equal(status, 200);
  const dev = body.data.find((user) => user.username === DEV.username);
  assert.ok(dev, 'le compte connecté doit figurer dans le roster');
  assert.equal(dev.role, 'admin');
  assert.equal(dev.displayName, 'Développeur local');
  assert.ok(dev.lastLoginAt, 'lastLoginAt renseigné à la connexion');
});

test('attribution : création d’un dossier pour une menace', async (t) => {
  if (maybe(t)) return;

  const invalid = await json('/api/cases', { method: 'POST', body: { threatId: 'th-999', assignee: 'dev' } });
  assert.equal(invalid.status, 404, 'menace absente de la base locale');

  const noAssignee = await json('/api/cases', { method: 'POST', body: { threatId: 'th-1' } });
  assert.equal(noAssignee.status, 400);
  assert.match(noAssignee.body.error, /technicien/i);

  const created = await json('/api/cases', {
    method: 'POST',
    body: { threatId: 'th-1', assignee: DEV.username, priority: 'haute' },
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.data.status, 'nouveau');
  assert.equal(created.body.data.priority, 'haute');
  assert.equal(created.body.data.assignee, DEV.username);
  assert.equal(created.body.data.threat.id, 'th-1');
  assert.equal(created.body.data.threat.name, 'Trojan.FakeAlert');

  const duplicate = await json('/api/cases', {
    method: 'POST',
    body: { threatId: 'th-1', assignee: 'autre' },
  });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.caseId, created.body.data.id, 'le 409 renvoie le dossier existant');

  const detail = await json(`/api/cases/${created.body.data.id}`);
  assert.equal(detail.status, 200);
  const types = detail.body.data.events.map((event) => event.type).sort();
  assert.deepEqual(types, ['assigned', 'created']);
  const assigned = detail.body.data.events.find((event) => event.type === 'assigned');
  assert.deepEqual(assigned.payload, { from: '', to: DEV.username });
});

test('suivi : statut, priorité et attribution génèrent le journal', async (t) => {
  if (maybe(t)) return;
  const list = await json('/api/cases?threatId=th-1');
  assert.equal(list.status, 200);
  assert.equal(list.body.data.length, 1);
  const id = list.body.data[0].id;

  const changed = await json(`/api/cases/${id}`, {
    method: 'PATCH',
    body: { status: 'en_cours' },
  });
  assert.equal(changed.status, 200);
  assert.equal(changed.body.changed, true);
  assert.equal(changed.body.data.status, 'en_cours');

  const same = await json(`/api/cases/${id}`, { method: 'PATCH', body: { status: 'en_cours' } });
  assert.equal(same.status, 200);
  assert.equal(same.body.changed, false, 'une valeur identique ne produit pas d’événement');

  const invalid = await json(`/api/cases/${id}`, { method: 'PATCH', body: { status: 'en_fin' } });
  assert.equal(invalid.status, 400);

  const empty = await json(`/api/cases/${id}`, { method: 'PATCH', body: {} });
  assert.equal(empty.status, 400);

  const reassigned = await json(`/api/cases/${id}`, {
    method: 'PATCH',
    body: { priority: 'critique', assignee: 'alice' },
  });
  assert.equal(reassigned.status, 200);
  assert.equal(reassigned.body.changed, true);
  assert.equal(reassigned.body.data.priority, 'critique');
  assert.equal(reassigned.body.data.assignee, 'alice');

  const detail = await json(`/api/cases/${id}`);
  const events = detail.body.data.events;
  assert.equal(events.filter((event) => event.type === 'status').length, 1);
  assert.equal(events.filter((event) => event.type === 'priority').length, 1);
  assert.equal(events.filter((event) => event.type === 'assigned').length, 2);
  const statusEvent = events.find((event) => event.type === 'status');
  assert.deepEqual(statusEvent.payload, { from: 'nouveau', to: 'en_cours' });
  assert.equal(statusEvent.author, DEV.username);
  assert.equal(detail.body.data.case.commentCount, 0);
});

test('commentaires : messages de l’équipe', async (t) => {
  if (maybe(t)) return;
  const list = await json('/api/cases?threatId=th-1');
  const id = list.body.data[0].id;

  const blank = await json(`/api/cases/${id}/events`, { method: 'POST', body: { message: '   ' } });
  assert.equal(blank.status, 400);

  const posted = await json(`/api/cases/${id}/events`, {
    method: 'POST',
    body: { message: '  Analyse en cours — binaire isolé sur PC-ALPHA  ' },
  });
  assert.equal(posted.status, 201);
  assert.equal(posted.body.data.type, 'comment');
  assert.equal(posted.body.data.author, DEV.username);
  assert.equal(posted.body.data.message, 'Analyse en cours — binaire isolé sur PC-ALPHA');

  const missing = await json('/api/cases/999999/events', { method: 'POST', body: { message: 'x' } });
  assert.equal(missing.status, 404);

  const detail = await json(`/api/cases/${id}`);
  assert.equal(detail.body.data.case.commentCount, 1);
  assert.ok(detail.body.data.events.some((event) => event.type === 'comment'));
});

test('pièces jointes : rapport d’incident', async (t) => {
  if (maybe(t)) return;
  const list = await json('/api/cases?threatId=th-1');
  const id = list.body.data[0].id;

  const refused = new FormData();
  refused.append('file', new Blob([Buffer.from('MZ payload')], { type: 'application/octet-stream' }), 'payload.exe');
  const refusedResponse = await fetch(`${baseUrl}/api/cases/${id}/attachments`, {
    method: 'POST',
    headers: { Cookie: cookie },
    body: refused,
  });
  assert.equal(refusedResponse.status, 400);
  assert.match((await refusedResponse.json()).error, /Format non autorisé/i);

  const bytes = Buffer.from('%PDF-1.4 rapport d\u2019incident\n');
  const form = new FormData();
  form.append('file', new Blob([bytes], { type: 'application/pdf' }), 'rapport-incident.pdf');
  const uploaded = await fetch(`${baseUrl}/api/cases/${id}/attachments`, {
    method: 'POST',
    headers: { Cookie: cookie },
    body: form,
  });
  assert.equal(uploaded.status, 201);
  const attachment = (await uploaded.json()).data;
  assert.equal(attachment.filename, 'rapport-incident.pdf');
  assert.equal(attachment.contentType, 'application/pdf');
  assert.equal(attachment.size, bytes.length);
  assert.equal(attachment.uploadedBy, DEV.username);

  const detail = await json(`/api/cases/${id}`);
  assert.equal(detail.body.data.attachments.length, 1);
  assert.equal(detail.body.data.case.attachmentCount, 1);
  assert.ok(detail.body.data.events.some((event) => event.type === 'attachment_added'));

  const download = await fetch(`${baseUrl}/api/cases/${id}/attachments/${attachment.id}`, {
    headers: { Cookie: cookie },
  });
  assert.equal(download.status, 200);
  assert.equal(download.headers.get('content-type'), 'application/pdf');
  assert.match(download.headers.get('content-disposition'), /attachment; filename="rapport-incident\.pdf"/);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), bytes);

  const unknown = await fetch(`${baseUrl}/api/cases/${id}/attachments/424242`, { headers: { Cookie: cookie } });
  assert.equal(unknown.status, 404);

  const removed = await json(`/api/cases/${id}/attachments/${attachment.id}`, { method: 'DELETE' });
  assert.equal(removed.status, 200);
  assert.equal(removed.body.data.filename, 'rapport-incident.pdf');
  assert.equal((await json(`/api/cases/${id}`)).body.data.attachments.length, 0);
});

test('liste des menaces : dossier joint + filtre d’attribution', async (t) => {
  if (maybe(t)) return;

  const all = await json('/api/threats?limit=10');
  assert.equal(all.status, 200);
  assert.equal(all.body.data.length, 2, 'deux menaces en base');
  const withCase = all.body.data.find((threat) => threat.id === 'th-1');
  const withoutCase = all.body.data.find((threat) => threat.id === 'th-2');
  assert.equal(withCase.case.assignee, 'alice', 'jointure : dernière attribution');
  assert.equal(withCase.case.status, 'en_cours');
  assert.equal(withoutCase.case, null, 'menace encore sans dossier');

  const mine = await json('/api/threats?assignedTo=me');
  assert.equal(mine.body.data.length, 0, '`me` = identifiant de session (dev) → aucun dossier');

  const none = await json('/api/threats?assignedTo=none');
  assert.equal(none.body.data.length, 1);
  assert.equal(none.body.data[0].id, 'th-2');

  const alice = await json('/api/threats?assignedTo=alice');
  assert.equal(alice.body.data.length, 1);
  assert.equal(alice.body.data[0].id, 'th-1');
});

test('résumé : compteurs exacts de la page Incidents', async (t) => {
  if (maybe(t)) return;
  const { status, body } = await json('/api/cases/summary');
  assert.equal(status, 200);
  assert.equal(body.data.total, 1);
  assert.equal(body.data.open, 1, 'en_cours est ouvert');
  assert.equal(body.data.closed, 0);
  assert.equal(body.data.critical, 1, 'priorité critique ouverte');
  assert.equal(body.data.mine, 0, 'le dossier est attribué à alice, pas à dev');
  assert.equal(body.data.assignedToMe, 0);
});

test('répertoire : la page Incidents est servie', async (t) => {
  if (maybe(t)) return;
  const response = await fetch(`${baseUrl}/incidents`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type') || '', /text\/html/);
  const html = await response.text();
  assert.match(html, /<title>/);
});

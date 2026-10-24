'use strict';

// Chemin de lecture PostgreSQL : les vues doivent se servir dans la base sans
// repartir vers SentinelOne, la synchro delta ne doit récupérer que ce qui a
// bougé, et la réconciliation doit reprendre une passe complète.
//
// Nécessite un PostgreSQL : la base `soc_test` est créée au besoin.
// Sans base joignable, la suite est sautée — `npm test` reste vert partout.
//   TEST_DATABASE_URL=postgresql://user:pass@host:port/soc_test npm test

const http = require('node:http');
const { once } = require('node:events');
const test = require('node:test');
const assert = require('node:assert/strict');
const { Client } = require('pg');

const TEST_URL =
  process.env.TEST_DATABASE_URL || 'postgresql://soc:soc@127.0.0.1:5435/soc_test';

let ready = false;
let appServer = null;
let baseUrl = '';
let cookie = '';
let fakeServer = null;
let fakeBase = '';
let client = null;
let store = null;
let runSync = null;
let closePool = null;

const s1Requests = [];

/* ────────────────────────────── fixtures S1 ──────────────────────────────── */

const now = Date.now();
const ago = (minutes) => new Date(now - minutes * 60000).toISOString();

const AGENTS = [
  {
    id: 'a1',
    computerName: 'PC-ALPHA',
    osName: 'Windows 11',
    osType: 'windows',
    agentVersion: '24.1.0',
    networkStatus: 'connected',
    infected: false,
    isActive: true,
    siteName: 'Siège',
    accountName: 'compta',
    lastIpToMgmt: '10.0.0.1',
    domain: 'corp.local',
    machineType: 'desktop',
    lastActiveDate: ago(5),
    registeredAt: ago(40000),
    updatedAt: ago(60),
  },
  {
    id: 'a2',
    computerName: 'SRV-BETA',
    osName: 'Windows Server 2022',
    osType: 'server',
    agentVersion: '24.1.2',
    networkStatus: 'connected',
    infected: true,
    isActive: true,
    siteName: 'Datacenter',
    accountName: 'infra',
    lastIpToMgmt: '10.0.0.20',
    domain: 'corp.local',
    machineType: 'server',
    lastActiveDate: ago(1),
    registeredAt: ago(50000),
    updatedAt: ago(60),
  },
  {
    id: 'a3',
    computerName: 'PC-GAMMA',
    osName: 'Ubuntu 22.04',
    osType: 'linux',
    agentVersion: '24.1.0',
    networkStatus: 'disconnected',
    infected: false,
    isActive: true,
    siteName: 'Siège',
    accountName: 'dev',
    lastIpToMgmt: '10.0.0.30',
    domain: '',
    machineType: 'desktop',
    lastActiveDate: ago(900),
    registeredAt: ago(60000),
    updatedAt: ago(60),
  },
];

const THREATS = [
  {
    id: 't1',
    threatInfo: {
      threatId: 't1',
      threatName: 'Ransomware behavior',
      severity: 'high',
      classification: 'Malware',
      confidenceLevel: 'malicious',
      mitigationStatus: 'not_mitigated',
      incidentStatus: 'unresolved',
      analystVerdict: 'true_positive',
      agentComputerName: 'SRV-BETA',
      agentId: 'a2',
      siteName: 'Datacenter',
      createdAt: ago(60),
      updatedAt: ago(60),
      storyline: 'story-1',
      filePath: 'C:\\Users\\Public\\malware.exe',
      fileExtension: '.exe',
      sha256: 'abc123sha256hash',
      processUser: 'SRV-BETA\\admin',
      originatorProcess: 'powershell.exe',
      initiatingUsername: 'admin',
    },
  },
  {
    id: 't2',
    threatInfo: {
      threatId: 't2',
      threatName: 'PUA.Tool',
      severity: 'medium',
      classification: 'PUA',
      mitigationStatus: 'mitigated',
      incidentStatus: 'resolved',
      analystVerdict: 'false_positive',
      agentComputerName: 'PC-ALPHA',
      agentId: 'a1',
      siteName: 'Siège',
      createdAt: ago(180),
      updatedAt: ago(180),
      storyline: 'story-1',
    },
  },
  {
    id: 't3',
    threatInfo: {
      threatId: 't3',
      threatName: 'Suspicious.Script',
      severity: 'low',
      analystVerdict: 'undefined',
      agentComputerName: 'PC-GAMMA',
      agentId: 'a3',
      createdAt: ago(4000),
      updatedAt: ago(4000),
      storyline: 'story-2',
    },
  },
];

const ALERTS = [
  {
    alertInfo: {
      alertId: 'al1',
      eventType: 'ransomware',
      analystVerdict: 'TRUE_POSITIVE',
      incidentStatus: 'unresolved',
      severity: 'High',
      reportedAt: ago(30),
      createdAt: ago(30),
      indicatorCategory: 'Malware',
      indicatorName: 'Ransomware behavior',
    },
    ruleInfo: { name: 'Ransomware behavior', severity: 'High', description: 'Rançongiciel' },
    agentDetectionInfo: { name: 'SRV-BETA', uuid: 'uuid-a2', osName: 'Windows Server 2022', siteId: 'site-1' },
    sourceProcessInfo: {
      name: 'malware.exe',
      filePath: 'C:\\Users\\Public\\malware.exe',
      fileHashSha256: 'abc123sha256hash',
      storyline: 'story-1',
      user: 'SRV-BETA\\admin',
    },
  },
  {
    alertInfo: {
      alertId: 'al2',
      eventType: 'suspicious',
      analystVerdict: 'FALSE_POSITIVE',
      incidentStatus: 'resolved',
      severity: 'Info',
      reportedAt: ago(200),
      createdAt: ago(200),
      indicatorCategory: 'Script',
      indicatorName: 'Suspicious PowerShell',
    },
    ruleInfo: { name: 'Suspicious PowerShell', severity: 'Info', description: 'PowerShell suspect' },
    agentDetectionInfo: { name: 'PC-ALPHA', uuid: 'uuid-a1', osName: 'Windows 11', siteId: 'site-1' },
    sourceProcessInfo: { name: 'powershell.exe', storyline: 'story-2' },
  },
];

const ACTIVITIES = [
  {
    id: 'act1',
    activityType: 27,
    primaryDescription: 'Agent connected to management',
    secondaryDescription: 'PC-ALPHA',
    createdAt: ago(10),
    agentId: 'a1',
    agentName: 'PC-ALPHA',
    siteName: 'Siège',
    userEmail: 'analyste@exemple.local',
    threatId: 't1',
  },
  {
    id: 'act2',
    activityType: 3608,
    primaryDescription: 'User logged in to console',
    createdAt: ago(25),
    agentId: 'a3',
    agentName: 'PC-GAMMA',
    siteName: 'Siège',
    threatId: 't3',
  },
];

const THREAT_NOTES = [
  {
    id: 'n1',
    text: 'Investigé — payload confirmé.',
    creator: 'jean@exemple.local',
    createdAt: ago(5),
    edited: false,
  },
];

/* ───────────────────────── faux SentinelOne local ────────────────────────── */

function startFakeSentinelOne() {
  fakeServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname.replace(/^\/web\/api\/v2\.1/, '');
    s1Requests.push(req.url);

    const send = (data) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data, pagination: { totalItems: data.length, nextCursor: null } }));
    };
    const gte = (param) => {
      const raw = url.searchParams.get(param);
      if (!raw) return null;
      return new Date(raw);
    };

    if (path === '/threats') {
      const since = gte('updatedAt__gte');
      return send(since ? THREATS.filter((t) => new Date(t.threatInfo.updatedAt) >= since) : THREATS);
    }
    if (path === '/cloud-detection/alerts') {
      const since = gte('reportedAt__gte');
      return send(since ? ALERTS.filter((a) => new Date(a.alertInfo.reportedAt) >= since) : ALERTS);
    }
    if (path === '/activities') {
      const since = gte('createdAt__gte');
      return send(since ? ACTIVITIES.filter((a) => new Date(a.createdAt) >= since) : ACTIVITIES);
    }
    if (path === '/agents') {
      const since = gte('updatedAt__gte');
      return send(since ? AGENTS.filter((a) => new Date(a.updatedAt) >= since) : AGENTS);
    }
    const notes = path.match(/^\/threats\/([^/]+)\/notes$/);
    if (notes) return send(THREAT_NOTES);

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ errors: [{ detail: 'not found' }] }));
  });
  fakeServer.listen(0, '127.0.0.1');
}

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
  t.skip('PostgreSQL indisponible — suite de lecture SQL ignorée');
  return true;
}

async function login() {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'dev', password: 'dev-password' }),
  });
  assert.equal(response.status, 200);
  const setCookie = response.headers.getSetCookie()[0];
  cookie = setCookie.split(';')[0];
}

const get = (path) => fetch(`${baseUrl}${path}`, { headers: { Cookie: cookie } });
const getJson = async (path) => (await get(path)).json();

/* ────────────────────────────────── suite ─────────────────────────────────── */

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
  process.env.DB_SYNC_ENABLED = 'false'; // la synchro est déclenchée à la main
  process.env.DB_SYNC_REFRESH_MIN_MS = '0'; // le refresh doit toujours passer
  process.env.DB_SYNC_RECONCILE_MIN = '60';
  process.env.AI_RAG_INDEX_ENABLED = 'false';

  const db = require('../src/db');
  closePool = db.closePool;
  // Base neuve à chaque exécution : les assertions ne dépendent pas d'un état antérieur.
  await db.query('DROP SCHEMA public CASCADE');
  await db.query('CREATE SCHEMA public');
  await db.migrateOnce();

  store = require('../src/db/store');
  runSync = require('../src/services/sync').runSync;

  startFakeSentinelOne();
  await once(fakeServer, 'listening');
  fakeBase = `http://127.0.0.1:${fakeServer.address().port}/web/api/v2.1`;

  const { SentinelOneClient } = require('../src/sentinelone/client');
  client = new SentinelOneClient({
    baseUrl: fakeBase,
    apiToken: 'test-token',
    timeoutMs: 5000,
    cacheTtlMs: 0,
    sampleLimit: 500,
    defaultPageSize: 25,
  });

  // 1re passe : aucun pointeur → mode complet.
  await runSync(client);

  const { createApp } = require('../src/app');
  const app = createApp({ client });
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
  if (fakeServer) {
    fakeServer.close();
    await once(fakeServer, 'close');
  }
  if (closePool) await closePool().catch(() => {});
});

test('migration : pointeurs de synchronisation présents', async (t) => {
  if (maybe(t)) return;
  const { rows } = await require('../src/db').query(
    'SELECT entity FROM sync_cursors ORDER BY entity',
  );
  const entities = rows.map((row) => row.entity);
  assert.ok(entities.includes('threats'));
  assert.ok(entities.includes('alerts'));
  assert.ok(entities.includes('agents'));
  assert.ok(entities.includes('__reconcile__'));
});

test('store : filtres gravité, verdict et période sur les alertes', async (t) => {
  if (maybe(t)) return;

  const high = await store.listCloudAlerts({ severity: 'High', limit: 50 });
  assert.equal(high.data.length, 1);
  assert.equal(high.data[0].alertInfo.alertId, 'al1');

  // La casse de l'API (TRUE_POSITIVE) et celle normalisée doivent toutes les deux matcher.
  const verdict = await store.listCloudAlerts({ analystVerdict: 'TRUE_POSITIVE', limit: 50 });
  assert.equal(verdict.data.length, 1);

  const recent = await store.listCloudAlerts({ reportedAtGte: ago(60), limit: 50 });
  assert.equal(recent.data.length, 1);

  const storyline = await store.listCloudAlerts({ storyline: 'story-2', limit: 50 });
  assert.equal(storyline.data.length, 1);
});

test('store : filtres menaces, activités, endpoints et pagination', async (t) => {
  if (maybe(t)) return;

  const story1 = await store.listThreats({ storylines: 'story-1', limit: 50 });
  assert.equal(story1.data.length, 2);

  const verdict = await store.listThreats({ analystVerdicts: 'true_positive', limit: 50 });
  assert.equal(verdict.data.length, 1);
  assert.equal(verdict.data[0].threatInfo.threatId, 't1');

  // threat_id doit avoir été persisté : c'est ce qui rend ce filtre possible.
  const byThreat = await store.listActivities({ threatIds: 't1', limit: 50 });
  assert.equal(byThreat.data.length, 1);
  assert.equal(byThreat.data[0].id, 'act1');

  const agentSearch = await store.listAgents({ query: 'BETA', limit: 50 });
  assert.equal(agentSearch.data.length, 1);
  assert.equal(agentSearch.data[0].computerName, 'SRV-BETA');

  const page1 = await store.listThreats({ limit: 2 });
  assert.equal(page1.data.length, 2);
  assert.equal(page1.pagination.totalItems, 3);
  assert.ok(page1.pagination.nextCursor);
  const page2 = await store.listThreats({ limit: 2, cursor: page1.pagination.nextCursor });
  assert.equal(page2.data.length, 1);
  assert.equal(page2.pagination.nextCursor, null);

  const detail = await store.getThreat('t1');
  assert.equal(detail.threatInfo.threatName, 'Ransomware behavior');
  assert.equal(await store.getThreat('inconnu'), null);
});

test('API : les vues se lisent dans la base sans repartir vers SentinelOne', async (t) => {
  if (maybe(t)) return;

  s1Requests.length = 0;
  const alerts = await getJson('/api/alerts?limit=50');
  assert.equal(alerts.data.length, 2);
  assert.equal(alerts.data[0].severity, 'high');

  const threats = await getJson('/api/threats?storylines=story-1');
  assert.equal(threats.data.length, 2);

  const activities = await getJson('/api/activities?threatIds=t1');
  assert.equal(activities.data.length, 1);
  assert.equal(activities.data[0].id, 'act1');

  const agents = await getJson('/api/agents?query=alpha');
  assert.equal(agents.data.length, 1);

  const overview = await getJson('/api/overview');
  assert.equal(overview.kpis.agentsTotal, 3);
  assert.equal(overview.kpis.threatsTotal, 3);
  assert.ok(Array.isArray(overview.severityOrder));

  assert.equal(s1Requests.length, 0, 'aucune appel SentinelOne pour une lecture seule');
});

test('API : ?refresh=1 déclenche un delta puis relit la base', async (t) => {
  if (maybe(t)) return;

  s1Requests.length = 0;
  const response = await get('/api/alerts?refresh=1');
  assert.equal(response.status, 200);
  assert.ok(s1Requests.length > 0, 'le refresh doit relancer une synchro delta');
  assert.ok(
    s1Requests.some((url) => url.includes('reportedAt__gte=')),
    'le delta doit filtrer par reportedAt__gte',
  );
});

test('sync delta : seules les nouveautés partent vers SentinelOne', async (t) => {
  if (maybe(t)) return;

  const fresh = {
    alertInfo: {
      alertId: 'al-new',
      eventType: 'phishing',
      analystVerdict: 'UNDEFINED',
      incidentStatus: 'unresolved',
      severity: 'Critical',
      reportedAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      indicatorCategory: 'Phishing',
      indicatorName: 'Nouvelle campagne',
    },
    ruleInfo: { name: 'Phishing campaign', severity: 'Critical', description: 'Hameçonnage' },
    agentDetectionInfo: { name: 'PC-GAMMA', uuid: 'uuid-a3', osName: 'Ubuntu 22.04', siteId: 'site-1' },
    sourceProcessInfo: { name: 'curl', storyline: 'story-3' },
  };
  ALERTS.push(fresh);

  s1Requests.length = 0;
  await runSync(client);

  const alertRequest = s1Requests.find((url) => url.includes('/cloud-detection/alerts'));
  assert.ok(alertRequest, 'les alertes doivent être interrogées');
  assert.ok(alertRequest.includes('reportedAt__gte='), 'filtre reportedAt__gte attendu');
  assert.ok(
    !alertRequest.includes('updatedAt__gte='),
    'les alertes n ont pas de updatedAt côté API',
  );

  const page = await store.listCloudAlerts({ limit: 50 });
  assert.equal(page.pagination.totalItems, 3, 'la nouvelle alerte est en base');
  assert.ok(page.data.some((row) => row.alertInfo.alertId === 'al-new'));
});

test('sync delta : une modification postérieure au pointeur est reprise', async (t) => {
  if (maybe(t)) return;

  // Une menace mise à jour après la fenêtre initiale (verdict changé par un analyste).
  THREATS[0].threatInfo.updatedAt = new Date().toISOString();
  THREATS[0].threatInfo.analystVerdict = 'false_positive';

  s1Requests.length = 0;
  await runSync(client);

  const threatRequest = s1Requests.find((url) => url.includes('/threats?'));
  assert.ok(threatRequest, 'les menaces doivent être interrogées');
  assert.ok(threatRequest.includes('updatedAt__gte='), 'filtre updatedAt__gte attendu');

  const stored = await store.getThreat('t1');
  assert.equal(stored.threatInfo.analystVerdict, 'false_positive');
});

test('sync : la réconciliation reprend une passe complète', async (t) => {
  if (maybe(t)) return;

  // Pointeur de réconciliation vieilli au-delà de DB_SYNC_RECONCILE_MIN (60 min).
  await require('../src/db').query(
    `UPDATE sync_cursors SET watermark = now() - interval '120 minutes' WHERE entity = '__reconcile__'`,
  );

  s1Requests.length = 0;
  await runSync(client);

  const threatRequest = s1Requests.find((url) => url.includes('/threats?'));
  assert.ok(threatRequest, 'les menaces doivent être interrogées');
  assert.ok(!threatRequest.includes('updatedAt__gte='), 'la réconciliation ne filtre pas par date');

  const { rows } = await require('../src/db').query(
    `SELECT watermark > now() - interval '5 minutes' AS fresh FROM sync_cursors WHERE entity = '__reconcile__'`,
  );
  assert.equal(rows[0].fresh, true);
});

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
// Simule une fenêtre de synchro insuffisante : /agents renvoie toujours un
// cursor (comme une console dont le parc dépasse PAGE_SIZE × MAX_PAGES).
let fakeAgentsTruncated = false;
// Journal d'activités très volumineux : le cursor ne s'arrête jamais.
let fakeActivitiesTruncated = false;

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
    serialNumber: 'AA112233',
    modelName: 'Dell Inc. OptiPlex 7090',
    machineSid: 'S-1-5-21-111-222-333-1001',
    uuid: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
    externalId: '',
    networkInterfaces: [{ name: 'Ethernet', physical: 'bc:e9:2f:a1:dd:5e', inet: ['10.0.0.1'] }],
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
    agentRealtimeInfo: { id: 'a2', name: 'SRV-BETA', os: 'Windows Server 2022' },
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
    agentRealtimeInfo: { id: 'a1', name: 'PC-ALPHA', os: 'Windows 11' },
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

// Inventaire des applications par endpoint (GET /agents/applications?ids=…).
// La console renvoie les applications FUSIONNÉES sans attribution : c'est
// applicationsSync qui fait 1 appel par endpoint pour retrouver qui porte quoi.
const APPS = {
  a1: [
    { name: 'Google Chrome', version: '130.0.6612.105', publisher: 'Google LLC', size: 268435456, installedDate: ago(120), signed: 'oui' },
    { name: '7-Zip', version: '24.08', publisher: 'Igor Pavlov', size: 1572864, installedDate: ago(5000), signed: 'non' },
  ],
  a2: [
    { name: 'Backup Agent', version: '3.1.0', publisher: 'Acme Corp', size: 52428800, installedDate: ago(200), signed: 'oui' },
  ],
  a3: [
    { name: 'Google Chrome', version: '129.0.6668.100', publisher: 'Google LLC', size: 262144000, installedDate: ago(300), signed: 'oui' },
  ],
};

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
      const rows = since ? ACTIVITIES.filter((a) => new Date(a.createdAt) >= since) : ACTIVITIES;
      if (fakeActivitiesTruncated) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: rows, pagination: { totalItems: 50000, nextCursor: 'cursor-2' } }));
        return;
      }
      return send(rows);
    }
    if (path === '/agents') {
      const since = gte('updatedAt__gte');
      const rows = since ? AGENTS.filter((a) => new Date(a.updatedAt) >= since) : AGENTS;
      if (fakeAgentsTruncated) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: rows, pagination: { totalItems: rows.length, nextCursor: 'page-2' } }));
        return;
      }
      return send(rows);
    }
    if (path === '/agents/applications') {
      const ids = (url.searchParams.get('ids') || '').split(',').filter(Boolean);
      return send(ids.flatMap((id) => APPS[id] || []));
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

test('store : KPI exacts et plafond interne au-delà de 100 lignes', async (t) => {
  if (maybe(t)) return;
  const db = require('../src/db');

  // Parc fictif de 150 endpoints supplémentaires : au-delà du plafond public
  // de 100 lignes, seuls des agrégats SQL peuvent donner le vrai total.
  await db.query(`
    INSERT INTO agents (id, name, status)
    SELECT 'gen-' || i, 'PC-GEN-' || lpad(i::text, 4, '0'), 'offline'
    FROM generate_series(1, 150) AS i
    ON CONFLICT (id) DO NOTHING
  `);

  try {
    const counts = await store.overviewCounts();
    assert.equal(counts.agents.total, 153);
    assert.equal(counts.agents.online, 2);
    assert.equal(counts.agents.offline, 151);
    assert.equal(counts.agents.infected, 1);
    assert.equal(counts.agents.decommissioned, 0);
    assert.equal(counts.threats.total, 3);
    assert.equal(counts.threats.active, 2);
    assert.equal(counts.threats.highCritical, 1);
    // 2 alertes du fixture + celle injectée par le test « nouveautés ».
    assert.equal(counts.alerts.total, 3);
    assert.equal(counts.alerts.open, 2);
    assert.equal(counts.severity.high, 1);
    assert.equal(counts.severity.medium, 1);
    assert.equal(counts.severity.low, 1);
    assert.equal(
      Object.values(counts.trend).reduce((sum, n) => sum + n, 0),
      3,
      'tendance 7 jours = toutes les menaces du fixture',
    );

    const capped = await store.listAgents({ limit: 500 });
    assert.equal(capped.data.length, 100, 'plafond public inchangé à 100');
    const lifted = await store.listAgents({ limit: 500, maxLimit: 1000 });
    assert.equal(lifted.data.length, 153, 'plafond interne des KPI levé');

    s1Requests.length = 0;
    const overview = await getJson('/api/overview');
    assert.equal(overview.kpis.agentsTotal, 153, 'total exact au tableau de bord');
    assert.equal(overview.kpis.agentsOnline, 2, 'compteur exact, pas un échantillon');
    assert.deepEqual(overview.sampled, { agents: false, threats: false, alerts: false });
    assert.equal(overview.threatTrend.length, 7);
    assert.equal(s1Requests.length, 0, 'les KPI viennent du SQL, pas de S1');
  } finally {
    await db.query(`DELETE FROM agents WHERE id LIKE 'gen-%'`);
  }
});

test('sync : une fenêtre tronquée ne fait pas avancer les pointeurs', async (t) => {
  if (maybe(t)) return;
  const db = require('../src/db');

  const watermarkOf = async (entity) => {
    const { rows } = await db.query('SELECT watermark FROM sync_cursors WHERE entity = $1', [entity]);
    return rows[0] ? new Date(rows[0].watermark).getTime() : null;
  };

  const agentsBefore = await watermarkOf('agents');
  const threatsBefore = await watermarkOf('threats');
  assert.ok(agentsBefore, 'pointeur agents initialisé par les runs précédents');

  fakeAgentsTruncated = true;
  try {
    const result = await runSync(client);

    assert.equal(result.status, 'partial', 'run signalé partiel');
    assert.ok(
      result.errors.some((error) => error.includes('fenêtre endpoints tronquée')),
      `message de fenêtre attendu, reçu : ${JSON.stringify(result.errors)}`,
    );
    assert.equal(
      await watermarkOf('agents'),
      agentsBefore,
      'pointeur agents gelé : sinon les objets hors fenêtre sont perdus à vie',
    );
    assert.ok(
      (await watermarkOf('threats')) > threatsBefore,
      'les entités entièrement lues avancent normalement',
    );
  } finally {
    fakeAgentsTruncated = false;
  }
});

test('sync : le plafond des activités est souple (n’bloque ni run ni pointeur)', async (t) => {
  if (maybe(t)) return;
  const db = require('../src/db');

  const watermarkOf = async (entity) => {
    const { rows } = await db.query('SELECT watermark FROM sync_cursors WHERE entity = $1', [entity]);
    return rows[0] ? new Date(rows[0].watermark).getTime() : null;
  };

  const before = await watermarkOf('activities');
  fakeActivitiesTruncated = true;
  try {
    const result = await runSync(client);

    assert.equal(result.status, 'success', 'le journal borné ne rend pas le run partiel');
    assert.ok(
      !result.errors.some((error) => error.includes('activités')),
      `aucune erreur d'activité attendue : ${JSON.stringify(result.errors)}`,
    );
    assert.ok((await watermarkOf('activities')) > before, 'le pointeur activités avance');
  } finally {
    fakeActivitiesTruncated = false;
  }
});

test('applications : inventaire synchronisé, jointure endpoint et vue filtrée', async (t) => {
  if (maybe(t)) return;
  const { runApplicationsSync } = require('../src/services/applicationsSync');

  const callsBefore = s1Requests.filter((url) => url.includes('/agents/applications')).length;
  const first = await runApplicationsSync(client);
  assert.equal(first.agents, 3, 'un appel par endpoint');
  assert.equal(first.errors, 0);
  assert.equal(first.applications, 4);

  const calls = s1Requests
    .slice(callsBefore)
    .filter((url) => url.includes('/agents/applications'));
  assert.equal(calls.length, 3, 'exactement 1 appel /agents/applications par endpoint');
  assert.ok(
    calls.every((url) => url.includes('ids=')),
    'paramètre ids du Swagger (limit/cursor renvoient 400)',
  );

  const page = await store.listApplications({ limit: 50 });
  assert.equal(page.pagination.totalItems, 4);
  const chrome = page.data.find((row) => row.name === 'Google Chrome' && row.endpoint.id === 'a1');
  assert.ok(chrome, 'application présente');
  assert.equal(chrome.publisher, 'Google LLC');
  assert.equal(chrome.version, '130.0.6612.105');
  assert.equal(chrome.endpoint.id, 'a1');
  assert.equal(chrome.endpoint.name, 'PC-ALPHA');
  assert.equal(chrome.endpoint.site, 'Siège');
  assert.equal(chrome.endpoint.status, 'online');

  // Recherche libre : nom, éditeur, version OU nom d'endpoint.
  assert.equal((await store.listApplications({ query: 'igor' })).pagination.totalItems, 1);
  assert.equal((await store.listApplications({ query: 'SRV-BETA' })).pagination.totalItems, 1);
  assert.equal((await store.listApplications({ query: '6612' })).pagination.totalItems, 1);
  assert.equal((await store.listApplications({ query: 'zzz' })).pagination.totalItems, 0);

  // Filtre endpoint (drill-down depuis la liste).
  const byAgent = await store.listApplications({ agentId: 'a2' });
  assert.equal(byAgent.pagination.totalItems, 1);
  assert.equal(byAgent.data[0].name, 'Backup Agent');
  assert.equal(byAgent.data[0].endpoint.name, 'SRV-BETA');

  // Désinstallation : la passe suivante remplace les lignes de l'endpoint.
  const removed = APPS.a1.pop();
  try {
    const second = await runApplicationsSync(client);
    assert.equal(second.applications, 3);
    const after = await store.listApplications({ agentId: 'a1' });
    assert.equal(after.pagination.totalItems, 1, 'la ligne désinstallée a disparu');
    assert.equal(after.data[0].name, 'Google Chrome');
  } finally {
    APPS.a1.push(removed);
  }

  const status = await store.applicationsStatus();
  assert.ok(status.lastSyncAt, 'pointeur applications renseigné');

  const response = await get('/api/applications?limit=2');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.data.length, 2, 'pagination appliquée');
  assert.equal(body.pagination.totalItems, 3);
  assert.ok(body.status.lastSyncAt);
  assert.ok(body.data[0].endpoint && body.data[0].endpoint.id, 'endpoint joint à la ligne');

  const refreshed = await getJson('/api/applications?refresh=1');
  assert.ok(
    refreshed.sync && (refreshed.sync.queued || refreshed.sync.running),
    'une passe de synchro est déclenchée en arrière-plan',
  );
});

test('endpoints : backfill 005, recherche par endpoint et jointure sur les listes', async (t) => {
  if (maybe(t)) return;
  const fs = require('node:fs');
  const path = require('node:path');
  const db = require('../src/db');

  // Lignes « legacy » : colonnes dénormalisées vides, brut au bon format —
  // exactement l'état laissé par l'ancien code sur la console réelle.
  await db.query(
    `INSERT INTO threats (id, name, agent_id, agent_name, site, raw, created_at)
     VALUES ('t-legacy', 'Legacy.Trojan', NULL, '', '', $1::jsonb, now())`,
    [
      JSON.stringify({
        threatInfo: { threatId: 't-legacy', threatName: 'Legacy.Trojan', severity: 'high' },
        agentRealtimeInfo: { agentId: 'a1', agentComputerName: 'PC-ALPHA', siteName: 'Siège' },
      }),
    ],
  );
  await db.query(
    `INSERT INTO alerts (id, name, agent_id, agent_name, site_id, raw, created_at)
     VALUES ('al-legacy', 'Legacy alert', NULL, '', '', $1::jsonb, now())`,
    [
      JSON.stringify({
        alertInfo: { alertId: 'al-legacy', eventType: 'recon', reportedAt: ago(10) },
        ruleInfo: { name: 'Legacy rule', severity: 'High' },
        agentDetectionInfo: { name: 'SRV-BETA', siteId: 'site-9' },
        agentRealtimeInfo: { id: 'a2' },
      }),
    ],
  );

  try {
    // 005 se rejoue tel quel (IF NOT EXISTS + clauses de garde), comme sur une
    // base déjà remplie au moment d'un déploiement.
    const sql = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'db', 'migrations', '005_endpoint_identity.sql'),
      'utf8',
    );
    await db.query(sql);

    const threatRow = await db.query(
      'SELECT agent_id, agent_name, site FROM threats WHERE id = $1',
      ['t-legacy'],
    );
    assert.deepEqual({ ...threatRow.rows[0] }, {
      agent_id: 'a1',
      agent_name: 'PC-ALPHA',
      site: 'Siège',
    });

    const alertRow = await db.query(
      'SELECT agent_id, agent_name, site_id FROM alerts WHERE id = $1',
      ['al-legacy'],
    );
    assert.deepEqual({ ...alertRow.rows[0] }, {
      agent_id: 'a2',
      agent_name: 'SRV-BETA',
      site_id: 'site-9',
    });

    // Recherche « par endpoint » : opérante une fois les colonnes remplies.
    const found = await store.listThreats({ query: 'PC-ALPHA', limit: 50 });
    assert.ok(
      found.data.some((row) => row.threatInfo && row.threatInfo.threatName === 'Legacy.Trojan'),
      'la menace legacy se trouve par le nom d endpoint',
    );
    const byAgent = await store.listCloudAlerts({ agentIds: ['a2'], limit: 50 });
    assert.ok(
      byAgent.data.some((row) => row.alertInfo && row.alertInfo.alertId === 'al-legacy'),
      'filtre agentIds opérant sur les alertes',
    );

    // Jointure : les listes servent l'état ACTUEL de la machine.
    const threats = await getJson('/api/threats?limit=50');
    const legacyThreat = threats.data.find((row) => row.id === 't-legacy');
    assert.ok(legacyThreat, 'la menace legacy est servie par la vue SQL');
    assert.equal(legacyThreat.agentName, 'PC-ALPHA');
    assert.equal(legacyThreat.site, 'Siège');
    assert.ok(legacyThreat.endpoint, 'endpoint jointé');
    assert.equal(legacyThreat.endpoint.id, 'a1');
    assert.equal(legacyThreat.endpoint.name, 'PC-ALPHA');
    assert.equal(legacyThreat.endpoint.status, 'online');
    assert.equal(legacyThreat.endpoint.partial, false);

    const alerts = await getJson('/api/alerts?limit=50');
    const legacyAlert = alerts.data.find((row) => row.id === 'al-legacy');
    assert.ok(legacyAlert, 'l alerte legacy est servie par la vue SQL');
    assert.equal(legacyAlert.agentId, 'a2');
    assert.equal(legacyAlert.agentName, 'SRV-BETA');
    assert.equal(legacyAlert.endpoint.name, 'SRV-BETA');
    assert.equal(legacyAlert.endpoint.site, 'Datacenter');
  } finally {
    await db.query("DELETE FROM threats WHERE id = 't-legacy'");
    await db.query("DELETE FROM alerts WHERE id = 'al-legacy'");
  }
});

test('identité machine : série, MAC, modèle, clé et recherche multi-critères', async (t) => {
  if (maybe(t)) return;
  const db = require('../src/db');

  const { rows } = await db.query('SELECT * FROM agents WHERE id = $1', ['a1']);
  assert.equal(rows.length, 1);
  const a1 = rows[0];
  assert.equal(a1.serial_number, 'AA112233');
  assert.deepEqual(a1.mac_addresses, ['BC:E9:2F:A1:DD:5E']);
  assert.deepEqual(a1.ip_addresses, ['10.0.0.1']);
  assert.equal(a1.model, 'Dell Inc. OptiPlex 7090');
  assert.equal(a1.machine_uuid, 'f0e1d2c3b4a5968778695a4b3c2d1e0f');
  assert.equal(a1.machine_sid, 'S-1-5-21-111-222-333-1001');
  assert.equal(a1.machine_key, 'sn:aa112233');
  assert.equal(a1.machine_key_source, 'serial');
  assert.ok(a1.first_seen_at, 'première observation renseignée');
  assert.ok(a1.last_seen_at, 'dernière observation renseignée');

  // Pas de série → clé nom|domaine (identité approximative, affichée comme telle).
  const { rows: agents } = await db.query(
    'SELECT machine_key, machine_key_source FROM agents ORDER BY id',
  );
  const beta = agents.find((row) => row.machine_key.startsWith('name:'));
  assert.ok(beta, 'une machine sans série est identifiée par nom|domaine');
  assert.equal(beta.machine_key_source, 'name');

  // Recherche multi-critères : série, MAC, modèle.
  assert.deepEqual(
    (await store.listAgents({ query: 'aa112233' })).data.map((row) => row.id),
    ['a1'],
    'recherche par série',
  );
  assert.deepEqual(
    (await store.listAgents({ query: 'bc:e9:2f:a1:dd:5e' })).data.map((row) => row.id),
    ['a1'],
    'recherche par MAC',
  );
  assert.deepEqual(
    (await store.listAgents({ query: 'OptiPlex' })).data.map((row) => row.id),
    ['a1'],
    'recherche par modèle',
  );

  // La vue servie à l'UI expose les mêmes champs.
  const body = await getJson('/api/agents?query=AA112233');
  assert.equal(body.data.length, 1);
  const served = body.data[0];
  assert.equal(served.name, 'PC-ALPHA');
  assert.equal(served.serialNumber, 'AA112233');
  assert.deepEqual(served.macAddresses, ['BC:E9:2F:A1:DD:5E']);
  assert.equal(served.model, 'Dell Inc. OptiPlex 7090');
  assert.equal(served.machineUuid, 'f0e1d2c3b4a5968778695a4b3c2d1e0f');
});

'use strict';

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-session-secret-0123456789';
process.env.AUTH_DEV_LOGIN = 'true';
process.env.AUTH_DEV_USER = 'dev';
process.env.AUTH_DEV_PASSWORD = 'dev-password';
process.env.AUTH_RATE_LIMIT_MAX = '100';
process.env.LOG_LEVEL = 'error';

const http = require('node:http');
const { once } = require('node:events');
const test = require('node:test');
const assert = require('node:assert/strict');

const { createApp } = require('../src/app');
const { SentinelOneClient, SentinelOneError } = require('../src/sentinelone/client');

const now = new Date('2026-10-23T12:00:00Z');
const iso = (daysAgo = 0) => {
  const date = new Date(now);
  date.setUTCDate(date.getUTCDate() - daysAgo);
  return date.toISOString();
};

const AGENTS = [
  {
    id: 'a1',
    computerName: 'PC-ALPHA',
    osName: 'Windows 11',
    agentVersion: '24.1.2',
    siteName: 'Siège',
    networkStatus: 'connected',
    isActive: true,
    lastActiveDate: iso(0),
    lastIpToMgmt: '10.0.0.10',
  },
  {
    id: 'a2',
    computerName: 'SRV-BETA',
    osName: 'Windows Server 2022',
    agentVersion: '24.1.2',
    siteName: 'Datacenter',
    networkStatus: 'connected',
    isActive: true,
    infected: true,
    lastActiveDate: iso(0),
  },
  {
    id: 'a3',
    computerName: 'PC-GAMMA',
    osName: 'Ubuntu 22.04',
    agentVersion: '23.4.1',
    siteName: 'Agence',
    networkStatus: 'disconnected',
    isActive: true,
    lastActiveDate: iso(3),
  },
];

const THREATS = [
  {
    id: 't1',
    threatName: 'Trojan.Agent',
    severity: 'Critical',
    classification: 'Malware',
    mitigationStatus: 'not_mitigated',
    incidentStatus: 'unresolved',
    agentComputerName: 'SRV-BETA',
    createdAt: iso(0),
    threatInfo: {
      threatId: 't1',
      threatName: 'Trojan.Agent',
      severity: 'Critical',
      classification: 'Malware',
      mitigationStatus: 'not_mitigated',
      incidentStatus: 'unresolved',
      analystVerdict: 'true_positive',
      confidenceLevel: 'malicious',
      agentComputerName: 'SRV-BETA',
      agentId: 'a2',
      siteName: 'Datacenter',
      createdAt: iso(0),
      storyline: 'story-1',
      filePath: 'C:\\Users\\Public\\malware.exe',
      fileExtension: '.exe',
      fileSize: 204800,
      md5: 'd41d8cd98f00b204e9800998ecf8427e',
      sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      sha256: 'abc123sha256hash',
      processUser: 'SRV-BETA\\admin',
      originatorProcess: 'powershell.exe',
      publisherName: 'Inconnu',
      initiatingUsername: 'admin',
    },
    agentDetectionInfo: {
      agentUuid: 'uuid-a2',
      agentOsName: 'Windows Server 2022',
      agentIpV4: '10.0.0.20',
      agentVersion: '24.1.2',
    },
    agentRealtimeInfo: {
      agentUuid: 'uuid-a2',
      agentNetworkStatus: 'connected',
      agentInfected: true,
    },
    mitigationStatus: [{ action: 'kill', status: 'cancelled', mitigationStartedAt: iso(0) }],
  },
  {
    id: 't2',
    agentComputerName: 'PC-ALPHA',
    threatInfo: {
      threatName: 'PUA.Tool',
      confidenceLevel: 'malicious',
      classification: 'PUA',
      mitigationStatus: 'mitigated',
      incidentStatus: 'resolved',
      createdAt: iso(1),
      storyline: 'story-1',
    },
  },
  {
    id: 't3',
    agentComputerName: 'PC-GAMMA',
    threatInfo: {
      threatName: 'Suspicious.Script',
      confidenceLevel: 'suspicious',
      createdAt: iso(20),
    },
  },
];

const THREAT_TIMELINE = [
  {
    id: 'tl1',
    activityType: 1005,
    primaryDescription: 'Malicious behavior detected',
    secondaryDescription: 'powershell.exe launched malware.exe',
    createdAt: iso(0),
    agentId: 'a2',
  },
];

const THREAT_NOTES = [
  {
    id: 'n1',
    text: 'Investigé par Jean — payload confirmé.',
    creator: 'jean@exemple.local',
    createdAt: iso(0),
    edited: false,
  },
];

const ALERTS = [
  {
    id: 'al1',
    alertInfo: { alertId: 'al1', eventType: 'ransomware', analystVerdict: 'true_positive', incidentStatus: 'unresolved', createdAt: iso(0), indicatorCategory: 'Malware', indicatorName: 'Ransomware behavior' },
    ruleInfo: { name: 'Ransomware behavior', severity: 'High', description: 'Comportement de rançongiciel détecté' },
    agentDetectionInfo: { name: 'SRV-BETA', uuid: 'uuid-a2', osName: 'Windows Server 2022', siteId: 'site-1' },
    sourceProcessInfo: { name: 'malware.exe', filePath: 'C:\\Users\\Public\\malware.exe', commandline: 'malware.exe -enc', user: 'SRV-BETA\\admin', fileHashSha256: 'abc123sha256hash', storyline: 'story-1' },
  },
  {
    id: 'al2',
    alertInfo: { alertId: 'al2', eventType: 'suspicious', analystVerdict: 'false_positive', incidentStatus: 'resolved', createdAt: iso(1), indicatorCategory: 'Script', indicatorName: 'Suspicious PowerShell' },
    ruleInfo: { name: 'Suspicious PowerShell', severity: 'Medium', description: 'PowerShell suspect' },
    agentDetectionInfo: { name: 'PC-ALPHA', uuid: 'uuid-a1', osName: 'Windows 11', siteId: 'site-1' },
    sourceProcessInfo: { name: 'powershell.exe', filePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', user: 'PC-ALPHA\\user', storyline: 'story-2' },
  },
];

const ACTIVITIES = [
  {
    id: 'act1',
    activityType: 27,
    primaryDescription: 'Agent connected to management',
    secondaryDescription: 'PC-ALPHA',
    createdAt: iso(0),
    siteName: 'Siège',
    threatId: 't1',
  },
  {
    id: 'act2',
    activityType: 3608,
    primaryDescription: 'User logged in to console',
    createdAt: iso(0),
    siteName: 'Siège',
    userEmail: 'analyst@exemple.local',
    threatId: 't2',
  },
];

let fakeServer;
let fakeBase;
let appServer;
let baseUrl;
let cookie = '';
const requests = [];

// Enum sortBy de /cloud-detection/alerts (formatted_swagger_2_1.json) — le mock
// reproduit le 400 réel de la console pour éviter qu'un tri invalide passe en prod.
const ALERT_SORT_BY = [
  'id', 'machineType', 'osName', 'incidentStatus', 'analystVerdict', 'severity',
  'agentDetectionInfoMachineType', 'agentDetectionInfoName', 'agentDetectionInfoOsFamily',
  'agentDetectionInfoOsName', 'agentDetectionInfoOsRevision', 'agentDetectionInfoSiteId',
  'agentDetectionInfoUuid', 'agentDetectionInfoVersion', 'alertInfoAlertId',
  'alertInfoAnalystVerdict', 'alertInfoCreatedAt', 'alertInfoDvEventId', 'alertInfoEventType',
  'alertInfoHitType', 'alertInfoIncidentStatus', 'alertInfoReportedAt', 'alertInfoSource',
  'containerInfoId', 'containerInfoImage', 'containerInfoLabels', 'containerInfoName',
  'kubernetesInfoCluster', 'kubernetesInfoControllerKind', 'kubernetesInfoControllerLabels',
  'kubernetesInfoControllerName', 'kubernetesInfoNamespace', 'kubernetesInfoNamespaceLabels',
  'kubernetesInfoNode', 'kubernetesInfoPod', 'kubernetesInfoPodLabels', 'ruleInfoDescription',
  'ruleInfoId', 'ruleInfoName', 'ruleInfoScopeLevel', 'ruleInfoSeverity', 'ruleInfoTreatAsThreat',
  'sourceParentProcessInfoCommandline', 'sourceParentProcessInfoFileHashMd5',
  'sourceParentProcessInfoFileHashSha1', 'sourceParentProcessInfoFileHashSha256',
  'sourceParentProcessInfoFilePath', 'sourceParentProcessInfoFileSignerIdentity',
  'sourceParentProcessInfoName', 'sourceParentProcessInfoPid', 'sourceParentProcessInfoPidStarttime',
  'sourceParentProcessInfoStoryline', 'sourceParentProcessInfoIntegrityLevel',
  'sourceParentProcessInfoSubsystem', 'sourceParentProcessInfoUser',
  'sourceProcessInfoCommandline', 'sourceProcessInfoFileHashMd5', 'sourceProcessInfoFileHashSha1',
  'sourceProcessInfoFileHashSha256', 'sourceProcessInfoFilePath',
  'sourceProcessInfoFileSignerIdentity', 'sourceProcessInfoName', 'sourceProcessInfoPid',
  'sourceProcessInfoPidStarttime', 'sourceProcessInfoStoryline', 'sourceProcessInfoIntegrityLevel',
  'sourceProcessInfoSubsystem', 'sourceProcessInfoUser',
];

async function startFakeSentinelOne() {
  fakeServer = http.createServer((req, res) => {
    requests.push({ url: req.url, authorization: req.headers.authorization });
    if (req.headers.authorization !== 'ApiToken test-token') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ errors: [{ detail: 'Invalid API token' }] }));
      return;
    }

    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname.replace(/^\/web\/api\/v2\.1/, '');
    const limit = Number.parseInt(url.searchParams.get('limit') || '25', 10);
    const send = (data, total, nextCursor = null) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data, pagination: { totalItems: total, nextCursor } }));
    };

    if (path === '/agents') {
      if (url.searchParams.get('cursor') === 'cursor-2') {
        send(AGENTS.slice(2), AGENTS.length, null);
      } else if (limit < AGENTS.length) {
        send(AGENTS.slice(0, limit), AGENTS.length, 'cursor-2');
      } else {
        send(AGENTS, AGENTS.length, null);
      }
      return;
    }
    if (path === '/threats') {
      const ids = url.searchParams.get('ids');
      if (ids) {
        const rows = THREATS.filter((threat) => ids.split(',').includes(threat.id));
        send(rows, rows.length, null);
        return;
      }
      const storylines = url.searchParams.get('storylines');
      if (storylines) {
        const rows = THREATS.filter((threat) => {
          const info = threat.threatInfo || {};
          return storylines.split(',').includes(info.storyline);
        });
        send(rows, rows.length, null);
        return;
      }
      const verdicts = url.searchParams.get('analystVerdicts');
      if (verdicts) {
        const rows = THREATS.filter((threat) => {
          const info = threat.threatInfo || {};
          return verdicts.split(',').includes(info.analystVerdict);
        });
        send(rows, rows.length, null);
        return;
      }
      send(THREATS, THREATS.length, null);
      return;
    }
    if (path === '/cloud-detection/alerts') {
      const sortBy = url.searchParams.get('sortBy');
      if (sortBy && !ALERT_SORT_BY.includes(sortBy)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ errors: [{ detail: `sortBy: "${sortBy}" is not a valid choice.` }] }));
        return;
      }
      let rows = ALERTS;
      const storyline = url.searchParams.get('sourceProcessStoryline__contains');
      const sha256 = url.searchParams.get('sourceProcessFileHashSha256__contains');
      if (storyline) rows = rows.filter((alert) => (alert.sourceProcessInfo.storyline || '').includes(storyline));
      if (sha256) rows = rows.filter((alert) => (alert.sourceProcessInfo.fileHashSha256 || '').includes(sha256));
      send(rows, rows.length, null);
      return;
    }
    const threatDetail = path.match(/^\/threats\/([^/]+)\/(timeline|notes)$/);
    if (threatDetail) {
      const rows = threatDetail[2] === 'timeline' ? THREAT_TIMELINE : THREAT_NOTES;
      send(rows, rows.length, null);
      return;
    }
    if (path === '/activities') {
      const threatIds = url.searchParams.get('threatIds');
      if (threatIds) {
        const rows = ACTIVITIES.filter((activity) => threatIds.split(',').includes(activity.threatId));
        send(rows, rows.length, null);
        return;
      }
      send(ACTIVITIES, ACTIVITIES.length, null);
      return;
    }
    const detail = path.match(/^\/agents\/([^/]+)\/(processes|applications)$/);
    if (detail) {
      if (detail[2] === 'processes') {
        send(
          [
            {
              pid: 1001,
              processName: 'chrome.exe',
              executablePath: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
              cpuUsage: 4,
              memoryUsage: 512,
              startTime: iso(0),
            },
          ],
          1,
          null,
        );
      } else {
        const apps = {
          a1: [{ name: 'Google Chrome', size: 104857600, version: '131.0', signed: true, installedAt: iso(30) }],
          a2: [{ name: 'Backup Agent', size: 52428800, version: '4.2', signed: true, installedAt: iso(100) }],
        };
        send(apps[detail[1]] || [], (apps[detail[1]] || []).length, null);
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ errors: [{ detail: 'Not found' }] }));
  });

  fakeServer.listen(0, '127.0.0.1');
  await once(fakeServer, 'listening');
  fakeBase = `http://127.0.0.1:${fakeServer.address().port}/web/api/v2.1`;
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

test.before(async () => {
  await startFakeSentinelOne();
  const client = new SentinelOneClient({
    baseUrl: fakeBase,
    apiToken: 'test-token',
    timeoutMs: 5000,
    cacheTtlMs: 0,
    sampleLimit: 500,
    defaultPageSize: 25,
  });
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
});

test('healthz is public and reports configuration', async () => {
  const response = await fetch(`${baseUrl}/healthz`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.sentineloneConfigured, true);
});

test('login page is public and protected pages redirect', async () => {
  const loginPage = await fetch(`${baseUrl}/login`);
  assert.equal(loginPage.status, 200);
  assert.match(await loginPage.text(), /Console SOC/);

  const dashboard = await fetch(`${baseUrl}/`, { redirect: 'manual' });
  assert.equal(dashboard.status, 302);
  assert.equal(dashboard.headers.get('location'), '/login');

  const agentsPage = await fetch(`${baseUrl}/agents`, { redirect: 'manual' });
  assert.equal(agentsPage.status, 302);
});

test('login page assets resolve', async () => {
  for (const path of ['/assets/css/app.min.css', '/js/login.js', '/css/soc.css']) {
    const response = await fetch(`${baseUrl}${path}`);
    assert.equal(response.status, 200, `asset ${path}`);
  }
});

test('API rejects unauthenticated calls and bad credentials', async () => {
  const anonymous = await fetch(`${baseUrl}/api/overview`);
  assert.equal(anonymous.status, 401);

  const badLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'dev', password: 'wrong-password' }),
  });
  assert.equal(badLogin.status, 401);
});

test('session exposes the authenticated user', async () => {
  const response = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.user.username, 'dev');
  assert.equal(body.user.role, 'admin');
});

test('overview aggregates SentinelOne data and flags partial results', async () => {
  const response = await fetch(`${baseUrl}/api/overview`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();

  assert.equal(body.kpis.agentsTotal, 3);
  assert.equal(body.kpis.agentsOnline, 2);
  assert.equal(body.kpis.agentsInfectedSample, 1);
  assert.equal(body.kpis.threatsTotal, 3);
  assert.equal(body.kpis.threatsHighCriticalSample, 2);
  assert.equal(body.kpis.alertsTotal, 2);
  assert.equal(body.kpis.alertsOpenSample, 1);
  assert.equal(body.severity.critical, 1);
  assert.equal(body.severity.high, 1);
  assert.equal(body.recentThreats[0].name, 'Trojan.Agent');
  assert.equal(body.recentAlerts[0].agentName, 'SRV-BETA');
  assert.deepEqual(body.warnings, []);
  assert.equal(body.threatTrend.length, 7);
});

test('agents endpoint normalizes rows and follows cursors', async () => {
  const first = await fetch(`${baseUrl}/api/agents?limit=2`, { headers: { Cookie: cookie } });
  assert.equal(first.status, 200);
  const firstPage = await first.json();
  assert.equal(firstPage.data.length, 2);
  assert.equal(firstPage.pagination.totalItems, 3);
  assert.equal(firstPage.pagination.nextCursor, 'cursor-2');
  assert.equal(firstPage.data[0].name, 'PC-ALPHA');
  assert.equal(firstPage.data[1].status, 'infected');

  const second = await fetch(`${baseUrl}/api/agents?limit=2&cursor=cursor-2`, {
    headers: { Cookie: cookie },
  });
  const secondPage = await second.json();
  assert.equal(secondPage.data.length, 1);
  assert.equal(secondPage.pagination.nextCursor, null);
  assert.equal(secondPage.data[0].name, 'PC-GAMMA');
});

test('threats, alerts and activities endpoints return normalized data', async () => {
  const threats = await fetch(`${baseUrl}/api/threats`, { headers: { Cookie: cookie } });
  const threatsBody = await threats.json();
  assert.equal(threatsBody.data[1].name, 'PUA.Tool');
  assert.equal(threatsBody.data[1].severity, 'high');

  const alerts = await fetch(`${baseUrl}/api/alerts`, { headers: { Cookie: cookie } });
  const alertsBody = await alerts.json();
  assert.equal(alertsBody.data[0].severity, 'high');
  assert.equal(alertsBody.data[0].status, 'unresolved');
  assert.equal(alertsBody.data[0].name, 'Ransomware behavior');

  const activities = await fetch(`${baseUrl}/api/activities`, { headers: { Cookie: cookie } });
  const activitiesBody = await activities.json();
  assert.equal(activitiesBody.data[0].description, 'Agent connected to management');
});

test('every upstream call carries the ApiToken header', () => {
  assert.ok(requests.length > 0);
  assert.ok(requests.every((request) => request.authorization === 'ApiToken test-token'));
});

test('invalid upstream token is reported without leaking it', async () => {
  const badClient = new SentinelOneClient({
    baseUrl: fakeBase,
    apiToken: 'wrong-token',
    timeoutMs: 5000,
    cacheTtlMs: 0,
  });
  await assert.rejects(
    () => badClient.listAgents({ limit: 1 }),
    (error) => {
      assert.ok(error instanceof SentinelOneError);
      assert.equal(error.status, 502);
      assert.match(error.message, /Token API SentinelOne refusé/);
      assert.doesNotMatch(error.message, /wrong-token/);
      return true;
    },
  );
});

test('agent detail endpoints expose processes and applications', async () => {
  const processes = await fetch(`${baseUrl}/api/agents/a1/processes`, { headers: { Cookie: cookie } });
  assert.equal(processes.status, 200);
  const processesBody = await processes.json();
  assert.equal(processesBody.data[0].pid, 1001);
  assert.equal(processesBody.data[0].name, 'chrome.exe');
  assert.equal(processesBody.data[0].path, 'C:\\Program Files\\Google\\Chrome\\chrome.exe');
  assert.equal(processesBody.data[0].cpuUsage, 4);

  const apps = await fetch(`${baseUrl}/api/agents/a1/applications`, { headers: { Cookie: cookie } });
  assert.equal(apps.status, 200);
  const appsBody = await apps.json();
  assert.equal(appsBody.data[0].name, 'Google Chrome');
  assert.equal(appsBody.data[0].version, '131.0');

  const invalid = await fetch(`${baseUrl}/api/agents/${encodeURIComponent('not!valid')}/processes`, {
    headers: { Cookie: cookie },
  });
  assert.equal(invalid.status, 400);
});

test('settings endpoint exposes migration banner and console info', async () => {
  const anonymous = await fetch(`${baseUrl}/api/settings`);
  assert.equal(anonymous.status, 401);

  const response = await fetch(`${baseUrl}/api/settings`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.migration.enabled, true);
  assert.equal(body.migration.defaultDate, '2026-11-02');
  assert.equal(body.migration.retirementDate, '2027-06-01');
  assert.equal(typeof body.apiBasePath, 'string');
  assert.ok(body.sampleLimit >= 50);
  assert.equal(typeof body.sentineloneConfigured, 'boolean');
  assert.equal(body.apiTokenMasked, '');
});

test('maskApiToken never exposes the full token', () => {
  const { maskApiToken } = require('../src/routes/sentinel.routes');
  assert.equal(maskApiToken(''), '');
  assert.equal(maskApiToken('short'), '••••••••');
  assert.equal(maskApiToken('abcdefghijklmnop'), 'abcd…mnop');
});

test('authenticated pages and static assets are served', async () => {
  const pages = ['/', '/agents', '/threats', '/alerts', '/activities', '/chat', '/settings', '/api-docs'];
  for (const path of pages) {
    const response = await fetch(`${baseUrl}${path}`, { headers: { Cookie: cookie } });
    assert.equal(response.status, 200, `page ${path}`);
    assert.match(response.headers.get('content-type') || '', /text\/html/);
  }

  const assets = [
    '/assets/css/app.min.css',
    '/assets/js/vendor.min.js',
    '/assets/vendor/apexcharts/apexcharts.min.js',
    '/js/soc.js',
    '/js/dashboard.js',
    '/js/chat.js',
    '/js/settings.js',
    '/js/api-catalog.js',
    '/js/api-docs.js',
    '/css/soc.css',
  ];
  for (const path of assets) {
    const response = await fetch(`${baseUrl}${path}`);
    assert.equal(response.status, 200, `asset ${path}`);
  }
});

test('API docs data is protected and serves the generated catalog', async () => {
  const anonymous = await fetch(`${baseUrl}/api-docs/data/index.json`);
  assert.equal(anonymous.status, 401);

  const index = await fetch(`${baseUrl}/api-docs/data/index.json`, { headers: { Cookie: cookie } });
  assert.equal(index.status, 200);
  const body = await index.json();
  assert.ok(body.totalCategories >= 118, 'catégories générées');
  assert.ok(body.totalOperations >= 825, 'endpoints générés');
  const agents = body.categories.find((cat) => cat.key === 'agents');
  assert.ok(agents, 'catégorie agents présente');
  assert.ok(agents.operations.some((op) => op.url === '/web/api/v2.1/agents'));

  const detail = await fetch(`${baseUrl}/api-docs/data/cat/agents.json`, { headers: { Cookie: cookie } });
  assert.equal(detail.status, 200);
  const detailBody = await detail.json();
  const getAgents = detailBody.operations.find((op) => op.id === 'get-agents');
  assert.equal(getAgents.method, 'GET');
  assert.ok(getAgents.permissions.includes('Endpoints.view'));
  assert.ok(getAgents.parameters.query.length > 0);
  assert.ok(getAgents.response.fields.some((field) => field.path.startsWith('pagination')));

  const missing = await fetch(`${baseUrl}/api-docs/data/cat/nope.json`, { headers: { Cookie: cookie } });
  assert.equal(missing.status, 404);
});

test('threat detail exposes the investigation chain', async () => {
  const response = await fetch(`${baseUrl}/api/threats/t1`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.data.name, 'Trojan.Agent');
  assert.equal(body.data.storyline, 'story-1');
  assert.equal(body.data.sha256, 'abc123sha256hash');
  assert.equal(body.data.filePath, 'C:\\Users\\Public\\malware.exe');
  assert.equal(body.data.agentUuid, 'uuid-a2');
  assert.equal(body.data.originatorProcess, 'powershell.exe');
  assert.equal(body.data.analystVerdict, 'true_positive');
  assert.equal(body.data.mitigationActions[0].action, 'kill');

  const missing = await fetch(`${baseUrl}/api/threats/nope`, { headers: { Cookie: cookie } });
  assert.equal(missing.status, 404);

  const invalid = await fetch(`${baseUrl}/api/threats/${encodeURIComponent('not!valid')}`, {
    headers: { Cookie: cookie },
  });
  assert.equal(invalid.status, 400);
});

test('threat timeline and notes are served normalized', async () => {
  const timeline = await fetch(`${baseUrl}/api/threats/t1/timeline`, { headers: { Cookie: cookie } });
  assert.equal(timeline.status, 200);
  const timelineBody = await timeline.json();
  assert.equal(timelineBody.data[0].description, 'Malicious behavior detected');
  assert.equal(timelineBody.data[0].type, 1005);

  const notes = await fetch(`${baseUrl}/api/threats/t1/notes`, { headers: { Cookie: cookie } });
  assert.equal(notes.status, 200);
  const notesBody = await notes.json();
  assert.equal(notesBody.data[0].creator, 'jean@exemple.local');
  assert.match(notesBody.data[0].text, /payload confirmé/);
});

test('investigate endpoint correlates storyline threats and STAR alerts', async () => {
  const response = await fetch(`${baseUrl}/api/threats/t1/investigate`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();

  assert.equal(body.threat.id, 't1');
  assert.equal(body.correlation.key, 'storyline');
  assert.equal(body.correlation.value, 'story-1');
  assert.equal(body.timeline.data.length, 1);
  assert.equal(body.notes.data.length, 1);
  assert.equal(body.activities.data.length, 1);
  assert.equal(body.activities.data[0].description, 'Agent connected to management');
  assert.equal(body.applications.data.length, 1);
  assert.equal(body.applications.data[0].name, 'Backup Agent');
  assert.equal(body.relatedAlerts.data.length, 1);
  assert.equal(body.relatedAlerts.data[0].name, 'Ransomware behavior');
  assert.equal(body.relatedAlerts.data[0].severity, 'high');
  assert.equal(body.relatedAlerts.data[0].processName, 'malware.exe');
  assert.equal(body.relatedAlerts.data[0].sha256, 'abc123sha256hash');
  assert.equal(body.relatedThreats.data.length, 1);
  assert.equal(body.relatedThreats.data[0].id, 't2');
  assert.deepEqual(body.warnings, []);

  const missing = await fetch(`${baseUrl}/api/threats/nope/investigate`, { headers: { Cookie: cookie } });
  assert.equal(missing.status, 404);
});

test('cloud-alerts endpoint filters by storyline', async () => {
  const all = await fetch(`${baseUrl}/api/cloud-alerts`, { headers: { Cookie: cookie } });
  assert.equal(all.status, 200);
  const allBody = await all.json();
  assert.equal(allBody.data[0].agentName, 'SRV-BETA');
  assert.equal(allBody.data[0].analystVerdict, 'true_positive');

  const filtered = await fetch(`${baseUrl}/api/cloud-alerts?storyline=story-1`, { headers: { Cookie: cookie } });
  const filteredBody = await filtered.json();
  assert.equal(filteredBody.data.length, 1);

  const none = await fetch(`${baseUrl}/api/cloud-alerts?storyline=other`, { headers: { Cookie: cookie } });
  const noneBody = await none.json();
  assert.equal(noneBody.data.length, 0);

  // Filtres de périodes et gravité passent au client S1 (vérifié via la requête factice).
  const requestsBefore = requests.length;
  await fetch(`${baseUrl}/api/cloud-alerts?severity=Critical&analystVerdict=TRUE_POSITIVE&reportedAtGte=2026-10-01T00:00:00Z`, {
    headers: { Cookie: cookie },
  });
  const lastRequest = requests[requestsBefore];
  const url = new URL(lastRequest.url, 'http://localhost');
  assert.equal(url.searchParams.get('severity'), 'Critical');
  assert.equal(url.searchParams.get('analystVerdict'), 'TRUE_POSITIVE');
  assert.equal(url.searchParams.get('reportedAt__gte'), '2026-10-01T00:00:00.000Z');
  assert.equal(url.searchParams.get('sortBy'), 'alertInfoReportedAt');
});

test('threats and activities accept correlation filters', async () => {
  const storylines = await fetch(`${baseUrl}/api/threats?storylines=story-1`, { headers: { Cookie: cookie } });
  const storylinesBody = await storylines.json();
  assert.equal(storylinesBody.data.length, 2);

  const verdicts = await fetch(`${baseUrl}/api/threats?analystVerdicts=true_positive`, { headers: { Cookie: cookie } });
  const verdictsBody = await verdicts.json();
  assert.equal(verdictsBody.data.length, 1);
  assert.equal(verdictsBody.data[0].id, 't1');

  const byThreat = await fetch(`${baseUrl}/api/activities?threatIds=t1`, { headers: { Cookie: cookie } });
  const byThreatBody = await byThreat.json();
  assert.equal(byThreatBody.data.length, 1);
  assert.equal(byThreatBody.data[0].description, 'Agent connected to management');
});

test('logout clears the session', async () => {
  const response = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Cookie: cookie },
  });
  assert.equal(response.status, 200);
  const cleared = response.headers.getSetCookie()[0];
  assert.match(cleared, /soc_session=;/);

  const after = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: 'soc_session=' } });
  assert.equal(after.status, 401);
});

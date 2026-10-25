'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  severityKey,
  countBySeverity,
  normalizeAgent,
  normalizeThreat,
  normalizeAlert,
  normalizeCloudAlert,
  normalizeActivity,
} = require('../src/sentinelone/normalize');

test('severityKey normalizes strings, numbers and confidence levels', () => {
  assert.equal(severityKey('Critical'), 'critical');
  assert.equal(severityKey('INFORMATIONAL'), 'info');
  assert.equal(severityKey('moderate'), 'medium');
  assert.equal(severityKey('malicious'), 'high');
  assert.equal(severityKey('suspicious'), 'medium');
  assert.equal(severityKey(4), 'critical');
  assert.equal(severityKey(0), 'info');
  assert.equal(severityKey(undefined), 'unknown');
  assert.equal(severityKey('n/a'), 'unknown');
});

test('countBySeverity returns every bucket', () => {
  const counts = countBySeverity([{ severity: 'high' }, { severity: 'high' }, { severity: 'bogus' }]);
  assert.deepEqual(counts, { critical: 0, high: 2, medium: 0, low: 0, info: 0, unknown: 1 });
});

test('normalizeAgent maps status and identity', () => {
  const online = normalizeAgent({
    id: 'a1',
    computerName: 'PC-ALPHA',
    osName: 'Windows 11',
    agentVersion: '24.1.2',
    siteName: 'Siège',
    networkStatus: 'connected',
    isActive: true,
    lastActiveDate: '2026-10-23T10:00:00Z',
    lastIpToMgmt: '10.0.0.10',
  });
  assert.equal(online.status, 'online');
  assert.equal(online.name, 'PC-ALPHA');
  assert.equal(online.ip, '10.0.0.10');

  const infected = normalizeAgent({ id: 'a2', computerName: 'SRV', infected: true, networkStatus: 'connected' });
  assert.equal(infected.status, 'infected');
  assert.equal(infected.infected, true);

  const off = normalizeAgent({ id: 'a3', computerName: 'PC', networkStatus: 'disconnected', isActive: true });
  assert.equal(off.status, 'offline');

  const gone = normalizeAgent({ id: 'a4', computerName: 'OLD', isDecommissioned: true });
  assert.equal(gone.status, 'decommissioned');
});

test('normalizeThreat supports flat v2.1 and nested threatInfo payloads', () => {
  const flat = normalizeThreat({
    id: 't1',
    threatName: 'Trojan.X',
    severity: 'Critical',
    classification: 'Malware',
    mitigationStatus: 'not_mitigated',
    incidentStatus: 'unresolved',
    agentComputerName: 'PC-ALPHA',
    createdAt: '2026-10-23T09:00:00Z',
  });
  assert.equal(flat.severity, 'critical');
  assert.equal(flat.name, 'Trojan.X');
  assert.equal(flat.agentName, 'PC-ALPHA');

  const nested = normalizeThreat({
    id: 't2',
    agentComputerName: 'SRV-BETA',
    threatInfo: {
      threatName: 'PUA.Y',
      confidenceLevel: 'malicious',
      classification: 'PUA',
      mitigationStatus: 'mitigated',
      incidentStatus: 'resolved',
      createdAt: '2026-10-22T09:00:00Z',
    },
  });
  assert.equal(nested.name, 'PUA.Y');
  assert.equal(nested.severity, 'high');
  assert.equal(nested.mitigationStatus, 'mitigated');
});

test('normalizeAlert and normalizeActivity fall back safely', () => {
  const alert = normalizeAlert({
    id: 'al1',
    alertInfo: { name: 'Ransomware behavior', severity: 'High', classification: 'Ransomware' },
    status: 'OPEN',
    detectedAt: '2026-10-23T08:00:00Z',
    agentName: 'SRV-BETA',
  });
  assert.equal(alert.name, 'Ransomware behavior');
  assert.equal(alert.severity, 'high');
  assert.equal(alert.status, 'OPEN');

  const empty = normalizeAlert({});
  assert.equal(empty.name, 'Alerte');
  assert.equal(empty.severity, 'unknown');

  const activity = normalizeActivity({
    id: 'act1',
    activityType: 27,
    primaryDescription: 'Agent connected',
    secondaryDescription: 'PC-ALPHA',
    createdAt: '2026-10-23T07:00:00Z',
  });
  assert.equal(activity.type, 27);
  assert.equal(activity.description, 'Agent connected');
  assert.equal(activity.details, 'PC-ALPHA');
});

test('normalizeThreat lit la forme réelle (agentRealtimeInfo / agentDetectionInfo)', () => {
  // Console réelle : ni threatInfo.agentComputerName, ni threat.agentName.
  const threat = normalizeThreat({
    id: 't-real',
    threatInfo: { threatName: 'Trojan.X', severity: 'high', createdAt: '2026-10-23T09:00:00Z' },
    agentRealtimeInfo: {
      agentComputerName: 'ENTDPH-VNCHO',
      agentId: '1585483511912501139',
      siteName: 'Siège',
      agentUuid: 'uuid-x',
      agentOsName: 'Windows 11',
      agentNetworkStatus: 'connected',
    },
    agentDetectionInfo: { agentIpV4: '10.105.0.149', agentUuid: 'uuid-x' },
  });

  assert.equal(threat.agentName, 'ENTDPH-VNCHO');
  assert.equal(threat.agentId, '1585483511912501139');
  assert.equal(threat.site, 'Siège');
  assert.equal(threat.agentUuid, 'uuid-x');

  // La forme historique reste prioritaire quand elle est présente.
  const legacy = normalizeThreat({
    id: 't-legacy',
    agentComputerName: 'PC-ALPHA',
    agentRealtimeInfo: { agentComputerName: 'AUTRE', agentId: 'a9' },
  });
  assert.equal(legacy.agentName, 'PC-ALPHA');
  assert.equal(legacy.agentId, 'a9');
});

test('normalizeCloudAlert expose l id agent et la cible de jointure', () => {
  const alert = normalizeCloudAlert({
    alertInfo: { alertId: 'al-real', eventType: 'recon', incidentStatus: 'unresolved' },
    ruleInfo: { name: 'Scheduled Tasks Creation' },
    agentDetectionInfo: {
      name: 'DAF-CBOHOUSSOU',
      uuid: '4b4687bb93e64c368dbd517ae0aecefd',
      osName: 'Windows 10 Professionnel',
      siteId: '1386833605938637196',
    },
    agentRealtimeInfo: { id: '1875251630166151998', name: 'DAF-CBOHOUSSOU', os: 'Windows 10 Professionnel' },
    sourceProcessInfo: { name: 'schtasks.exe', storyline: 'story-9' },
  });

  assert.equal(alert.agentName, 'DAF-CBOHOUSSOU');
  assert.equal(alert.agentId, '1875251630166151998');
  assert.equal(alert.agentUuid, '4b4687bb93e64c368dbd517ae0aecefd');
  assert.equal(alert.agentOs, 'Windows 10 Professionnel');
  assert.equal(alert.siteId, '1386833605938637196');

  const noRealtime = normalizeCloudAlert({
    alertInfo: { alertId: 'al-1', eventType: 'recon' },
    ruleInfo: { name: 'Rule' },
    agentDetectionInfo: { name: 'PC-1', uuid: 'u1', osName: 'Windows 11' },
  });
  assert.equal(noRealtime.agentName, 'PC-1');
  assert.equal(noRealtime.agentId, '');
});

test("normalizeAgent extrait l'identité machine (série, MAC, IP, modèle, uuid)", () => {
  const agent = normalizeAgent({
    id: 'a9',
    computerName: 'ENTSEC-KDIABI',
    osName: 'Windows 11',
    networkStatus: 'connected',
    isActive: true,
    lastIpToMgmt: '10.20.0.14',
    serialNumber: '4G79JF3',
    modelName: 'Dell Inc. OptiPlex 7090',
    machineSid: 'S-1-5-21-1-2-3-1001',
    uuid: 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
    externalId: '',
    networkInterfaces: [
      { name: 'Ethernet', physical: 'bc:e9:2f:a1:dd:5e', inet: ['10.20.0.14', 'fe80::1'] },
      { name: 'Wi-Fi', physical: 'BC-E9-2F-A1-DD-5F', inet: ['10.20.0.15'] },
      { name: 'vEthernet', physical: '00:00:00:00:00:00', inet: ['10.20.0.16'] },
    ],
  });

  assert.equal(agent.serialNumber, '4G79JF3');
  assert.equal(agent.model, 'Dell Inc. OptiPlex 7090');
  assert.equal(agent.machineUuid, 'f0e1d2c3b4a5968778695a4b3c2d1e0f');
  assert.equal(agent.machineSid, 'S-1-5-21-1-2-3-1001');
  assert.equal(agent.ip, '10.20.0.14');
  assert.deepEqual(agent.macAddresses, ['BC:E9:2F:A1:DD:5E', 'BC:E9:2F:A1:DD:5F']);
  assert.deepEqual(agent.ipAddresses, ['10.20.0.14', '10.20.0.15', '10.20.0.16']);

  const junk = normalizeAgent({
    id: 'a10',
    computerName: 'PC-JUNK',
    serialNumber: 'Default string',
    networkInterfaces: [{ name: 'eth0', physical: 'zz:zz', inet: ['not-an-ip'] }],
  });
  assert.equal(junk.serialNumber, '', 'série constructeur bidon écartée');
  assert.deepEqual(junk.macAddresses, []);
  assert.deepEqual(junk.ipAddresses, []);

  const withoutInterfaces = normalizeAgent({ id: 'a11', computerName: 'PC-NU', serialNumber: '' });
  assert.equal(withoutInterfaces.serialNumber, '');
  assert.deepEqual(withoutInterfaces.macAddresses, []);
  assert.deepEqual(withoutInterfaces.ipAddresses, []);
});

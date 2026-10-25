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

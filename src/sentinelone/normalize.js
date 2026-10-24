'use strict';

// Normalisation des objets SentinelOne : les réponses varient selon la version du management
// (champs imbriqués sous threatInfo / alertInfo en v2.0, plats en v2.1). Le front ne reçoit
// que des objets stables, jamais la structure brute de l'API.

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

const SEVERITY_ALIASES = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  moderate: 'medium',
  low: 'low',
  informational: 'info',
  information: 'info',
  info: 'info',
  benign: 'info',
  suspicious: 'medium',
  malicious: 'high',
  unknown: 'unknown',
  'n/a': 'unknown',
};

function toInt(value, fallback = 0) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function severityKey(value) {
  if (value === null || value === undefined || value === '') return 'unknown';
  if (typeof value === 'number') {
    // Certaines APIs (ex. Deep Visibility) encodent la gravité de 0 à 4.
    return ['info', 'low', 'medium', 'high', 'critical'][value] || 'unknown';
  }
  return SEVERITY_ALIASES[String(value).trim().toLowerCase()] || 'unknown';
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
  }
  return '';
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function countBySeverity(items) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((key) => [key, 0]));
  for (const item of items) {
    const key = SEVERITY_ORDER.includes(item.severity) ? item.severity : 'unknown';
    counts[key] += 1;
  }
  return counts;
}

function normalizeAgent(raw) {
  const agent = asObject(raw);
  const networkStatus = String(agent.networkStatus || '').toLowerCase();
  const decommissioned = agent.isDecommissioned === true;
  const active = agent.isActive !== false && !decommissioned;
  const online = active && (networkStatus === 'connected' || networkStatus === 'online');
  const infected = agent.infected === true;

  let status = 'offline';
  if (decommissioned) status = 'decommissioned';
  else if (infected) status = 'infected';
  else if (online) status = 'online';

  return {
    id: firstString(agent.id),
    name: firstString(agent.computerName, agent.name) || 'Endpoint inconnu',
    os: firstString(agent.osName, agent.osType) || '—',
    osType: firstString(agent.osType),
    version: firstString(agent.agentVersion) || '—',
    status,
    online,
    infected,
    site: firstString(agent.siteName) || '—',
    account: firstString(agent.accountName) || '—',
    ip: firstString(agent.lastIpToMgmt, agent.networkInterfaces && agent.networkInterfaces[0] && agent.networkInterfaces[0].inet) || '—',
    lastActiveAt: firstString(agent.lastActiveDate, agent.lastSeen) || null,
    registeredAt: firstString(agent.registeredAt) || null,
    domain: firstString(agent.domain) || '—',
    machineType: firstString(agent.machineType) || '—',
  };
}

function threatSource(raw) {
  const threat = asObject(raw);
  return { threat, info: asObject(threat.threatInfo) };
}

function normalizeThreat(raw) {
  const { threat, info } = threatSource(raw);
  const id = firstString(threat.id, info.id, info.threatId);
  const name = firstString(threat.threatName, info.threatName, threat.name) || 'Menace inconnue';
  const severity = severityKey(
    threat.severity !== undefined ? threat.severity : info.severity !== undefined ? info.severity : info.confidenceLevel,
  );

  return {
    id,
    name,
    severity,
    classification: firstString(threat.classification, info.classification) || '—',
    confidence: firstString(info.confidenceLevel, threat.confidenceLevel) || '—',
    mitigationStatus: firstString(threat.mitigationStatus, info.mitigationStatus) || '—',
    incidentStatus: firstString(threat.incidentStatus, info.incidentStatus) || '—',
    analystVerdict: firstString(threat.analystVerdict, info.analystVerdict) || '—',
    agentName: firstString(threat.agentComputerName, threat.agentName, info.agentComputerName) || '—',
    agentId: firstString(threat.agentId, info.agentId),
    site: firstString(threat.siteName, info.siteName) || '—',
    createdAt: firstString(threat.createdAt, info.createdAt) || null,
    updatedAt: firstString(threat.updatedAt, info.updatedAt) || null,
  };
}

// Détail d'enquête : la menace enrichie avec le chaînage (fichier, process, agent, storyline).
function normalizeThreatDetail(raw) {
  const base = normalizeThreat(raw);
  const { threat, info } = threatSource(raw);
  const detection = asObject(threat.agentDetectionInfo);
  const realtime = asObject(threat.agentRealtimeInfo);
  const mitigationReports = Array.isArray(threat.mitigationStatus) ? threat.mitigationStatus : [];

  return {
    ...base,
    storyline: firstString(info.storyline, threat.storyline),
    filePath: firstString(info.filePath, threat.filePath) || '—',
    fileExtension: firstString(info.fileExtension, threat.fileExtension) || '—',
    fileSize: Number.isFinite(Number(info.fileSize)) ? Number(info.fileSize) : null,
    md5: firstString(info.md5, threat.md5),
    sha1: firstString(info.sha1, threat.sha1),
    sha256: firstString(info.sha256, threat.sha256),
    processUser: firstString(info.processUser, threat.processUser) || '—',
    originatorProcess: firstString(info.originatorProcess, threat.originatorProcess) || '—',
    maliciousProcessArguments: firstString(info.maliciousProcessArguments) || '',
    publisherName: firstString(info.publisherName, threat.publisherName) || '—',
    initiatingUsername: firstString(info.initiatingUsername, threat.initiatingUsername) || '—',
    externalTicketId: firstString(info.externalTicketId) || '',
    agentUuid: firstString(realtime.agentUuid, detection.agentUuid, base.agentId),
    agentOs: firstString(detection.agentOsName, realtime.agentOsName) || '—',
    agentIp: firstString(detection.agentIpV4, detection.externalIp) || '—',
    agentVersion: firstString(detection.agentVersion, realtime.agentVersion) || '—',
    agentNetworkStatus: firstString(realtime.agentNetworkStatus) || '',
    agentInfected: realtime.agentInfected === true,
    mitigationActions: mitigationReports.map((report) => ({
      action: firstString(report.action) || '—',
      status: firstString(report.status) || '—',
      startedAt: firstString(report.mitigationStartedAt) || null,
      endedAt: firstString(report.mitigationEndedAt) || null,
    })),
  };
}

function normalizeAlert(raw) {
  const alert = asObject(raw);
  const info = asObject(alert.alertInfo);
  const rule = asObject(alert.ruleInfo);
  const detection = asObject(alert.agentDetectionInfo);
  const endpoint = asObject(alert.endpoint);
  const severity = severityKey(
    rule.severity !== undefined
      ? rule.severity
      : alert.severity !== undefined
        ? alert.severity
        : info.severity !== undefined
          ? info.severity
          : alert.severityLevel,
  );

  return {
    id: firstString(info.alertId, alert.id),
    name: firstString(rule.name, info.name, alert.name, info.ruleName) || 'Alerte',
    severity,
    status: firstString(alert.status, info.status, info.incidentStatus) || '—',
    detectedAt: firstString(alert.detectedAt, info.detectedAt, info.createdAt, alert.createdAt) || null,
    agentName: firstString(detection.name, alert.agentName, endpoint.name, alert.sourceName) || '—',
    agentId: firstString(detection.uuid, alert.agentId, endpoint.id),
    site: firstString(alert.siteName, detection.siteId) || '—',
    analystVerdict: firstString(alert.analystVerdict, info.analystVerdict) || '—',
    classification: firstString(info.classification, alert.classification, info.indicatorCategory) || '—',
    description: firstString(info.description, alert.description, rule.description) || '',
  };
}

function normalizeActivity(raw) {
  const activity = asObject(raw);
  return {
    id: firstString(activity.id, activity.activityUuid),
    type: toInt(activity.activityType, 0),
    description: firstString(activity.primaryDescription, activity.description) || 'Activité',
    details: firstString(activity.secondaryDescription) || '',
    agentName: firstString(activity.agentName, activity.data && activity.data.agentComputerName) || '',
    agentId: firstString(activity.agentId),
    site: firstString(activity.siteName) || '—',
    user: firstString(activity.userEmail, activity.userFullName) || '',
    createdAt: firstString(activity.createdAt) || null,
  };
}

// Alerte STAR (cloud-detection) : règle, process source, agent de détection.
function normalizeCloudAlert(raw) {
  const alert = asObject(raw);
  const info = asObject(alert.alertInfo);
  const rule = asObject(alert.ruleInfo);
  const agent = asObject(alert.agentDetectionInfo);
  const process = asObject(alert.sourceProcessInfo);
  const severity = severityKey(rule.severity !== undefined ? rule.severity : info.severity);

  return {
    id: firstString(info.alertId, alert.id),
    name: firstString(rule.name, info.eventType) || 'Alerte',
    eventType: firstString(info.eventType) || '—',
    severity,
    indicatorCategory: firstString(info.indicatorCategory) || '—',
    indicatorName: firstString(info.indicatorName) || '',
    indicatorDescription: firstString(info.indicatorDescription) || '',
    analystVerdict: firstString(info.analystVerdict) || '—',
    status: firstString(info.incidentStatus) || '—',
    incidentStatus: firstString(info.incidentStatus) || '—',
    createdAt: firstString(info.createdAt, info.reportedAt) || null,
    agentName: firstString(agent.name) || '—',
    agentUuid: firstString(agent.uuid),
    agentOs: firstString(agent.osName) || '—',
    siteId: firstString(agent.siteId) || '—',
    ruleDescription: firstString(rule.description) || '',
    processName: firstString(process.name) || '—',
    processPath: firstString(process.filePath) || '—',
    processCommandLine: firstString(process.commandline) || '',
    processUser: firstString(process.user, process.realUser) || '—',
    sha256: firstString(process.fileHashSha256),
    storyline: firstString(process.storyline),
    dstIp: firstString(info.dstIp) || '',
    dstPort: info.dstPort === undefined || info.dstPort === null ? '' : String(info.dstPort),
    dnsRequest: firstString(info.dnsRequest) || '',
    registryKeyPath: firstString(info.registryKeyPath) || '',
    loginUserName: firstString(info.loginsUserName) || '',
  };
}

// Note d'équipe laissée sur une menace dans la console SentinelOne.
function normalizeThreatNote(raw) {
  const note = asObject(raw);
  return {
    id: firstString(note.id),
    text: firstString(note.text) || '',
    creator: firstString(note.creator) || '—',
    createdAt: firstString(note.createdAt) || null,
    updatedAt: firstString(note.updatedAt) || null,
    edited: note.edited === true,
  };
}

function normalizeProcess(raw) {
  const process = asObject(raw);
  return {
    pid: toInt(process.pid, 0),
    name: firstString(process.processName, process.name) || '—',
    path: firstString(process.executablePath, process.path) || '—',
    cpuUsage: toInt(process.cpuUsage, 0),
    memoryUsage: toInt(process.memoryUsage, 0),
    startTime: firstString(process.startTime) || null,
  };
}

function normalizeApplication(raw) {
  const app = asObject(raw);
  return {
    name: firstString(app.name, app.applicationName) || '—',
    size: Number.isFinite(Number(app.size)) ? Number(app.size) : null,
    version: firstString(app.version) || '—',
    signed: firstString(app.signed) || (app.signed === true ? 'oui' : app.signed === false ? 'non' : '—'),
    path: firstString(app.path, app.installedPath) || '—',
    installedAt: firstString(app.installedAt, app.installDate) || null,
  };
}

module.exports = {
  SEVERITY_ORDER,
  severityKey,
  countBySeverity,
  normalizeAgent,
  normalizeThreat,
  normalizeThreatDetail,
  normalizeAlert,
  normalizeCloudAlert,
  normalizeThreatNote,
  normalizeActivity,
  normalizeProcess,
  normalizeApplication,
};

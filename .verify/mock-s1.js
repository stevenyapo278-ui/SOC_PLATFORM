'use strict';

const http = require('node:http');

const now = Date.now();
const iso = (hoursAgo) => new Date(now - hoursAgo * 3600 * 1000).toISOString();

const data = {
  '/agents': [
    { id: 'a1', computerName: 'PC-ALPHA', osName: 'Windows 11', agentVersion: '24.1.2', siteName: 'Siège', networkStatus: 'connected', isActive: true, infected: false, lastActiveDate: iso(0), lastIpToMgmt: '10.0.0.10', domain: 'exemple.local', machineType: 'desktop' },
    { id: 'a2', computerName: 'SRV-BETA', osName: 'Windows Server 2022', agentVersion: '24.1.2', siteName: 'Datacenter', networkStatus: 'connected', isActive: true, infected: true, lastActiveDate: iso(0), lastIpToMgmt: '10.0.0.20', domain: 'exemple.local', machineType: 'server' },
    { id: 'a3', computerName: 'PC-GAMMA', osName: 'Ubuntu 22.04', agentVersion: '23.4.1', siteName: 'Agence', networkStatus: 'disconnected', isActive: true, infected: false, lastActiveDate: iso(72), lastIpToMgmt: '10.0.0.30', domain: 'exemple.local', machineType: 'desktop' },
  ],
  '/threats': [
    { id: 't1', threatName: 'Trojan.Agent', severity: 'Critical', classification: 'Malware', mitigationStatus: 'not_mitigated', incidentStatus: 'unresolved', agentComputerName: 'SRV-BETA', siteName: 'Datacenter', createdAt: iso(1), threatInfo: { threatId: 't1', threatName: 'Trojan.Agent', severity: 'Critical', classification: 'Malware', mitigationStatus: 'not_mitigated', incidentStatus: 'unresolved', analystVerdict: 'true_positive', confidenceLevel: 'malicious', agentComputerName: 'SRV-BETA', agentId: 'a2', siteName: 'Datacenter', createdAt: iso(1), storyline: 'story-1', filePath: 'C:\\Users\\Public\\malware.exe', fileExtension: '.exe', fileSize: 204800, md5: 'd41d8cd98f00b204e9800998ecf8427e', sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', sha256: 'abc123sha256hash', processUser: 'SRV-BETA\\admin', originatorProcess: 'powershell.exe', publisherName: 'Inconnu', initiatingUsername: 'admin' }, agentDetectionInfo: { agentUuid: 'uuid-a2', agentOsName: 'Windows Server 2022', agentIpV4: '10.0.0.20', agentVersion: '24.1.2' }, agentRealtimeInfo: { agentUuid: 'uuid-a2', agentNetworkStatus: 'connected', agentInfected: true }, mitigationStatus: [{ action: 'kill', status: 'cancelled', mitigationStartedAt: iso(1) }] },
    { id: 't2', agentComputerName: 'PC-ALPHA', siteName: 'Siège', threatInfo: { threatName: 'PUA.Tool', confidenceLevel: 'malicious', classification: 'PUA', mitigationStatus: 'mitigated', incidentStatus: 'resolved', createdAt: iso(20), storyline: 'story-1' } },
    { id: 't3', agentComputerName: 'PC-GAMMA', siteName: 'Agence', threatInfo: { threatName: 'Suspicious.Script', confidenceLevel: 'suspicious', createdAt: iso(50) } },
  ],
  '/cloud-detection/alerts': [
    { id: 'al1', alertInfo: { alertId: 'al1', eventType: 'ransomware', analystVerdict: 'true_positive', incidentStatus: 'unresolved', createdAt: iso(1), indicatorCategory: 'Malware', indicatorName: 'Ransomware behavior' }, ruleInfo: { name: 'Ransomware behavior', severity: 'High', description: 'Comportement de rançongiciel détecté' }, agentDetectionInfo: { name: 'SRV-BETA', uuid: 'uuid-a2', osName: 'Windows Server 2022', siteId: 'site-1' }, sourceProcessInfo: { name: 'malware.exe', filePath: 'C:\\Users\\Public\\malware.exe', commandline: 'malware.exe -enc', user: 'SRV-BETA\\admin', fileHashSha256: 'abc123sha256hash', storyline: 'story-1' } },
    { id: 'al2', alertInfo: { alertId: 'al2', eventType: 'suspicious', analystVerdict: 'false_positive', incidentStatus: 'resolved', createdAt: iso(30), indicatorCategory: 'Script', indicatorName: 'Suspicious PowerShell' }, ruleInfo: { name: 'Suspicious PowerShell', severity: 'Medium', description: 'PowerShell suspect' }, agentDetectionInfo: { name: 'PC-ALPHA', uuid: 'uuid-a1', osName: 'Windows 11', siteId: 'site-1' }, sourceProcessInfo: { name: 'powershell.exe', filePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', user: 'PC-ALPHA\\user', storyline: 'story-2' } },
  ],
  '/activities': [
    { id: 'act1', activityType: 27, primaryDescription: 'Agent connected to management', secondaryDescription: 'PC-ALPHA', createdAt: iso(1), siteName: 'Siège', threatId: 't1' },
    { id: 'act2', activityType: 3608, primaryDescription: 'User logged in to console', createdAt: iso(2), siteName: 'Siège', userEmail: 'analyst@exemple.local', threatId: 't2' },
  ],
  timeline: {
    t1: [
      { id: 'tl1', activityType: 1005, primaryDescription: 'Malicious behavior detected', secondaryDescription: 'powershell.exe launched malware.exe', createdAt: iso(1), agentId: 'a2' },
    ],
  },
  notes: {
    t1: [
      { id: 'n1', text: 'Investigé par Jean — payload confirmé.', creator: 'jean@exemple.local', createdAt: iso(1), edited: false },
    ],
  },
  processes: {
    a1: [
      { pid: 1001, processName: 'chrome.exe', executablePath: 'C:\\Program Files\\Google\\Chrome\\chrome.exe', cpuUsage: 4, memoryUsage: 512, startTime: iso(2) },
      { pid: 1002, processName: 'explorer.exe', executablePath: 'C:\\Windows\\explorer.exe', cpuUsage: 1, memoryUsage: 120, startTime: iso(10) },
    ],
  },
  applications: {
    a1: [
      { name: 'Google Chrome', size: 104857600, version: '131.0', signed: true, installedAt: iso(720) },
      { name: '7-Zip', size: 2048000, version: '24.09', signed: true, installedAt: iso(2400) },
    ],
    a2: [
      { name: 'Backup Agent', size: 52428800, version: '4.2', signed: true, installedAt: iso(100) },
      { name: 'SQL Server', size: 1073741824, version: '15.0', signed: true, installedAt: iso(4000) },
    ],
  },
};

http
  .createServer((req, res) => {
    if (req.headers.authorization !== 'ApiToken test-token') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ errors: [{ detail: 'Invalid API token' }] }));
      return;
    }
    const path = new URL(req.url, 'http://localhost').pathname.replace(/^\/web\/api\/v2\.1/, '');

    const agentDetail = path.match(/^\/agents\/([^/]+)\/(processes|applications)$/);
    if (agentDetail) {
      const rows = (data[agentDetail[2]] && data[agentDetail[2]][agentDetail[1]]) || [];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: rows, pagination: { totalItems: rows.length, nextCursor: null } }));
      return;
    }

    const threatDetail = path.match(/^\/threats\/([^/]+)\/(timeline|notes)$/);
    if (threatDetail) {
      const rows = (data[threatDetail[2]] && data[threatDetail[2]][threatDetail[1]]) || [];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: rows, pagination: { totalItems: rows.length, nextCursor: null } }));
      return;
    }

    const urlObj = new URL(req.url, 'http://localhost');
    let rows = data[path];

    if (path === '/threats') {
      rows = data['/threats'];
      const ids = urlObj.searchParams.get('ids');
      if (ids) rows = rows.filter((threat) => ids.split(',').includes(threat.id));
      const storylines = urlObj.searchParams.get('storylines');
      if (storylines) {
        rows = rows.filter((threat) => storylines.split(',').includes((threat.threatInfo || {}).storyline));
      }
      const verdicts = urlObj.searchParams.get('analystVerdicts');
      if (verdicts) {
        rows = rows.filter((threat) => verdicts.split(',').includes((threat.threatInfo || {}).analystVerdict));
      }
      const mitigation = urlObj.searchParams.get('mitigationStatuses');
      if (mitigation) {
        rows = rows.filter((threat) => {
          const info = threat.threatInfo || {};
          const status = info.mitigationStatus || (typeof threat.mitigationStatus === 'string' ? threat.mitigationStatus : '');
          return mitigation.split(',').includes(status);
        });
      }
    }
    if (path === '/cloud-detection/alerts') {
      rows = data['/cloud-detection/alerts'];
      const storyline = urlObj.searchParams.get('sourceProcessStoryline__contains');
      if (storyline) rows = rows.filter((alert) => alert.sourceProcessInfo.storyline.includes(storyline));
      const sha256 = urlObj.searchParams.get('sourceProcessFileHashSha256__contains');
      if (sha256) rows = rows.filter((alert) => alert.sourceProcessInfo.fileHashSha256.includes(sha256));
      const severity = urlObj.searchParams.get('severity');
      if (severity) rows = rows.filter((alert) => alert.ruleInfo.severity === severity);
    }
    if (path === '/activities') {
      rows = data['/activities'];
      const threatIds = urlObj.searchParams.get('threatIds');
      if (threatIds) rows = rows.filter((activity) => threatIds.split(',').includes(activity.threatId));
    }

    res.writeHead(rows ? 200 : 404, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify(
        rows
          ? { data: rows, pagination: { totalItems: rows.length, nextCursor: null } }
          : { errors: [{ detail: 'Not found' }] },
      ),
    );
  })
  .listen(3211, '127.0.0.1', () => console.log('mock sentinelone on 3211'));

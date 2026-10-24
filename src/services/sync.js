'use strict';

// Synchro périodique SentinelOne → PostgreSQL (historique SOC pour le futur RAG).
// Upsert idempotent : une relance ne duplique jamais. Bypass du cache client (force).

const config = require('../config');
const log = require('../logger');
const { query } = require('../db');
const {
  normalizeThreatDetail,
  normalizeCloudAlert,
  normalizeThreatNote,
  normalizeActivity,
} = require('../sentinelone/normalize');

// Nombre de menaces récentes pour lesquelles on récupère les notes à chaque run.
const NOTES_PER_RUN = 25;

function toTs(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

async function fetchAll(fetchPage, pageSize, maxPages) {
  const items = [];
  let cursor = null;
  for (let page = 0; page < maxPages; page += 1) {
    const { data, pagination } = await fetchPage({ limit: pageSize, cursor, force: true });
    items.push(...data);
    cursor = pagination && pagination.nextCursor;
    if (!cursor) break;
  }
  return items;
}

async function upsertThreat(raw) {
  const threat = normalizeThreatDetail(raw);
  if (!threat.id) return false;
  await query(
    `INSERT INTO threats (
      id, name, severity, classification, confidence, mitigation_status, incident_status,
      analyst_verdict, agent_id, agent_name, agent_uuid, site, storyline, file_path,
      file_extension, md5, sha1, sha256, process_user, originator_process, process_arguments,
      publisher, initiating_username, external_ticket_id, agent_os, agent_ip, agent_version,
      agent_network_status, agent_infected, mitigation_actions, raw, created_at, updated_at, synced_at
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
      $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, now()
    )
    ON CONFLICT (id) DO UPDATE SET
      name = EXCLUDED.name, severity = EXCLUDED.severity, classification = EXCLUDED.classification,
      confidence = EXCLUDED.confidence, mitigation_status = EXCLUDED.mitigation_status,
      incident_status = EXCLUDED.incident_status, analyst_verdict = EXCLUDED.analyst_verdict,
      agent_id = EXCLUDED.agent_id, agent_name = EXCLUDED.agent_name, agent_uuid = EXCLUDED.agent_uuid,
      site = EXCLUDED.site, storyline = EXCLUDED.storyline, file_path = EXCLUDED.file_path,
      file_extension = EXCLUDED.file_extension, md5 = EXCLUDED.md5, sha1 = EXCLUDED.sha1,
      sha256 = EXCLUDED.sha256, process_user = EXCLUDED.process_user,
      originator_process = EXCLUDED.originator_process, process_arguments = EXCLUDED.process_arguments,
      publisher = EXCLUDED.publisher, initiating_username = EXCLUDED.initiating_username,
      external_ticket_id = EXCLUDED.external_ticket_id, agent_os = EXCLUDED.agent_os,
      agent_ip = EXCLUDED.agent_ip, agent_version = EXCLUDED.agent_version,
      agent_network_status = EXCLUDED.agent_network_status, agent_infected = EXCLUDED.agent_infected,
      mitigation_actions = EXCLUDED.mitigation_actions, raw = EXCLUDED.raw,
      created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at, synced_at = now()`,
    [
      threat.id, threat.name, threat.severity, threat.classification, threat.confidence,
      threat.mitigationStatus, threat.incidentStatus, threat.analystVerdict, threat.agentId || null,
      threat.agentName, threat.agentUuid || null, threat.site, threat.storyline || null,
      threat.filePath, threat.fileExtension, threat.md5 || null, threat.sha1 || null,
      threat.sha256 || null, threat.processUser, threat.originatorProcess,
      threat.maliciousProcessArguments, threat.publisherName, threat.initiatingUsername,
      threat.externalTicketId, threat.agentOs, threat.agentIp, threat.agentVersion,
      threat.agentNetworkStatus, threat.agentInfected === true, JSON.stringify(threat.mitigationActions),
      JSON.stringify(raw), toTs(threat.createdAt), toTs(threat.updatedAt),
    ],
  );
  return true;
}

async function upsertAlert(raw) {
  const alert = normalizeCloudAlert(raw);
  if (!alert.id) return false;
  await query(
    `INSERT INTO alerts (
      id, name, event_type, severity, indicator_category, indicator_name, indicator_description,
      analyst_verdict, incident_status, agent_uuid, agent_name, agent_os, site_id, rule_description,
      process_name, process_path, process_command_line, process_user, sha256, storyline,
      dst_ip, dst_port, dns_request, registry_key_path, login_username, raw, created_at, synced_at
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
      $21, $22, $23, $24, $25, $26, $27, now()
    )
    ON CONFLICT (id) DO UPDATE SET
      name = EXCLUDED.name, event_type = EXCLUDED.event_type, severity = EXCLUDED.severity,
      indicator_category = EXCLUDED.indicator_category, indicator_name = EXCLUDED.indicator_name,
      indicator_description = EXCLUDED.indicator_description, analyst_verdict = EXCLUDED.analyst_verdict,
      incident_status = EXCLUDED.incident_status, agent_uuid = EXCLUDED.agent_uuid,
      agent_name = EXCLUDED.agent_name, agent_os = EXCLUDED.agent_os, site_id = EXCLUDED.site_id,
      rule_description = EXCLUDED.rule_description, process_name = EXCLUDED.process_name,
      process_path = EXCLUDED.process_path, process_command_line = EXCLUDED.process_command_line,
      process_user = EXCLUDED.process_user, sha256 = EXCLUDED.sha256, storyline = EXCLUDED.storyline,
      dst_ip = EXCLUDED.dst_ip, dst_port = EXCLUDED.dst_port, dns_request = EXCLUDED.dns_request,
      registry_key_path = EXCLUDED.registry_key_path, login_username = EXCLUDED.login_username,
      raw = EXCLUDED.raw, created_at = EXCLUDED.created_at, synced_at = now()`,
    [
      alert.id, alert.name, alert.eventType, alert.severity, alert.indicatorCategory,
      alert.indicatorName, alert.indicatorDescription, alert.analystVerdict, alert.incidentStatus,
      alert.agentUuid || null, alert.agentName, alert.agentOs, alert.siteId, alert.ruleDescription,
      alert.processName, alert.processPath, alert.processCommandLine, alert.processUser,
      alert.sha256 || null, alert.storyline || null, alert.dstIp, alert.dstPort, alert.dnsRequest,
      alert.registryKeyPath, alert.loginUserName, raw, toTs(alert.createdAt),
    ],
  );
  return true;
}

async function upsertNote(threatId, raw) {
  const note = normalizeThreatNote(raw);
  if (!note.id) return false;
  await query(
    `INSERT INTO threat_notes (id, threat_id, text, creator, edited, created_at, updated_at, synced_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, now())
     ON CONFLICT (id) DO UPDATE SET
       threat_id = EXCLUDED.threat_id, text = EXCLUDED.text, creator = EXCLUDED.creator,
       edited = EXCLUDED.edited, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at,
       synced_at = now()`,
    [note.id, threatId, note.text, note.creator, note.edited === true, toTs(note.createdAt), toTs(note.updatedAt)],
  );
  return true;
}

async function upsertActivity(raw) {
  const activity = normalizeActivity(raw);
  if (!activity.id) return false;
  await query(
    `INSERT INTO activities (
      id, type, description, details, agent_id, agent_name, site, "user", threat_id, raw, created_at, synced_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
    ON CONFLICT (id) DO UPDATE SET
      type = EXCLUDED.type, description = EXCLUDED.description, details = EXCLUDED.details,
      agent_id = EXCLUDED.agent_id, agent_name = EXCLUDED.agent_name, site = EXCLUDED.site,
      "user" = EXCLUDED."user", threat_id = EXCLUDED.threat_id, raw = EXCLUDED.raw,
      created_at = EXCLUDED.created_at, synced_at = now()`,
    [
      activity.id, activity.type, activity.description, activity.details, activity.agentId || null,
      activity.agentName, activity.site, activity.user, null, raw, toTs(activity.createdAt),
    ],
  );
  return true;
}

async function startRun() {
  const { rows } = await query(`INSERT INTO sync_runs (status) VALUES ('running') RETURNING id`);
  return rows[0].id;
}

async function finishRun(runId, status, counts, error) {
  await query(
    `UPDATE sync_runs
     SET finished_at = now(), status = $2, threats_count = $3, alerts_count = $4,
         notes_count = $5, activities_count = $6, error = $7
     WHERE id = $1`,
    [runId, status, counts.threats, counts.alerts, counts.notes, counts.activities, error || null],
  );
}

// Une passe complète : menaces, alertes STAR, notes (menaces récentes), activités.
async function runSync(client) {
  const { syncPageSize: pageSize, syncMaxPages: maxPages } = config.database;
  const counts = { threats: 0, alerts: 0, notes: 0, activities: 0 };
  const errors = [];
  const runId = await startRun();

  try {
    const threats = await fetchAll((opts) => client.listThreats(opts), pageSize, maxPages);
    for (const raw of threats) {
      if (await upsertThreat(raw)) counts.threats += 1;
    }

    const alerts = await fetchAll((opts) => client.listAlerts(opts), pageSize, maxPages);
    for (const raw of alerts) {
      if (await upsertAlert(raw)) counts.alerts += 1;
    }

    // Notes : uniquement les menaces les plus récentes (limite les appels API).
    const recentThreats = threats.slice(0, NOTES_PER_RUN);
    for (const raw of recentThreats) {
      const threatId = (raw && (raw.id || (raw.threatInfo || {}).threatId)) || null;
      if (!threatId) continue;
      try {
        const page = await client.listThreatNotes(threatId, { limit: 100, force: true });
        for (const noteRaw of page.data) {
          if (await upsertNote(threatId, noteRaw)) counts.notes += 1;
        }
      } catch (error) {
        errors.push(`notes ${threatId}: ${error.message}`);
      }
    }

    const activities = await fetchAll((opts) => client.listActivities(opts), pageSize, maxPages);
    for (const raw of activities) {
      if (await upsertActivity(raw)) counts.activities += 1;
    }

    const status = errors.length > 0 ? 'partial' : 'success';
    await finishRun(runId, status, counts, errors.join(' | ') || null);
    log.info('Synchro PostgreSQL terminée', { runId, status, ...counts, errors: errors.length });

    // Indexation RAG en arrière-plan (jamais bloquante : erreurs provider → reprise au prochain run).
    if (config.ai.ragIndexEnabled) {
      const { runRagIndex } = require('./ragIndex');
      setTimeout(() => {
        runRagIndex().catch(() => {});
      }, 500);
    }

    return { runId, status, counts, errors };
  } catch (error) {
    await finishRun(runId, 'error', counts, error.message).catch(() => {});
    log.error('Synchro PostgreSQL échouée', { runId, error: error.message });
    throw error;
  }
}

// Planification : premier run différé (laisse le serveur démarrer), puis intervalle.
let timers = [];
let running = false;

function startSyncScheduler(client) {
  if (!config.database.syncEnabled) {
    log.info('Synchro PostgreSQL désactivée (DB_SYNC_ENABLED=false).');
    return;
  }
  const intervalMs = config.database.syncIntervalMs;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      await runSync(client);
    } catch (error) {
      // déjà journalisé dans runSync
    } finally {
      running = false;
    }
  };
  const first = setTimeout(tick, 5000);
  const loop = setInterval(tick, intervalMs);
  first.unref();
  loop.unref();
  timers = [first, loop];
  log.info('Synchro PostgreSQL planifiée', { intervalMs, firstRunInMs: 5000 });
}

function stopSyncScheduler() {
  for (const timer of timers) {
    clearTimeout(timer);
    clearInterval(timer);
  }
  timers = [];
}

module.exports = { runSync, startSyncScheduler, stopSyncScheduler };

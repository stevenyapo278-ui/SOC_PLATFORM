'use strict';

// Synchro SentinelOne → PostgreSQL.
//
// Deux modes :
//  - « delta »  : on ne récupère que ce qui a bougé depuis le pointeur de
//    l'entité (moins la fenêtre de recouvrement), filtré par createdAt /
//    updatedAt / reportedAt. C'est le mode des runs périodiques et du bouton
//    « Rafraîchir ».
//  - « complet » : pas de filtre temporel (les N éléments les plus récents de
//    chaque entité). Réserve à la 1re exécution et à la réconciliation
//    horaire, qui rattrape les modifications sur des objets anciens.
//
// Les pointeurs vivent dans sync_cursors (et pas en mémoire) : un redéploiement
// ne re-télécharge pas tout et ne perd aucune fenêtre.
// Upsert idempotent : une relance ne duplique jamais.

const config = require('../config');
const log = require('../logger');
const { query } = require('../db');
const {
  normalizeAgent,
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

function csvIds(value) {
  if (!value) return [];
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

async function fetchAll(fetchPage, pageSize, maxPages) {
  const items = [];
  let cursor = null;
  let truncated = false;
  for (let page = 0; page < maxPages; page += 1) {
    const { data, pagination } = await fetchPage({ limit: pageSize, cursor, force: true });
    items.push(...data);
    cursor = pagination && pagination.nextCursor;
    if (!cursor) break;
    if (page === maxPages - 1) truncated = true;
  }
  return { items, truncated };
}

/* ─────────────────────────── Pointeurs de synchronisation ─────────────────── */

async function loadCursors() {
  const { rows } = await query('SELECT entity, watermark FROM sync_cursors');
  return new Map(rows.map((row) => [row.entity, row.watermark]));
}

async function saveCursors(entries) {
  for (const [entity, watermark] of Object.entries(entries)) {
    if (!watermark) continue;
    await query(
      `INSERT INTO sync_cursors (entity, watermark, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (entity) DO UPDATE SET watermark = EXCLUDED.watermark, updated_at = now()`,
      [entity, watermark],
    );
  }
}

// Plan de la synchro : date de départ par entité (undefined = passe complète)
// + éventuelle réconciliation due.
async function buildPlan() {
  const cursors = await loadCursors();
  const entities = ['threats', 'alerts', 'activities', 'agents'];
  const overlapMs = config.database.syncOverlapMs;
  const since = {};

  for (const entity of entities) {
    const watermark = cursors.get(entity);
    // Recouvrement : une donnée modifiée peu après sa création est re-fetchée.
    since[entity] = watermark ? new Date(watermark.getTime() - overlapMs) : undefined;
  }

  const reconcile = cursors.get('__reconcile__');
  const reconcileDue = !reconcile || Date.now() - reconcile.getTime() >= config.database.syncReconcileMs;
  if (reconcileDue) {
    for (const entity of entities) since[entity] = undefined;
    return { since, reconcile: true };
  }
  return { since, reconcile: false };
}

/* ───────────────────────────────── Upserts ───────────────────────────────── */

async function upsertAgent(raw) {
  const agent = normalizeAgent(raw);
  if (!agent.id) return false;
  await query(
    `INSERT INTO agents (
      id, name, os, os_type, version, status, site, account, ip, domain,
      machine_type, infected, last_active_at, registered_at, updated_at, raw, synced_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, now())
    ON CONFLICT (id) DO UPDATE SET
      name = EXCLUDED.name, os = EXCLUDED.os, os_type = EXCLUDED.os_type,
      version = EXCLUDED.version, status = EXCLUDED.status, site = EXCLUDED.site,
      account = EXCLUDED.account, ip = EXCLUDED.ip, domain = EXCLUDED.domain,
      machine_type = EXCLUDED.machine_type, infected = EXCLUDED.infected,
      last_active_at = EXCLUDED.last_active_at, registered_at = EXCLUDED.registered_at,
      updated_at = EXCLUDED.updated_at, raw = EXCLUDED.raw, synced_at = now()`,
    [
      agent.id, agent.name, agent.os, agent.osType, agent.version, agent.status,
      agent.site, agent.account, agent.ip, agent.domain, agent.machineType,
      agent.infected === true, toTs(agent.lastActiveAt), toTs(agent.registeredAt),
      toTs(raw && raw.updatedAt), JSON.stringify(raw),
    ],
  );
  return true;
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
      indicator_description = EXCLUDED.indicator_description,
      analyst_verdict = EXCLUDED.analyst_verdict, incident_status = EXCLUDED.incident_status,
      agent_uuid = EXCLUDED.agent_uuid, agent_name = EXCLUDED.agent_name, agent_os = EXCLUDED.agent_os,
      site_id = EXCLUDED.site_id, rule_description = EXCLUDED.rule_description,
      process_name = EXCLUDED.process_name, process_path = EXCLUDED.process_path,
      process_command_line = EXCLUDED.process_command_line, process_user = EXCLUDED.process_user,
      sha256 = EXCLUDED.sha256, storyline = EXCLUDED.storyline, dst_ip = EXCLUDED.dst_ip,
      dst_port = EXCLUDED.dst_port, dns_request = EXCLUDED.dns_request,
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
    `INSERT INTO threat_notes (id, threat_id, text, creator, edited, created_at, updated_at, raw, synced_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
     ON CONFLICT (id) DO UPDATE SET
       threat_id = EXCLUDED.threat_id, text = EXCLUDED.text, creator = EXCLUDED.creator,
       edited = EXCLUDED.edited, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at,
       raw = EXCLUDED.raw, synced_at = now()`,
    [
      note.id, threatId, note.text, note.creator, note.edited === true,
      toTs(note.createdAt), toTs(note.updatedAt), JSON.stringify(raw),
    ],
  );
  return true;
}

async function upsertActivity(raw) {
  const activity = normalizeActivity(raw);
  if (!activity.id) return false;
  // threat_id doit être repris du brut : c'est lui qui rend possible
  // /api/activities?threatIds=… quand la lecture vient de la base.
  const threatId = (raw && (raw.threatId || (raw.data && raw.data.threatId))) || null;
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
      activity.agentName, activity.site, activity.user, threatId, raw, toTs(activity.createdAt),
    ],
  );
  return true;
}

/* ──────────────────────────────── Exécution ──────────────────────────────── */

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

// Menaces pour lesquelles on récupère les notes : celles du delta, complétées
// par les plus récentes de la base (sinon un run delta calme fige les notes).
async function noteTargets(deltaThreats) {
  const ids = [];
  const seen = new Set();
  for (const raw of deltaThreats) {
    const id = (raw && (raw.id || (raw.threatInfo || {}).threatId)) || null;
    if (id && !seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
    if (ids.length >= NOTES_PER_RUN) return ids;
  }
  try {
    const { rows } = await query(
      'SELECT id FROM threats ORDER BY created_at DESC NULLS LAST LIMIT $1',
      [NOTES_PER_RUN],
    );
    for (const row of rows) {
      if (!seen.has(row.id)) {
        seen.add(row.id);
        ids.push(row.id);
      }
      if (ids.length >= NOTES_PER_RUN) break;
    }
  } catch (error) {
    log.warn('Notes : liste des menaces récentes indisponible', { error: error.message });
  }
  return ids;
}

// Une passe : menaces, alertes STAR, notes, activités, agents.
async function runSync(client) {
  const { syncPageSize: pageSize, syncMaxPages: maxPages } = config.database;
  const counts = { threats: 0, alerts: 0, notes: 0, activities: 0, agents: 0 };
  const errors = [];
  const runId = await startRun();
  const startedAt = new Date();

  let plan;
  try {
    plan = await buildPlan();
  } catch (error) {
    await finishRun(runId, 'error', counts, error.message).catch(() => {});
    log.error('Synchro PostgreSQL : lecture des pointeurs impossible', { runId, error: error.message });
    throw error;
  }

  const delta = Object.fromEntries(
    Object.entries(plan.since).map(([entity, date]) => [entity, date ? date.toISOString() : null]),
  );
  const mode = plan.reconcile ? 'complet' : 'delta';
  log.debug('Synchro PostgreSQL démarrée', { runId, mode, delta });

  try {
    const threatsResult = await fetchAll(
      (opts) => client.listThreats({ ...opts, updatedAtGte: plan.since.threats || undefined }),
      pageSize,
      maxPages,
    );
    for (const raw of threatsResult.items) {
      if (await upsertThreat(raw)) counts.threats += 1;
    }
    if (threatsResult.truncated) errors.push('fenêtre menaces tronquée');

    const alertsResult = await fetchAll(
      (opts) => client.listAlerts({ ...opts, reportedAtGte: plan.since.alerts || undefined }),
      pageSize,
      maxPages,
    );
    for (const raw of alertsResult.items) {
      if (await upsertAlert(raw)) counts.alerts += 1;
    }
    if (alertsResult.truncated) errors.push('fenêtre alertes tronquée');

    for (const threatId of await noteTargets(threatsResult.items)) {
      try {
        const page = await client.listThreatNotes(threatId, { limit: 100, force: true });
        for (const noteRaw of page.data) {
          if (await upsertNote(threatId, noteRaw)) counts.notes += 1;
        }
      } catch (error) {
        errors.push(`notes ${threatId}: ${error.message}`);
      }
    }

    const activitiesResult = await fetchAll(
      (opts) => client.listActivities({ ...opts, createdAtGte: plan.since.activities || undefined }),
      pageSize,
      maxPages,
    );
    for (const raw of activitiesResult.items) {
      if (await upsertActivity(raw)) counts.activities += 1;
    }
    if (activitiesResult.truncated) errors.push('fenêtre activités tronquée');

    const agentsResult = await fetchAll(
      (opts) => client.listAgents({ ...opts, updatedAtGte: plan.since.agents || undefined }),
      pageSize,
      maxPages,
    );
    for (const raw of agentsResult.items) {
      if (await upsertAgent(raw)) counts.agents += 1;
    }
    if (agentsResult.truncated) errors.push('fenêtre endpoints tronquée');

    // Pointeurs avancés seulement à la fin : un échec reprend la même fenêtre.
    const watermarks = {
      threats: startedAt,
      alerts: startedAt,
      activities: startedAt,
      agents: startedAt,
    };
    if (plan.reconcile) watermarks.__reconcile__ = startedAt;
    await saveCursors(watermarks);

    const status = errors.length > 0 ? 'partial' : 'success';
    await finishRun(runId, status, counts, errors.join(' | ') || null);
    log.info('Synchro PostgreSQL terminée', { runId, status, mode, ...counts, errors: errors.length });

    // Indexation RAG en arrière-plan (jamais bloquante : erreurs provider → reprise au prochain run).
    if (config.ai.ragIndexEnabled) {
      const { runRagIndex } = require('./ragIndex');
      setTimeout(() => {
        runRagIndex().catch(() => {});
      }, 500);
    }

    return { runId, status, mode, counts, errors };
  } catch (error) {
    await finishRun(runId, 'error', counts, error.message).catch(() => {});
    log.error('Synchro PostgreSQL échouée', { runId, error: error.message });
    throw error;
  }
}

/* ────────────────────── Planification + verrou unique ────────────────────── */

let timers = [];
let inflight = null;
let lastRunAt = 0;

// Un seul run à la fois : le scheduler et le bouton « Rafraîchir » partagent
// ce verrou, sinon deux deltas parallèles se marcheraient sur les pointeurs.
function syncOnce(client) {
  if (inflight) return inflight;
  const promise = runSync(client).finally(() => {
    inflight = null;
    lastRunAt = Date.now();
  });
  inflight = promise;
  return promise;
}

// Déclenché par ?refresh=1 : delta immédiat, limité à un toutes les N ms.
async function syncNow(client) {
  if (!client) return null;
  if (inflight) return inflight;
  if (Date.now() - lastRunAt < config.database.syncRefreshMinMs) return { skipped: true };
  return syncOnce(client);
}

function startSyncScheduler(client) {
  if (!config.database.syncEnabled) {
    log.info('Synchro PostgreSQL désactivée (DB_SYNC_ENABLED=false).');
    return;
  }
  const intervalMs = config.database.syncIntervalMs;
  const tick = async () => {
    if (inflight) return;
    try {
      await syncOnce(client);
    } catch (error) {
      // déjà journalisé dans runSync
    }
  };
  const first = setTimeout(tick, 500);
  const loop = setInterval(tick, intervalMs);
  first.unref();
  loop.unref();
  timers = [first, loop];
  log.info('Synchro PostgreSQL planifiée', {
    intervalMs,
    firstRunInMs: 500,
    overlapMin: Math.round(config.database.syncOverlapMs / 60000),
    reconcileMin: Math.round(config.database.syncReconcileMs / 60000),
  });
}

function stopSyncScheduler() {
  for (const timer of timers) {
    clearTimeout(timer);
    clearInterval(timer);
  }
  timers = [];
}

module.exports = { runSync, syncOnce, syncNow, startSyncScheduler, stopSyncScheduler };

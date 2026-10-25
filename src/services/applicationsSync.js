'use strict';

// Inventaire des applications par endpoint — GET /agents/applications?ids=<id>.
//
// SentinelOne n'expose aucune liste plate « application × endpoint » :
//   - /agents/applications?ids=a,b,c renvoie les applications fusionnées SANS
//     attribution (impossible de savoir quelle machine les porte) ;
//   - /application-management/inventory (et son export CSV) ne donne que des
//     agrégats : nom + éditeur + nombre de versions + nombre de endpoints ;
//   - /application-management/inventory/endpoints exige applicationName et
//     applicationVendor → 1 appel par application (≈ 6 700).
// Reste : 1 appel par endpoint (1 321 sur la console réelle), concours limité.
// Les lignes vont dans endpoint_applications, la vue « Applications » se lit
// ensuite en SQL avec jointure sur `agents` (nom/OS/site/statut de la machine).
//
// Planification : volontairement décalée du scheduler principal (DB_SYNC_APPS_MIN,
// 6 h par défaut, première passe à +60 s) pour ne pas marteler la console au
// démarrage. ?refresh=1 déclenche une passe en arrière-plan (verrou unique +
// anti-rafale DB_SYNC_REFRESH_MIN_MS) : la page répond immédiatement.

const log = require('../logger');
const config = require('../config');
const { query, getPool } = require('../db');
const { normalizeApplication } = require('../sentinelone/normalize');

// Appels concurrents vers SentinelOne pendant une passe complète.
const CONCURRENCY = 6;
// Passe de démarrage : laisse le scheduler principal (delta à +500 ms) se faire.
const FIRST_RUN_DELAY_MS = 60 * 1000;

const COLUMNS = ['agent_id', 'name', 'version', 'publisher', 'size', 'installed_at', 'raw'];

function insertStatement(agentId, apps) {
  const values = [];
  const params = [];
  apps.forEach((app, index) => {
    const base = index * COLUMNS.length;
    values.push(`(${COLUMNS.map((_, column) => `$${base + column + 1}`).join(', ')})`);
    params.push(
      agentId,
      app.name,
      app.version,
      app.publisher,
      app.size,
      app.installedAt,
      JSON.stringify(app.raw),
    );
  });
  return {
    text: `INSERT INTO endpoint_applications (${COLUMNS.join(', ')}) VALUES ${values.join(', ')}
           ON CONFLICT (agent_id, name, version) DO NOTHING`,
    params,
  };
}

// Remplacement atomique par endpoint : une application désinstallée disparaît.
async function replaceAgentApplications(agentId, apps) {
  const connection = await getPool().connect();
  try {
    await connection.query('BEGIN');
    await connection.query('DELETE FROM endpoint_applications WHERE agent_id = $1', [agentId]);
    if (apps.length > 0) {
      const statement = insertStatement(agentId, apps);
      await connection.query(statement.text, statement.params);
    }
    await connection.query('COMMIT');
  } catch (error) {
    await connection.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    connection.release();
  }
}

async function listAgentIds() {
  const { rows } = await query('SELECT id FROM agents ORDER BY id');
  return rows.map((row) => row.id);
}

async function saveWatermark() {
  await query(
    `INSERT INTO sync_cursors (entity, watermark, updated_at) VALUES ('applications', now(), now())
     ON CONFLICT (entity) DO UPDATE SET watermark = EXCLUDED.watermark, updated_at = now()`,
  );
}

// Une passe complète : 1 appel par endpoint, concours limité, erreurs isolées
// (un endpoint en erreur ne bloque pas les autres, il sera repris à la passe
// suivante).
async function runApplicationsSync(client, options = {}) {
  const force = options.force !== false;
  const startedAt = Date.now();
  const agentIds = await listAgentIds();

  if (agentIds.length === 0) {
    log.warn('Synchro applications ignorée : aucun endpoint en base (lancez d\'abord la synchro principale).');
    return { agents: 0, applications: 0, errors: 0, skipped: true };
  }

  const stats = { agents: 0, applications: 0, errors: 0 };
  let cursor = 0;

  async function worker() {
    while (cursor < agentIds.length) {
      const agentId = agentIds[cursor++];
      try {
        const page = await client.listAgentApplications(agentId, { force });
        const apps = (page && Array.isArray(page.data) ? page.data : []).map((raw) => {
          const normalized = normalizeApplication(raw);
          return { ...normalized, raw };
        });
        await replaceAgentApplications(agentId, apps);
        stats.agents += 1;
        stats.applications += apps.length;
      } catch (error) {
        stats.errors += 1;
        log.warn('Synchro applications : endpoint ignoré', { agentId, error: error.message });
      }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
  await saveWatermark();

  log.info('Synchro applications terminée', {
    durationMs: Date.now() - startedAt,
    ...stats,
  });
  return { ...stats, durationMs: Date.now() - startedAt };
}

/* ────────────────────── Planification + verrou unique ────────────────────── */

let timers = [];
let inflight = null;
let lastRunAt = 0;

function applicationsOnce(client) {
  if (inflight) return inflight;
  const promise = runApplicationsSync(client).finally(() => {
    inflight = null;
    lastRunAt = Date.now();
  });
  inflight = promise;
  return promise;
}

// Déclenché par ?refresh=1 : passe immédiate en arrière-plan, anti-rafale.
function syncApplicationsNow(client) {
  if (!client) return null;
  if (inflight) return { running: true };
  if (Date.now() - lastRunAt < config.database.syncRefreshMinMs) return { skipped: true };
  const promise = applicationsOnce(client);
  promise.catch(() => {}); // journalisé par runApplicationsSync
  return { queued: true };
}

function startApplicationsScheduler(client) {
  if (!config.database.syncEnabled) {
    log.info('Synchro applications désactivée (DB_SYNC_ENABLED=false).');
    return;
  }
  const intervalMs = config.database.syncApplicationsMs;
  const tick = async () => {
    if (inflight) return;
    try {
      await applicationsOnce(client);
    } catch (error) {
      log.warn('Synchro applications échouée', { error: error.message });
    }
  };
  const first = setTimeout(tick, FIRST_RUN_DELAY_MS);
  const loop = setInterval(tick, intervalMs);
  first.unref();
  loop.unref();
  timers = [first, loop];
  log.info('Synchro applications planifiée', {
    intervalMs,
    firstRunInMs: FIRST_RUN_DELAY_MS,
    concurrency: CONCURRENCY,
  });
}

function stopApplicationsScheduler() {
  for (const timer of timers) {
    clearTimeout(timer);
    clearInterval(timer);
  }
  timers = [];
}

module.exports = {
  runApplicationsSync,
  applicationsOnce,
  syncApplicationsNow,
  startApplicationsScheduler,
  stopApplicationsScheduler,
};

'use strict';

// Lecture SQL des vues (PostgreSQL) — alternative au passage direct à
// SentinelOne. Même contrat que le client S1 : { data, pagination }, où data
// contient les objets BRUTS stockés en JSONB, donc les normaliseurs du front
// sont strictement les mêmes que dans le mode « sans base ».
//
// Pagination : curseur offset encodé en base64url ({o:n}). Le front traite le
// cursor comme opaque, il n'y a rien à changer côté navigateur.
//
// Un échec SQL ne doit pas rendre la console muette : createReader (routes)
// retombe sur le client S1 en cas d'erreur ici.

const { query, migrateOnce } = require('./index');
const { SEVERITY_ORDER } = require('../sentinelone/normalize');

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 25;
// Plafond des lectures internes (KPI de l'aperçu) : la limite publique reste 100.
const MAX_INTERNAL_LIMIT = 5000;

function clampLimit(value, max = MAX_LIMIT) {
  const n = Number.parseInt(value, 10);
  const cap = Math.min(Math.max(Number(max) || MAX_LIMIT, 1), MAX_INTERNAL_LIMIT);
  if (!Number.isFinite(n) || n <= 0) return Math.min(DEFAULT_LIMIT, cap);
  return Math.min(n, cap);
}

function encodeCursor(offset) {
  return Buffer.from(JSON.stringify({ o: offset }), 'utf8').toString('base64url');
}

function decodeCursor(cursor) {
  if (typeof cursor !== 'string' || !cursor) return 0;
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
    return Number.isInteger(parsed.o) && parsed.o >= 0 ? parsed.o : 0;
  } catch {
    return 0;
  }
}

function csvList(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

/* ───────────────────────── construction des filtres ───────────────────────── */

// Recherche libre : LIKE insensible à la casse sur les colonnes textuelles clés.
function addSearch(parts, params, columns, value) {
  const term = typeof value === 'string' ? value.trim() : '';
  if (!term) return;
  params.push(`%${term}%`);
  const ref = `$${params.length}`;
  parts.push(`(${columns.map((column) => `${column} ILIKE ${ref}`).join(' OR ')})`);
}

// Filtre « contient » (équivalent des filtres __contains de l'API).
function addContains(parts, params, column, value) {
  if (typeof value !== 'string' || !value.trim()) return;
  params.push(`%${value.trim()}%`);
  parts.push(`${column} ILIKE $${params.length}`);
}

// Filtre exact, insensible à la casse (gravité, verdict : la casse varie selon
// les versions de la console : « Critical » côté API, « critical » normalisé).
function addIeq(parts, params, column, value) {
  if (typeof value !== 'string' || !value.trim()) return;
  params.push(value.trim());
  parts.push(`lower(${column}) = lower($${params.length})`);
}

// Filtre csv (storylines=a,b / analystVerdicts=true_positive,false_positive).
function addCsv(parts, params, column, value, { ignoreCase = false } = {}) {
  const list = csvList(value);
  if (!list) return;
  params.push(list);
  const ref = `$${params.length}`;
  const unnest = `SELECT btrim(lower(v)) FROM unnest(${ref}::text[]) AS v`;
  parts.push(
    ignoreCase
      ? `lower(${column}) IN (${unnest})`
      : `${column} IN (SELECT btrim(v) FROM unnest(${ref}::text[]) AS v)`,
  );
}

function addGte(parts, params, column, value) {
  if (!value) return;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return;
  params.push(date.toISOString());
  parts.push(`${column} >= $${params.length}`);
}

/* ──────────────────────────── pagination générique ────────────────────────── */

async function paged(table, parts, params, orderBy, options) {
  const limit = clampLimit(options.limit, options.maxLimit);
  const offset = decodeCursor(options.cursor);
  const whereSql = parts.length > 0 ? `WHERE ${parts.join(' AND ')}` : '';

  const countResult = await query(`SELECT count(*)::int AS total FROM ${table} ${whereSql}`, params);
  const total = countResult.rows[0].total;

  const pageParams = [...params, limit, offset];
  const rows = await query(
    `SELECT raw FROM ${table} ${whereSql} ORDER BY ${orderBy} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    pageParams,
  );

  const data = rows.rows.map((row) => row.raw).filter((row) => row && typeof row === 'object');
  const nextOffset = offset + data.length;
  return {
    data,
    pagination: {
      totalItems: total,
      nextCursor: nextOffset < total ? encodeCursor(nextOffset) : null,
    },
  };
}

const emptyPage = () => ({ data: [], pagination: { totalItems: 0, nextCursor: null } });

/* ──────────────────────────────── lecteurs ────────────────────────────────── */

async function listAgents(options = {}) {
  await migrateOnce();
  const parts = [];
  const params = [];
  // Recherche multi-critères : nom, IP, OS, site, compte, domaine, version +
  // identité machine (série, modèle, MAC, IP de toutes les interfaces, clé).
  addSearch(
    parts,
    params,
    [
      'name',
      'ip',
      'os',
      'site',
      'account',
      'domain',
      'version',
      'serial_number',
      'model',
      'machine_key',
      `array_to_string(mac_addresses, ' ')`,
      `array_to_string(ip_addresses, ' ')`,
    ],
    options.query,
  );
  return paged('agents', parts, params, 'name ASC, id ASC', options);
}

/* ──────────────────── identité machine (jointures de vues) ───────────────── */

// Résumé d'endpoint renvoyé aux listes (menaces / alertes / activités) : l'état
// ACTUEL de la machine (nom, site, statut, série, MAC) plutôt que la valeur
// figée au moment de la détection.
function endpointSummary(row) {
  return {
    id: row.id,
    name: row.name || '—',
    os: row.os || '—',
    osType: row.os_type || '',
    site: row.site || '—',
    status: row.status || 'unknown',
    ip: row.ip || '—',
    domain: row.domain || '—',
    machineType: row.machine_type || '—',
    infected: Boolean(row.infected),
    serialNumber: row.serial_number || '',
    macAddresses: Array.isArray(row.mac_addresses) ? row.mac_addresses : [],
    model: row.model || '',
    agentVersion: row.version || '—',
    lastActiveAt: row.last_active_at ? new Date(row.last_active_at).toISOString() : null,
  };
}

// Batch par ids : une seule requête pour une page entière (≤ 100 lignes).
async function getAgentsByIds(ids) {
  const list = [...new Set((Array.isArray(ids) ? ids : []).filter((id) => typeof id === 'string' && id))];
  const map = new Map();
  if (list.length === 0) return map;
  await migrateOnce();
  const { rows } = await query(
    `SELECT id, name, os, os_type, site, status, ip, domain, machine_type, infected,
            serial_number, mac_addresses, model, last_active_at, version
       FROM agents
      WHERE id = ANY($1)`,
    [list],
  );
  for (const row of rows) map.set(row.id, endpointSummary(row));
  return map;
}

async function listThreats(options = {}) {
  await migrateOnce();
  const parts = [];
  const params = [];
  addCsv(parts, params, 'id', options.ids);
  addCsv(parts, params, 'storyline', options.storylines);
  addCsv(parts, params, 'agent_id', options.agentIds);
  addCsv(parts, params, 'analyst_verdict', options.analystVerdicts, { ignoreCase: true });
  addCsv(parts, params, 'mitigation_status', options.mitigationStatuses, { ignoreCase: true });
  addSearch(
    parts,
    params,
    ['name', 'file_path', 'agent_name', 'storyline', 'sha256', 'process_user', 'initiating_username', 'originator_process'],
    options.query,
  );
  addGte(parts, params, 'updated_at', options.updatedAtGte);
  return paged('threats', parts, params, 'created_at DESC NULLS LAST, id DESC', options);
}

async function getThreat(id, options = {}) {
  void options;
  if (!id) return null;
  await migrateOnce();
  const { rows } = await query('SELECT raw FROM threats WHERE id = $1', [id]);
  const raw = rows[0] && rows[0].raw;
  return raw && typeof raw === 'object' ? raw : null;
}

async function listThreatNotes(threatId, options = {}) {
  await migrateOnce();
  if (!threatId) return emptyPage();
  return paged(
    'threat_notes',
    ['threat_id = $1'],
    [threatId],
    'created_at DESC NULLS LAST, id DESC',
    options,
  );
}

async function listCloudAlerts(options = {}) {
  await migrateOnce();
  const parts = [];
  const params = [];
  addSearch(
    parts,
    params,
    ['name', 'indicator_name', 'process_name', 'process_path', 'process_command_line', 'agent_name', 'rule_description', 'sha256', 'storyline'],
    options.query,
  );
  addIeq(parts, params, 'severity', options.severity);
  addIeq(parts, params, 'analyst_verdict', options.analystVerdict);
  addGte(parts, params, 'created_at', options.reportedAtGte);
  addContains(parts, params, 'storyline', options.storyline);
  addContains(parts, params, 'sha256', options.sha256);
  addContains(parts, params, 'agent_uuid', options.agentUuid);
  addContains(parts, params, 'agent_name', options.agentName);
  addCsv(parts, params, 'agent_id', options.agentIds);
  return paged('alerts', parts, params, 'created_at DESC NULLS LAST, id DESC', options);
}

async function listAlerts(options = {}) {
  await migrateOnce();
  const parts = [];
  const params = [];
  addSearch(
    parts,
    params,
    ['name', 'indicator_name', 'process_name', 'process_path', 'agent_name', 'rule_description', 'sha256', 'storyline'],
    options.query,
  );
  addGte(parts, params, 'created_at', options.reportedAtGte);
  addCsv(parts, params, 'agent_id', options.agentIds);
  return paged('alerts', parts, params, 'created_at DESC NULLS LAST, id DESC', options);
}

async function listActivities(options = {}) {
  await migrateOnce();
  const parts = [];
  const params = [];
  addCsv(parts, params, 'threat_id', options.threatIds);
  addCsv(parts, params, 'agent_id', options.agentIds);
  return paged('activities', parts, params, 'created_at DESC NULLS LAST, id DESC', options);
}

/* ─────────────────── Inventaire des applications (vue globale) ───────────── */

// Lecture de endpoint_applications avec jointure sur `agents` : chaque ligne
// porte l'application ET l'endpoint qui l'installe (nom, OS, site, statut).
// Contrairement aux autres lecteurs, la réponse n'est pas du JSONB brut : les
// colonnes sont projetées ici (le `raw` reste en base, utile au débogage).
function applicationRow(row) {
  const endpoint = row.endpoint_name || row.endpoint_ip ? {
    id: row.agent_id,
    name: row.endpoint_name || '—',
    os: row.endpoint_os || '',
    osType: row.endpoint_os_type || '',
    site: row.endpoint_site || '',
    status: row.endpoint_status || 'unknown',
    ip: row.endpoint_ip || '',
    machineType: row.endpoint_machine_type || '',
    infected: Boolean(row.endpoint_infected),
  } : null;

  return {
    name: row.name,
    version: row.version,
    publisher: row.publisher,
    size: row.size === null || row.size === undefined ? null : Number(row.size),
    installedAt: row.installed_at ? new Date(row.installed_at).toISOString() : null,
    signed: row.signed || null,
    endpoint,
    syncedAt: row.synced_at ? new Date(row.synced_at).toISOString() : null,
  };
}

async function listApplications(options = {}) {
  await migrateOnce();
  const parts = [];
  const params = [];
  addSearch(
    parts,
    params,
    ['a.name', 'a.publisher', 'a.version', 'ag.name', 'ag.ip', 'ag.site'],
    options.query,
  );
  addIeq(parts, params, 'a.publisher', options.publisher);
  if (typeof options.agentId === 'string' && options.agentId.trim()) {
    params.push(options.agentId.trim());
    parts.push(`a.agent_id = $${params.length}`);
  }
  const whereSql = parts.length > 0 ? `WHERE ${parts.join(' AND ')}` : '';
  const from = 'FROM endpoint_applications a LEFT JOIN agents ag ON ag.id = a.agent_id';

  const countResult = await query(`SELECT count(*)::int AS total ${from} ${whereSql}`, params);
  const total = countResult.rows[0].total;

  const limit = clampLimit(options.limit);
  const offset = decodeCursor(options.cursor);
  const rows = await query(
    `SELECT a.agent_id, a.name, a.version, a.publisher, a.size, a.installed_at, a.synced_at,
            a.raw->>'signed' AS signed,
            ag.name AS endpoint_name, ag.os AS endpoint_os, ag.os_type AS endpoint_os_type,
            ag.site AS endpoint_site, ag.status AS endpoint_status, ag.ip AS endpoint_ip,
            ag.machine_type AS endpoint_machine_type, ag.infected AS endpoint_infected
     ${from} ${whereSql}
     ORDER BY lower(a.name) ASC, a.version ASC, a.agent_id ASC
     LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, limit, offset],
  );

  const data = rows.rows.map(applicationRow);
  const nextOffset = offset + data.length;
  return {
    data,
    pagination: {
      totalItems: total,
      nextCursor: nextOffset < total ? encodeCursor(nextOffset) : null,
    },
  };
}

// Dernière passe de l'inventaire (pointeur `applications` + dernière ligne écrite).
async function applicationsStatus() {
  await migrateOnce();
  const { rows } = await query(
    `SELECT max(synced_at) AS last_row_at,
            (SELECT watermark FROM sync_cursors WHERE entity = 'applications') AS watermark
       FROM endpoint_applications`,
  );
  const row = rows[0] || {};
  const iso = (value) => (value ? new Date(value).toISOString() : null);
  return { lastSyncAt: iso(row.watermark), lastRowAt: iso(row.last_row_at) };
}

/* ──────────────────────── KPI exacts (aggrégats SQL) ──────────────────────── */

// Compteurs du tableau de bord calculés par PostgreSQL au lieu d'un
// échantillon de lignes : exacts quel que soit la taille du parc (1 400+
// endpoints), et pas de « ≈ » sur le dashboard.
//
// Les expressions reproduisent à l'identique normalizeAgent / isActiveThreat /
// isOpenAlert de src/sentinelone/normalize.js — si ces règles changent, les
// deux côtés doivent bouger ensemble (couverts par tests/overview.test.js).
async function overviewCounts(now = new Date()) {
  await migrateOnce();

  const start = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 6),
  ).toISOString();

  const [agents, threats, severityRows, alerts, trendRows] = await Promise.all([
    query(`
      SELECT count(*)::int AS total,
             (count(*) FILTER (
               WHERE lower(coalesce(raw->>'isActive', 'true')) <> 'false'
                 AND lower(coalesce(raw->>'isDecommissioned', 'false')) <> 'true'
                 AND lower(coalesce(raw->>'networkStatus', '')) IN ('connected', 'online')
             ))::int AS online,
             (count(*) FILTER (WHERE status = 'offline'))::int AS offline,
             (count(*) FILTER (WHERE status = 'decommissioned'))::int AS decommissioned,
             (count(*) FILTER (WHERE infected))::int AS infected
      FROM agents
    `),
    query(`
      SELECT count(*)::int AS total,
             (count(*) FILTER (
               WHERE lower(coalesce(incident_status, '')) NOT IN ('resolved', 'closed')
                 AND lower(coalesce(mitigation_status, '')) NOT IN ('mitigated', 'marked_as_benign', 'benign')
             ))::int AS active,
             (count(*) FILTER (WHERE lower(severity) IN ('critical', 'high')))::int AS high_critical
      FROM threats
    `),
    query(`SELECT lower(severity) AS severity, count(*)::int AS n FROM threats GROUP BY 1`),
    query(`
      SELECT count(*)::int AS total,
             (count(*) FILTER (
               WHERE lower(coalesce(
                 nullif(raw->>'status', ''),
                 raw#>>'{alertInfo,status}',
                 raw#>>'{alertInfo,incidentStatus}',
                 ''
               )) NOT IN ('resolved', 'closed', 'dismissed')
             ))::int AS open
      FROM alerts
    `),
    query(
      `SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day, count(*)::int AS n
       FROM threats WHERE created_at >= $1 GROUP BY 1`,
      [start],
    ),
  ]);

  const severity = Object.fromEntries(SEVERITY_ORDER.map((key) => [key, 0]));
  for (const row of severityRows.rows) {
    const key = SEVERITY_ORDER.includes(row.severity) ? row.severity : 'unknown';
    severity[key] += row.n;
  }

  const trend = {};
  for (const row of trendRows.rows) trend[row.day] = row.n;

  const agentRow = agents.rows[0] || {};
  const threatRow = threats.rows[0] || {};
  const alertRow = alerts.rows[0] || {};

  return {
    agents: {
      total: agentRow.total || 0,
      online: agentRow.online || 0,
      offline: agentRow.offline || 0,
      decommissioned: agentRow.decommissioned || 0,
      infected: agentRow.infected || 0,
    },
    threats: {
      total: threatRow.total || 0,
      active: threatRow.active || 0,
      highCritical: threatRow.high_critical || 0,
    },
    severity,
    alerts: { total: alertRow.total || 0, open: alertRow.open || 0 },
    trend,
  };
}

module.exports = {
  listAgents,
  getAgentsByIds,
  endpointSummary,
  listThreats,
  getThreat,
  listThreatNotes,
  listCloudAlerts,
  listAlerts,
  listActivities,
  listApplications,
  applicationsStatus,
  overviewCounts,
};

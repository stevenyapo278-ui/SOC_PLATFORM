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
const { heatmapStart, RANK_SEVERITY } = require('../sentinelone/stats');

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

/* ────────────────────────── machines (regroupement) ───────────────────────── */

// Une ligne = une machine physique (regroupement par `machine_key`) : SentinelOne
// remonte parfois 2 agents actifs pour la même machine (réinstallation sans
// décommission), ce qu'une liste d'agents ne laisse pas voir.
const MACHINES_CTE = `
WITH machines AS (
  SELECT
    machine_key,
    COUNT(*)::int AS agent_count,
    (COUNT(*) FILTER (WHERE status = 'online'))::int AS online_count,
    (COUNT(*) FILTER (WHERE status = 'decommissioned'))::int AS decommissioned_count,
    bool_or(infected) AS infected,
    max(last_active_at) AS last_active_at,
    min(registered_at) AS registered_at,
    array_agg(DISTINCT lower(name)) AS name_list,
    string_agg(DISTINCT lower(name), ' ') AS names,
    string_agg(
      lower(
        name || ' | ' || COALESCE(serial_number, '') || ' | ' ||
        array_to_string(mac_addresses, ' ') || ' | ' ||
        array_to_string(ip_addresses, ' ') || ' | ' ||
        COALESCE(model, '') || ' | ' || site || ' | ' || domain
      ),
      ' '
    ) AS search_blob,
    jsonb_agg(
      jsonb_build_object(
        'id', id, 'name', name, 'os', os, 'osType', os_type, 'status', status,
        'site', site, 'ip', ip, 'domain', domain, 'version', version, 'infected', infected,
        'serialNumber', serial_number, 'macAddresses', mac_addresses, 'model', model,
        'lastActiveAt', to_char(last_active_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MSZ'),
        'registeredAt', to_char(registered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MSZ')
      )
      ORDER BY (status = 'online') DESC, last_active_at DESC NULLS LAST, name ASC, id ASC
    ) AS agents
  FROM agents
  WHERE machine_key <> ''
  GROUP BY machine_key
)`;

// Vue machine : l'agent le plus récent porte l'identité affichée, les autres
// restent listés (c'est eux qui signalent le doublon).
function machineSummary(row) {
  const agents = Array.isArray(row.agents) ? row.agents : [];
  const primary = agents[0] || {};
  const serials = [...new Set(agents.map((agent) => agent.serialNumber).filter(Boolean))];
  const macs = [...new Set(agents.flatMap((agent) => agent.macAddresses || []))];
  return {
    machineKey: row.machine_key,
    name: primary.name || '—',
    site: primary.site || '—',
    status: primary.status || 'unknown',
    ip: primary.ip || '—',
    model: primary.model || '',
    serialNumbers: serials,
    macAddresses: macs,
    lastActiveAt: primary.lastActiveAt || null,
    registeredAt: row.registered_at
      ? new Date(row.registered_at).toISOString()
      : primary.registeredAt || null,
    agentCount: row.agent_count,
    onlineCount: row.online_count,
    decommissionedCount: row.decommissioned_count,
    infected: row.infected === true,
    duplicate: row.agent_count > 1,
    nameList: Array.isArray(row.name_list) ? row.name_list : [],
    nameCollision: false,
    agents,
  };
}

// Noms portés par PLUSIEURS machines distinctes (collision d'inventaire).
async function collidingNames() {
  try {
    const { rows } = await query(
      `${MACHINES_CTE}
       SELECT n FROM (
         SELECT unnest(name_list) AS n, machine_key FROM machines
       ) AS x
       GROUP BY n
       HAVING COUNT(DISTINCT machine_key) > 1`,
      [],
    );
    return rows.map((row) => row.n);
  } catch (error) {
    return [];
  }
}

/* ───────────────────────────── tags SOC (locaux) ─────────────────────────── */

// Étiquettes posées par l'équipe : table locale, jamais renvoyées à SentinelOne.
function cleanTag(value) {
  if (typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ').slice(0, 32);
}

function cleanKeys(value) {
  return [...new Set((Array.isArray(value) ? value : []).filter((key) => typeof key === 'string' && key))];
}

async function tagsByMachine(keys) {
  const map = new Map();
  if (keys.length === 0) return map;
  await migrateOnce();
  const { rows } = await query(
    'SELECT machine_key, tag FROM machine_tags WHERE machine_key = ANY($1) ORDER BY lower(tag)',
    [keys],
  );
  for (const row of rows) {
    if (!map.has(row.machine_key)) map.set(row.machine_key, []);
    map.get(row.machine_key).push(row.tag);
  }
  return map;
}

async function addMachineTags(machineKeys, tag, createdBy = '') {
  const keys = cleanKeys(machineKeys);
  const value = cleanTag(tag);
  if (keys.length === 0 || !value) return 0;
  await migrateOnce();
  const { rowCount } = await query(
    `INSERT INTO machine_tags (machine_key, tag, created_by)
     SELECT k, $2, $3 FROM unnest($1::text[]) AS k
     ON CONFLICT (machine_key, tag) DO NOTHING`,
    [keys, value, String(createdBy || '').slice(0, 64)],
  );
  return rowCount;
}

async function removeMachineTags(machineKeys, tag) {
  const keys = cleanKeys(machineKeys);
  const value = cleanTag(tag);
  if (keys.length === 0 || !value) return 0;
  await migrateOnce();
  const { rowCount } = await query(
    'DELETE FROM machine_tags WHERE machine_key = ANY($1) AND tag = $2',
    [keys, value],
  );
  return rowCount;
}

// Historique d'un agent : transitions d'identité et de cycle de vie enregistrées
// à chaque synchro (voir src/services/sync.js — recordAgentHistory).
// Fiche d'un endpoint : agent + clé machine + tags locaux + autres agents
// installés sur la même machine physique (doublons de réinstallation).
async function getAgent(id) {
  await migrateOnce();
  if (typeof id !== 'string' || !id) return null;
  const { rows } = await query('SELECT * FROM agents WHERE id = $1', [id]);
  if (rows.length === 0) return null;
  const row = rows[0];
  const machineKey = row.machine_key || '';

  let siblings = [];
  if (machineKey) {
    const result = await query(
      'SELECT * FROM agents WHERE machine_key = $1 AND id <> $2 ORDER BY name, id',
      [machineKey, id],
    );
    siblings = result.rows;
  }

  let tags = [];
  if (machineKey) {
    const result = await query(
      'SELECT tag, created_by, created_at FROM machine_tags WHERE machine_key = $1 ORDER BY tag',
      [machineKey],
    );
    tags = result.rows.map((tag) => ({
      tag: tag.tag,
      createdBy: tag.created_by || '',
      createdAt: tag.created_at ? new Date(tag.created_at).toISOString() : null,
    }));
  }

  const historyResult = await query('SELECT count(*)::int AS total FROM agent_history WHERE agent_id = $1', [id]);

  return {
    raw: row.raw,
    machineKey,
    machineKeySource: row.machine_key_source || '',
    firstSeenAt: row.first_seen_at ? new Date(row.first_seen_at).toISOString() : null,
    lastSeenAt: row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null,
    duplicate: siblings.length > 0,
    siblings: siblings.map(endpointSummary),
    tags,
    historyTotal: historyResult.rows[0].total,
  };
}

async function getAgentHistory(agentId, options = {}) {
  await migrateOnce();
  if (typeof agentId !== 'string' || !agentId) return emptyPage();

  const countResult = await query(
    'SELECT COUNT(*)::int AS total FROM agent_history WHERE agent_id = $1',
    [agentId],
  );
  const total = countResult.rows[0].total;

  const limit = clampLimit(options.limit, options.maxLimit || MAX_LIMIT);
  const offset = decodeCursor(options.cursor);
  const { rows } = await query(
    `SELECT id, event, old_value, new_value, detected_at, recorded_at
       FROM agent_history
      WHERE agent_id = $1
      ORDER BY detected_at DESC, id DESC
      LIMIT $2 OFFSET $3`,
    [agentId, limit, offset],
  );

  const data = rows.map((row) => ({
    id: Number(row.id),
    agentId,
    event: row.event,
    oldValue: row.old_value,
    newValue: row.new_value,
    detectedAt: row.detected_at ? new Date(row.detected_at).toISOString() : null,
    recordedAt: row.recorded_at ? new Date(row.recorded_at).toISOString() : null,
  }));

  return {
    data,
    pagination: {
      totalItems: total,
      nextCursor: offset + data.length < total ? encodeCursor(offset + data.length) : null,
    },
  };
}

async function listMachines(options = {}) {
  await migrateOnce();
  const collisions = new Set(await collidingNames());
  const term = typeof options.query === 'string' ? options.query.trim() : '';

  const where = [];
  const params = [];
  if (term) {
    params.push(`%${term}%`);
    where.push(`search_blob ILIKE $${params.length}`);
  }
  const selectedKeys = cleanKeys(options.machineKeys);
  if (selectedKeys.length > 0) {
    params.push(selectedKeys);
    where.push(`machine_key = ANY($${params.length})`);
  }
  if (options.duplicates) where.push('agent_count > 1');
  if (options.collisions && collisions.size > 0) {
    params.push([...collisions]);
    where.push(`EXISTS (SELECT 1 FROM unnest(name_list) AS n WHERE n = ANY($${params.length}))`);
  } else if (options.collisions) {
    where.push('FALSE');
  }
  if (typeof options.site === 'string' && options.site.trim()) {
    params.push(`%${options.site.trim()}%`);
    where.push(`EXISTS (SELECT 1 FROM jsonb_array_elements(agents) AS a WHERE a ->> 'site' ILIKE $${params.length})`);
  }
  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const countResult = await query(
    `${MACHINES_CTE} SELECT COUNT(*)::int AS total FROM machines ${whereSql}`,
    params,
  );
  const total = countResult.rows[0].total;

  const limit = clampLimit(options.limit, options.maxLimit || MAX_LIMIT);
  const offset = decodeCursor(options.cursor);
  const pageParams = [...params, limit, offset];
  const { rows } = await query(
    `${MACHINES_CTE}
     SELECT machine_key, agent_count, online_count, decommissioned_count, infected,
            last_active_at, registered_at, name_list, agents
       FROM machines
       ${whereSql}
      ORDER BY (agent_count > 1) DESC, last_active_at DESC NULLS LAST, names ASC, machine_key ASC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    pageParams,
  );

  const summaryResult = await query(
    `${MACHINES_CTE}
     SELECT
       (SELECT COUNT(*)::int FROM machines) AS machines,
       (SELECT COALESCE(SUM(agent_count), 0)::int FROM machines) AS agents,
       (SELECT COUNT(*)::int FROM machines WHERE agent_count > 1) AS duplicates`,
    [],
  );
  const summaryRow = summaryResult.rows[0] || {};

  const data = rows.map((row) => {
    const machine = machineSummary(row);
    machine.nameCollision = machine.nameList.some((name) => collisions.has(name));
    machine.tags = [];
    return machine;
  });

  const tags = await tagsByMachine(data.map((machine) => machine.machineKey));
  for (const machine of data) machine.tags = tags.get(machine.machineKey) || [];

  return {
    data,
    pagination: {
      totalItems: total,
      nextCursor: offset + data.length < total ? encodeCursor(offset + data.length) : null,
    },
    summary: {
      machines: summaryRow.machines || 0,
      agents: summaryRow.agents || 0,
      duplicates: summaryRow.duplicates || 0,
      nameCollisions: collisions.size,
      nameCollisionNames: [...collisions],
    },
  };
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

// ── Heatmap jour × heure (dashboard) ────────────────────────────────────────
// Agrégat SQL direct sur created_at (UTC), aligné sur la fenêtre renvoyée par
// buildHeatmap : les cellules hors fenêtre sont écartées côté constructeur.
// Les expressions de gravité doivent rester alignées sur SEVERITY_RANK de
// src/sentinelone/stats.js (couvert par tests/stats.test.js).
const HEATMAP_TABLES = { threats: 'threats', alerts: 'alerts', activities: 'activities' };

async function heatmap(entity, range, now = new Date()) {
  await migrateOnce();
  const table = HEATMAP_TABLES[entity] || 'threats';
  const start = heatmapStart(range, now);
  const severity =
    table === 'activities'
      ? ''
      : `,
      max(CASE lower(severity)
            WHEN 'critical' THEN 5
            WHEN 'high' THEN 4
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 2
            WHEN 'info' THEN 1
            ELSE 0
          END)::int AS rank`;

  const result = await query(
    `SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
            (EXTRACT(HOUR FROM created_at AT TIME ZONE 'UTC'))::int AS hour,
            count(*)::int AS count${severity}
     FROM ${table}
     WHERE created_at >= $1
     GROUP BY 1, 2`,
    [start.toISOString()],
  );

  return result.rows.map((row) => ({
    at: `${row.day}T${String(row.hour).padStart(2, '0')}:00:00.000Z`,
    count: row.count,
    severity: row.rank === null || row.rank === undefined ? null : RANK_SEVERITY[row.rank] || 'unknown',
  }));
}

// ── Radar de posture (dashboard) ────────────────────────────────────────────
// Six ratios max : chaque valeur est un compteur réel, jamais une estimation.
// Les prédicats reproduisent isActiveThreat / isOpenAlert / le filtre en ligne
// de overviewCounts — si ces règles bougent, les deux côtés bougent ensemble.
async function radarCounts() {
  await migrateOnce();

  const [agents, activeThreats, threats, alerts, applications] = await Promise.all([
    query(`
      WITH top AS (
        SELECT version
        FROM agents
        WHERE version <> ''
        GROUP BY version
        ORDER BY count(*) DESC, version DESC
        LIMIT 1
      )
      SELECT (SELECT count(*) FROM agents)::int AS total,
             (SELECT count(*) FROM agents
              WHERE lower(coalesce(raw->>'isActive', 'true')) <> 'false'
                AND lower(coalesce(raw->>'isDecommissioned', 'false')) <> 'true'
                AND lower(coalesce(raw->>'networkStatus', '')) IN ('connected', 'online'))::int AS online,
             COALESCE((SELECT count(*) FROM agents a JOIN top t ON a.version = t.version), 0)::int AS aligned
    `),
    query(`
      SELECT count(DISTINCT agent_id)::int AS n
      FROM threats
      WHERE agent_id IS NOT NULL AND agent_id <> ''
        AND lower(coalesce(incident_status, '')) NOT IN ('resolved', 'closed')
        AND lower(coalesce(mitigation_status, '')) NOT IN ('mitigated', 'marked_as_benign', 'benign')
    `),
    query(`
      SELECT count(*)::int AS total,
             (count(*) FILTER (
               WHERE lower(coalesce(mitigation_status, '')) IN ('mitigated', 'marked_as_benign', 'benign')
             ))::int AS mitigated
      FROM threats
    `),
    query(`
      SELECT count(*)::int AS total,
             (count(*) FILTER (
               WHERE lower(coalesce(
                 nullif(raw->>'status', ''),
                 raw#>>'{alertInfo,status}',
                 raw#>>'{alertInfo,incidentStatus}',
                 ''
               )) IN ('resolved', 'closed', 'dismissed')
             ))::int AS closed
      FROM alerts
    `),
    query(`SELECT count(DISTINCT agent_id)::int AS covered FROM endpoint_applications`).catch(() => ({
      rows: [{ covered: 0 }],
    })),
  ]);

  const agentRow = agents.rows[0] || {};
  const threatRow = threats.rows[0] || {};
  const alertRow = alerts.rows[0] || {};

  return {
    agents: {
      total: agentRow.total || 0,
      online: agentRow.online || 0,
      aligned: agentRow.aligned || 0,
      activeThreatAgents: activeThreats.rows[0] ? activeThreats.rows[0].n || 0 : 0,
    },
    threats: { total: threatRow.total || 0, mitigated: threatRow.mitigated || 0 },
    alerts: { total: alertRow.total || 0, closed: alertRow.closed || 0 },
    applications: { covered: applications.rows[0] ? applications.rows[0].covered || 0 : 0 },
  };
}

module.exports = {
  listAgents,
  getAgentsByIds,
  endpointSummary,
  listMachines,
  addMachineTags,
  removeMachineTags,
  getAgent,
  getAgentHistory,
  listThreats,
  getThreat,
  listThreatNotes,
  listCloudAlerts,
  listAlerts,
  listActivities,
  listApplications,
  applicationsStatus,
  overviewCounts,
  heatmap,
  radarCounts,
};

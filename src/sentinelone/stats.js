'use strict';

// Statistiques agrégées du tableau de bord : heatmap jour × heure et radar de
// posture. Les deux constructeurs sont purs — entrées = seaux déjà agrégés
// (SQL quand la base est active, échantillon sinon), sortie = payload JSON —
// afin que les deux chemins produisent exactement le même contrat.
//
// Aucun axe du radar n'est inventé : chaque valeur est un ratio de compteurs
// réels (renseignés par les listes SentinelOne / les agrégats SQL). Quand le
// dénominateur est nul, l'axe est `available: false` et `value: null` plutôt
// qu'un 0 % mensonger.

const { isActiveThreat, isOpenAlert } = require('./overview');

const HEATMAP_ENTITIES = ['threats', 'alerts', 'activities'];
const HEATMAP_RANGES = ['7d', '30d'];

const ENTITY_LABELS = {
  threats: 'menaces',
  alerts: 'alertes',
  activities: 'activités',
};

const ENTITY_DATE_FIELDS = {
  threats: 'createdAt',
  alerts: 'detectedAt',
  activities: 'createdAt',
};

// Doit rester aligné sur le CASE SQL de db/store.heatmap() (commentaire dupliqué
// volontairement : les deux côtés sont testés ensemble dans tests/stats.test.js).
const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
const RANK_SEVERITY = { 5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info', 0: 'unknown' };

const MITIGATED_STATUSES = ['mitigated', 'marked_as_benign', 'benign'];

function heatmapDays(range, now = new Date()) {
  const count = range === '30d' ? 30 : 7;
  const base = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const days = [];
  for (let index = count - 1; index >= 0; index -= 1) {
    days.push(new Date(base - index * 86400000).toISOString().slice(0, 10));
  }
  return days;
}

// Minuit UTC du premier jour de la fenêtre : limite SQL strictement alignée sur
// la liste `days` renvoyée au front (pas de décalage d'une journée).
function heatmapStart(range, now = new Date()) {
  return new Date(`${heatmapDays(range, now)[0]}T00:00:00.000Z`);
}

// Lignes normalisées (échantillon) → seaux pour buildHeatmap.
function sampleBuckets(entity, rows) {
  const field = ENTITY_DATE_FIELDS[entity] || 'createdAt';
  return (rows || []).map((row) => ({
    at: row[field] || null,
    severity: row.severity || null,
  }));
}

function buildHeatmap({ entity = 'threats', range = '7d', buckets = [], sampled = false, now = new Date() }) {
  const days = heatmapDays(range, now);
  const allowed = new Set(days);
  const cells = new Map();
  let total = 0;

  for (const bucket of buckets) {
    const at = bucket && bucket.at ? new Date(bucket.at) : null;
    if (!at || Number.isNaN(at.getTime())) continue;
    const day = at.toISOString().slice(0, 10);
    if (!allowed.has(day)) continue;

    const count = Number(bucket.count) || 1;
    if (count <= 0) continue;
    total += count;

    const hour = at.getUTCHours();
    const key = `${day}:${hour}`;
    let cell = cells.get(key);
    if (!cell) {
      cell = { day, hour, count: 0, severity: null, rank: -1 };
      cells.set(key, cell);
    }
    cell.count += count;

    const known = Boolean(bucket.severity) && bucket.severity in SEVERITY_RANK;
    const rank = known ? SEVERITY_RANK[bucket.severity] : -1;
    if (rank > cell.rank) {
      cell.rank = rank;
      cell.severity = known ? bucket.severity : null;
    }
  }

  const list = [...cells.values()]
    .map((cell) => ({ day: cell.day, hour: cell.hour, count: cell.count, severity: cell.severity }))
    .sort((left, right) => (left.day === right.day ? left.hour - right.hour : left.day < right.day ? -1 : 1));

  return {
    entity,
    entityLabel: ENTITY_LABELS[entity] || entity,
    range,
    sampled,
    generatedAt: now.toISOString(),
    days,
    hours: Array.from({ length: 24 }, (_, hour) => hour),
    cells: list,
    max: list.reduce((peak, cell) => Math.max(peak, cell.count), 0),
    total,
  };
}

const RADAR_AXES = [
  { key: 'online', label: 'Agents en ligne', empty: 'Aucun endpoint enregistré' },
  { key: 'clean', label: 'Parc sans menace active', empty: 'Aucun endpoint enregistré' },
  { key: 'aligned', label: 'Version majoritaire', empty: 'Aucune version connue' },
  { key: 'mitigated', label: 'Menaces atténuées', empty: 'Aucune menace enregistrée' },
  { key: 'closed', label: 'Alertes clôturées', empty: 'Aucune alerte enregistrée' },
  { key: 'inventoried', label: 'Inventaire applicatif', empty: 'Inventaire non synchronisé' },
];

function axisValue(definition, numerator, denominator, detail, forceUnavailable = false) {
  const den = Number(denominator) || 0;
  const num = Number(numerator) || 0;
  const available = !forceUnavailable && den > 0;
  return {
    key: definition.key,
    label: definition.label,
    available,
    numerator: num,
    denominator: den,
    value: available ? Math.round((num / den) * 100) : null,
    detail: available ? detail : definition.empty,
  };
}

// counts : { agents: {total, online, aligned, activeThreatAgents},
//             threats: {total, mitigated}, alerts: {total, closed},
//             applications: {covered} }
function buildRadar({ counts = {}, sampled = false, now = new Date() }) {
  const agents = counts.agents || {};
  const threats = counts.threats || {};
  const alerts = counts.alerts || {};
  const applications = counts.applications || {};

  const agentsTotal = Number(agents.total) || 0;
  const agentsOnline = Number(agents.online) || 0;
  const agentsAligned = Number(agents.aligned) || 0;
  const activeThreatAgents = Number(agents.activeThreatAgents) || 0;
  const threatsTotal = Number(threats.total) || 0;
  const threatsMitigated = Number(threats.mitigated) || 0;
  const alertsTotal = Number(alerts.total) || 0;
  const alertsClosed = Number(alerts.closed) || 0;
  const applicationsCovered = Number(applications.covered) || 0;

  const axes = [
    axisValue(
      RADAR_AXES[0],
      agentsOnline,
      agentsTotal,
      `${agentsOnline} / ${agentsTotal} endpoints connectés`,
    ),
    axisValue(
      RADAR_AXES[1],
      Math.max(agentsTotal - activeThreatAgents, 0),
      agentsTotal,
      `${Math.max(agentsTotal - activeThreatAgents, 0)} / ${agentsTotal} sans menace active`,
    ),
    axisValue(
      RADAR_AXES[2],
      agentsAligned,
      agentsTotal,
      `${agentsAligned} / ${agentsTotal} sur la version la plus répandue`,
      agentsAligned === 0,
    ),
    axisValue(
      RADAR_AXES[3],
      threatsMitigated,
      threatsTotal,
      `${threatsMitigated} / ${threatsTotal} menaces atténuées`,
    ),
    axisValue(RADAR_AXES[4], alertsClosed, alertsTotal, `${alertsClosed} / ${alertsTotal} alertes clôturées`),
    axisValue(
      RADAR_AXES[5],
      applicationsCovered,
      agentsTotal,
      `${applicationsCovered} / ${agentsTotal} endpoints avec inventaire`,
      applicationsCovered === 0,
    ),
  ];

  const values = axes.filter((axis) => axis.available).map((axis) => axis.value);
  const score = values.length
    ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
    : null;

  return {
    generatedAt: now.toISOString(),
    sampled,
    score,
    axes,
    counts: {
      agents: {
        total: agentsTotal,
        online: agentsOnline,
        aligned: agentsAligned,
        activeThreatAgents,
      },
      threats: { total: threatsTotal, mitigated: threatsMitigated },
      alerts: { total: alertsTotal, closed: alertsClosed },
      applications: { covered: applicationsCovered },
    },
  };
}

// Compteurs échantillon (sans base) : mêmes sémantiques que src/sentinelone/overview.js.
function sampleRadarCounts({ agents = [], threats = [], alerts = [] }) {
  const versions = new Map();
  for (const agent of agents) {
    const version = String(agent.version || '').trim();
    if (!version) continue;
    versions.set(version, (versions.get(version) || 0) + 1);
  }
  let mode = null;
  let modeCount = 0;
  for (const [version, count] of versions) {
    if (count > modeCount) {
      mode = version;
      modeCount = count;
    }
  }

  const activeThreatAgents = new Set(
    threats
      .filter((threat) => isActiveThreat(threat))
      .map((threat) => threat.agentId)
      .filter(Boolean),
  );

  return {
    agents: {
      total: agents.length,
      online: agents.filter((agent) => agent.online).length,
      aligned: mode ? modeCount : 0,
      activeThreatAgents: activeThreatAgents.size,
    },
    threats: {
      total: threats.length,
      mitigated: threats.filter((threat) =>
        MITIGATED_STATUSES.includes(String(threat.mitigationStatus || '').toLowerCase()),
      ).length,
    },
    alerts: {
      total: alerts.length,
      closed: alerts.filter((alert) => !isOpenAlert(alert)).length,
    },
    // Pas d'inventaire applicatif sans base : l'axe est déclaré indisponible
    // plutôt que d'afficher 0 %.
    applications: { covered: 0 },
  };
}

module.exports = {
  HEATMAP_ENTITIES,
  HEATMAP_RANGES,
  ENTITY_LABELS,
  SEVERITY_RANK,
  RANK_SEVERITY,
  heatmapDays,
  heatmapStart,
  sampleBuckets,
  buildHeatmap,
  buildRadar,
  sampleRadarCounts,
};

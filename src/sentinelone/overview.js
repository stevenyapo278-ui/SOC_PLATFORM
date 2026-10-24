'use strict';

const {
  SEVERITY_ORDER,
  countBySeverity,
  normalizeAgent,
  normalizeThreat,
  normalizeAlert,
  normalizeActivity,
} = require('./normalize');

function totalOf(page, fallbackLength) {
  const total = page && page.pagination ? Number(page.pagination.totalItems) : NaN;
  return Number.isFinite(total) ? total : fallbackLength;
}

function isOpenAlert(alert) {
  const status = String(alert.status || '').toLowerCase();
  return !['resolved', 'closed', 'dismissed'].includes(status);
}

function isActiveThreat(threat) {
  const incident = String(threat.incidentStatus || '').toLowerCase();
  const mitigation = String(threat.mitigationStatus || '').toLowerCase();
  if (['resolved', 'closed'].includes(incident)) return false;
  if (['mitigated', 'marked_as_benign', 'benign'].includes(mitigation)) return false;
  return true;
}

function dayKey(date) {
  return date.toISOString().slice(0, 10);
}

// Compteurs { 'AAAA-MM-JJ': n } → les 7 seaux du graphique (UTC).
// Utilisé par buildThreatTrend (échantillon) et par les agrégats SQL exacts.
function buildTrendBuckets(dayCounts, now, days = 7) {
  const labels = [];
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(start);
    d.setUTCDate(start.getUTCDate() - i);
    labels.push(dayKey(d));
  }
  return labels.map((date) => ({ date, count: Number(dayCounts[date]) || 0 }));
}

function buildThreatTrend(threats, now, days = 7) {
  const counts = {};
  for (const threat of threats) {
    if (!threat.createdAt) continue;
    const parsed = new Date(threat.createdAt);
    if (Number.isNaN(parsed.getTime())) continue;
    const key = dayKey(parsed);
    counts[key] = (counts[key] || 0) + 1;
  }
  return buildTrendBuckets(counts, now, days);
}

// `exact` : agrégats SQL fournis par db/store.overviewCounts() quand la base est
// active. Les totaux et sous-compteurs deviennent alors exacts à toute taille de
// parc (pas d'échantillon, donc plus de « ≈ » sur le tableau de bord).
function buildOverview({
  agentsPage,
  threatsPage,
  alertsPage,
  activitiesPage,
  warnings = [],
  sampleLimit,
  now = new Date(),
  exact = null,
}) {
  const agents = (agentsPage && agentsPage.data ? agentsPage.data : []).map(normalizeAgent);
  const threats = (threatsPage && threatsPage.data ? threatsPage.data : []).map(normalizeThreat);
  const alerts = (alertsPage && alertsPage.data ? alertsPage.data : []).map(normalizeAlert);
  const activities = (activitiesPage && activitiesPage.data ? activitiesPage.data : []).map(normalizeActivity);

  const agentsTotal = totalOf(agentsPage, agents.length);
  const threatsTotal = totalOf(threatsPage, threats.length);
  const alertsTotal = totalOf(alertsPage, alerts.length);

  // Un endpoint infecté reste « en ligne » : les deux indicateurs sont indépendants.
  const online = agents.filter((agent) => agent.online).length;
  const infected = agents.filter((agent) => agent.infected).length;
  const decommissioned = agents.filter((agent) => agent.status === 'decommissioned').length;
  const openAlerts = alerts.filter(isOpenAlert).length;
  const activeThreats = threats.filter(isActiveThreat).length;
  const highCritical = threats.filter((t) => t.severity === 'critical' || t.severity === 'high').length;

  const useExact = Boolean(exact && exact.agents && exact.threats && exact.alerts);

  return {
    generatedAt: now.toISOString(),
    sampleLimit,
    kpis: useExact
      ? {
          agentsTotal: exact.agents.total,
          agentsOnline: exact.agents.online,
          agentsOfflineSample: exact.agents.offline,
          agentsDecommissionedSample: exact.agents.decommissioned,
          agentsInfectedSample: exact.agents.infected,
          threatsTotal: exact.threats.total,
          threatsActiveSample: exact.threats.active,
          threatsHighCriticalSample: exact.threats.highCritical,
          alertsTotal: exact.alerts.total,
          alertsOpenSample: exact.alerts.open,
        }
      : {
          agentsTotal,
          agentsOnline: online,
          agentsOfflineSample: agents.filter((a) => a.status === 'offline').length,
          agentsDecommissionedSample: decommissioned,
          agentsInfectedSample: infected,
          threatsTotal,
          threatsActiveSample: activeThreats,
          threatsHighCriticalSample: highCritical,
          alertsTotal,
          alertsOpenSample: openAlerts,
        },
    sampled: useExact
      ? { agents: false, threats: false, alerts: false }
      : {
          agents: agents.length < agentsTotal,
          threats: threats.length < threatsTotal,
          alerts: alerts.length < alertsTotal,
        },
    severity: useExact ? exact.severity : countBySeverity(threats),
    severityOrder: SEVERITY_ORDER,
    threatTrend: useExact ? buildTrendBuckets(exact.trend, now) : buildThreatTrend(threats, now),
    recentThreats: threats.slice(0, 6),
    recentAlerts: alerts.slice(0, 6),
    recentActivities: activities.slice(0, 8),
    warnings,
  };
}

module.exports = { buildOverview, buildThreatTrend, buildTrendBuckets, isOpenAlert, isActiveThreat };

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

function buildThreatTrend(threats, now, days = 7) {
  const buckets = new Map();
  const labels = [];
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(start);
    d.setUTCDate(start.getUTCDate() - i);
    const key = dayKey(d);
    buckets.set(key, 0);
    labels.push(key);
  }
  for (const threat of threats) {
    if (!threat.createdAt) continue;
    const parsed = new Date(threat.createdAt);
    if (Number.isNaN(parsed.getTime())) continue;
    const key = dayKey(parsed);
    if (buckets.has(key)) buckets.set(key, buckets.get(key) + 1);
  }
  return labels.map((date) => ({ date, count: buckets.get(date) }));
}

function buildOverview({ agentsPage, threatsPage, alertsPage, activitiesPage, warnings = [], sampleLimit, now = new Date() }) {
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

  return {
    generatedAt: now.toISOString(),
    sampleLimit,
    kpis: {
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
    sampled: {
      agents: agents.length < agentsTotal,
      threats: threats.length < threatsTotal,
      alerts: alerts.length < alertsTotal,
    },
    severity: countBySeverity(threats),
    severityOrder: SEVERITY_ORDER,
    threatTrend: buildThreatTrend(threats, now),
    recentThreats: threats.slice(0, 6),
    recentAlerts: alerts.slice(0, 6),
    recentActivities: activities.slice(0, 8),
    warnings,
  };
}

module.exports = { buildOverview, buildThreatTrend, isOpenAlert, isActiveThreat };

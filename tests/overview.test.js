'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildOverview, buildThreatTrend, isOpenAlert, isActiveThreat } = require('../src/sentinelone/overview');

function daysAgo(days, now) {
  const date = new Date(now);
  date.setUTCDate(date.getUTCDate() - days);
  return date.toISOString();
}

test('buildOverview aggregates KPIs, severity and recents', () => {
  const now = new Date('2026-10-23T12:00:00Z');
  const overview = buildOverview({
    agentsPage: {
      data: [
        { id: 'a1', computerName: 'PC-ALPHA', networkStatus: 'connected', isActive: true },
        { id: 'a2', computerName: 'SRV-BETA', networkStatus: 'connected', isActive: true, infected: true },
        { id: 'a3', computerName: 'PC-GAMMA', networkStatus: 'disconnected', isActive: true },
      ],
      pagination: { totalItems: 3, nextCursor: null },
    },
    threatsPage: {
      data: [
        { id: 't1', threatName: 'A', severity: 'Critical', incidentStatus: 'unresolved', createdAt: daysAgo(0, now) },
        { id: 't2', threatName: 'B', severity: 'High', mitigationStatus: 'mitigated', createdAt: daysAgo(1, now) },
        { id: 't3', threatName: 'C', severity: 'Low', createdAt: daysAgo(10, now) },
      ],
      pagination: { totalItems: 3, nextCursor: null },
    },
    alertsPage: {
      data: [
        { id: 'al1', status: 'OPEN', severity: 'High', detectedAt: daysAgo(0, now) },
        { id: 'al2', status: 'RESOLVED', severity: 'Low', detectedAt: daysAgo(2, now) },
      ],
      pagination: { totalItems: 2, nextCursor: null },
    },
    activitiesPage: { data: [{ id: 'act1', primaryDescription: 'Test' }], pagination: { totalItems: 1 } },
    warnings: [{ source: 'alerts', message: 'indisponible' }],
    sampleLimit: 500,
    now,
  });

  assert.equal(overview.kpis.agentsTotal, 3);
  assert.equal(overview.kpis.agentsOnline, 2);
  assert.equal(overview.kpis.agentsInfectedSample, 1);
  assert.equal(overview.kpis.threatsTotal, 3);
  assert.equal(overview.kpis.threatsActiveSample, 2);
  assert.equal(overview.kpis.threatsHighCriticalSample, 2);
  assert.equal(overview.kpis.alertsTotal, 2);
  assert.equal(overview.kpis.alertsOpenSample, 1);
  assert.deepEqual(overview.severity, { critical: 1, high: 1, medium: 0, low: 1, info: 0, unknown: 0 });
  assert.equal(overview.threatTrend.length, 7);
  assert.equal(overview.threatTrend.reduce((sum, point) => sum + point.count, 0), 2);
  assert.equal(overview.recentThreats.length, 3);
  assert.equal(overview.recentAlerts.length, 2);
  assert.equal(overview.warnings.length, 1);
  assert.equal(overview.sampled.agents, false);
});

test('buildOverview marks sampled collections when totals exceed the sample', () => {
  const now = new Date('2026-10-23T12:00:00Z');
  const overview = buildOverview({
    agentsPage: { data: [{ id: 'a1' }], pagination: { totalItems: 4000 } },
    threatsPage: { data: [{ id: 't1' }], pagination: { totalItems: 900 } },
    alertsPage: { data: [], pagination: { totalItems: 12 } },
    activitiesPage: { data: [], pagination: { totalItems: 0 } },
    sampleLimit: 500,
    now,
  });
  assert.equal(overview.sampled.agents, true);
  assert.equal(overview.sampled.threats, true);
  assert.equal(overview.sampled.alerts, true);
});

test('buildThreatTrend ignores invalid and out-of-window dates', () => {
  const now = new Date('2026-10-23T12:00:00Z');
  const trend = buildThreatTrend(
    [
      { createdAt: daysAgo(0, now) },
      { createdAt: 'not-a-date' },
      { createdAt: null },
      { createdAt: daysAgo(30, now) },
      { createdAt: daysAgo(2, now) },
    ],
    now,
  );
  assert.equal(trend.length, 7);
  assert.equal(trend[trend.length - 1].count, 1);
  assert.equal(trend[trend.length - 3].count, 1);
  assert.equal(trend.reduce((sum, point) => sum + point.count, 0), 2);
});

test('isOpenAlert and isActiveThreat classify statuses', () => {
  assert.equal(isOpenAlert({ status: 'OPEN' }), true);
  assert.equal(isOpenAlert({ status: 'resolved' }), false);
  assert.equal(isActiveThreat({ incidentStatus: 'unresolved', mitigationStatus: 'not_mitigated' }), true);
  assert.equal(isActiveThreat({ incidentStatus: 'resolved' }), false);
  assert.equal(isActiveThreat({ mitigationStatus: 'mitigated' }), false);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildIncidentTimeline, scopeLabel } = require('../src/services/incidentTimeline');

const iso = (value) => new Date(value).toISOString();

test('timeline : fusionne les quatre sources par ordre chronologique ascendant', () => {
  const out = buildIncidentTimeline({
    threats: [
      {
        id: 't1',
        name: 'Ransomware',
        severity: 'critical',
        mitigation_status: 'mitigated',
        analyst_verdict: 'true_positive',
        agent_name: 'WS-01',
        created_at: iso('2026-10-25T10:00:00Z'),
      },
    ],
    alerts: [
      {
        id: 'a1',
        name: 'Suspicious DNS',
        event_type: 'dns',
        severity: 'high',
        process_name: 'svchost',
        agent_name: 'WS-01',
        created_at: iso('2026-10-25T09:00:00Z'),
      },
    ],
    notes: [
      { id: 'n1', threat_id: 't1', text: 'Analyse en cours', creator: 'steven', created_at: iso('2026-10-25T11:00:00Z') },
    ],
    activities: [
      {
        id: 'x1',
        description: 'Menace atténuée',
        details: 'mitigation auto',
        user: 'admin',
        agent_name: 'WS-01',
        threat_id: 't1',
        created_at: iso('2026-10-25T12:00:00Z'),
      },
    ],
    scope: { kind: 'threat', threatId: 't1', threatName: 'Ransomware', agentName: 'WS-01' },
  });

  assert.equal(out.counts.events, 4);
  assert.deepEqual(out.events.map((e) => e.type), ['alert', 'detection', 'note', 'activity']);
  const times = out.events.map((e) => e.at);
  for (let i = 1; i < times.length; i += 1) assert.ok(times[i - 1] <= times[i], 'ordre croissant');
  assert.equal(out.events[0].typeLabel, 'Alerte');
  assert.equal(out.events[1].threatId, 't1');
  assert.equal(out.truncated, false);
  assert.equal(out.scope.label, 'Menace t1 (WS-01)');
  assert.match(out.summary, /Menace t1 \(WS-01\) : 1 détection, 1 alerte, 1 note et 1 activité/);
  assert.match(out.summary, /4 événements/);
});

test('timeline : tronque en gardant les événements les plus récents, ordre conservé', () => {
  const activities = Array.from({ length: 30 }, (_, i) => ({
    id: `x${i}`,
    description: `Act ${i}`,
    details: 'd',
    user: 'u',
    created_at: new Date(Date.UTC(2026, 9, 1, 0, i, 0)),
  }));
  const out = buildIncidentTimeline({
    activities,
    scope: { kind: 'agent', agentName: 'WS-01' },
    limit: 5,
  });

  assert.equal(out.counts.events, 30);
  assert.equal(out.events.length, 5);
  assert.equal(out.truncated, true);
  assert.equal(out.maxEvents, 5);
  assert.equal(out.events[0].title, 'Act 25');
  assert.equal(out.events[4].title, 'Act 29');
  assert.match(out.summary, /30 événements au total, 5 affichés/);
});

test('timeline : événements sans date en fin de série, détails tronqués', () => {
  const out = buildIncidentTimeline({
    activities: [
      { id: 'x1', description: 'Sans date', created_at: null },
      { id: 'x2', description: 'Avec date', created_at: iso('2026-10-25T08:00:00Z') },
    ],
    notes: [{ id: 'n1', text: 'x'.repeat(300), creator: 'steven', created_at: iso('2026-10-25T09:00:00Z') }],
    scope: { kind: 'agent', agentName: 'WS-01' },
  });

  assert.equal(out.events.length, 3);
  assert.equal(out.events[2].at, null);
  assert.equal(out.events[2].title, 'Sans date');
  assert.ok(out.events[1].detail.length <= 140, 'détail borné');
  assert.ok(out.events[1].detail.endsWith('…'));
  assert.equal(out.firstAt, iso('2026-10-25T08:00:00Z'));
  assert.equal(out.lastAt, iso('2026-10-25T09:00:00Z'));
});

test('timeline : aucune donnée → résumé à zéro et liste vide', () => {
  const out = buildIncidentTimeline({ scope: { kind: 'agent', agentName: 'WS-01' } });
  assert.deepEqual(out.events, []);
  assert.equal(out.truncated, false);
  assert.equal(out.firstAt, null);
  assert.equal(out.lastAt, null);
  assert.match(out.summary, /0 détection, 0 alerte, 0 note et 0 activité/);
});

test('scopeLabel : les trois périmètres et le repli', () => {
  assert.equal(scopeLabel({ threatId: 't1', agentName: 'WS-01' }), 'Menace t1 (WS-01)');
  assert.equal(scopeLabel({ storyline: 's-42' }), 'Storyline s-42');
  assert.equal(scopeLabel({ agentName: 'WS-01' }), 'Endpoint WS-01');
  assert.equal(scopeLabel({}), 'Périmètre inconnu');
  assert.equal(scopeLabel(null), 'Périmètre inconnu');
});

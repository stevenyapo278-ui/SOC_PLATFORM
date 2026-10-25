'use strict';

// Constructeurs purs des statistiques agrégées du tableau de bord : heatmap
// jour × heure et radar de posture. Le même constructeur sert le chemin SQL et
// le chemin « échantillon » — seul le drapeau `sampled` change.
//
// Garde-fou permanent : aucun axe du radar n'est inventé. Un dénominateur nul
// donne `available: false` + `value: null`, jamais un 0 % mensonger.

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  HEATMAP_ENTITIES,
  HEATMAP_RANGES,
  heatmapDays,
  heatmapStart,
  sampleBuckets,
  buildHeatmap,
  buildRadar,
  sampleRadarCounts,
} = require('../src/sentinelone/stats');

const NOW = new Date('2026-10-25T15:30:00Z');

test('heatmap : fenêtre UTC calée sur le jour courant', () => {
  assert.deepEqual(HEATMAP_ENTITIES, ['threats', 'alerts', 'activities']);
  assert.deepEqual(HEATMAP_RANGES, ['7d', '30d']);

  const days7 = heatmapDays('7d', NOW);
  assert.equal(days7.length, 7);
  assert.equal(days7[6], '2026-10-25');
  assert.equal(days7[0], '2026-10-19');
  assert.deepEqual(
    heatmapStart('7d', NOW),
    new Date('2026-10-19T00:00:00.000Z'),
    'la limite SQL tombe à minuit UTC du premier jour affiché',
  );

  const days30 = heatmapDays('30d', NOW);
  assert.equal(days30.length, 30);
  assert.equal(days30[29], '2026-10-25');
  assert.equal(days30[0], '2026-09-26');

  // Une plage inconnue retombe sur 7 jours plutôt que de casser la réponse.
  assert.equal(heatmapDays('90d', NOW).length, 7);
});

test('heatmap : agrégation par cellule, gravité maximale et recadrage', () => {
  const buckets = [
    { at: '2026-10-25T10:15:00Z', severity: 'high' },
    { at: '2026-10-25T10:45:00Z', severity: 'critical' },
    { at: '2026-10-25T10:05:00Z', severity: 'low' },
    { at: '2026-10-24T23:59:00Z', severity: 'medium' },
    { at: '2026-10-25T10:30:00Z', severity: null },
    // Hors fenêtre (8 jours avant) : écarté.
    { at: '2026-10-17T10:00:00Z', severity: 'critical' },
    // Dates invalides : écartées sans casser la réponse.
    { at: null, severity: 'high' },
    { at: 'pas-une-date', severity: 'high' },
  ];

  const payload = buildHeatmap({ entity: 'threats', range: '7d', buckets, now: NOW });

  assert.equal(payload.entity, 'threats');
  assert.equal(payload.entityLabel, 'menaces');
  assert.equal(payload.range, '7d');
  assert.equal(payload.sampled, false);
  assert.equal(payload.days.length, 7);
  assert.equal(payload.hours.length, 24);
  assert.deepEqual(payload.hours.slice(0, 3), [0, 1, 2]);

  // 5 cellules : 3 le 25/10 à 10h + 1 le 25/10 à 10h (null) + 1 le 24/10.
  assert.equal(payload.total, 5);
  assert.equal(payload.max, 4);

  const morning = payload.cells.find((cell) => cell.day === '2026-10-25' && cell.hour === 10);
  assert.equal(morning.count, 4, 'les occurrences se cumulent dans la cellule');
  assert.equal(morning.severity, 'critical', 'la gravité maximale de la cellule est retenue');

  const evening = payload.cells.find((cell) => cell.day === '2026-10-24' && cell.hour === 23);
  assert.equal(evening.count, 1);
  assert.equal(evening.severity, 'medium');

  assert.ok(
    payload.cells.every((cell) => payload.days.includes(cell.day)),
    'aucune cellule hors fenêtre',
  );
  const keys = payload.cells.map((cell) => `${cell.day}T${String(cell.hour).padStart(2, '0')}`);
  assert.deepEqual(keys, [...keys].sort(), 'les cellules sont triées par jour puis par heure');
});

test('heatmap : densité pondérée et entités sans gravité', () => {
  const weighted = buildHeatmap({
    entity: 'alerts',
    range: '7d',
    buckets: [{ at: '2026-10-25T06:00:00Z', severity: 'high', count: 7 }],
    now: NOW,
  });
  assert.equal(weighted.total, 7);
  assert.equal(weighted.max, 7);
  assert.equal(weighted.cells[0].count, 7);

  const empty = buildHeatmap({ entity: 'threats', range: '30d', buckets: [], now: NOW });
  assert.equal(empty.total, 0);
  assert.equal(empty.max, 0);
  assert.deepEqual(empty.cells, []);

  // Activités : aucune gravité, la cellule reste sans severity.
  const activities = buildHeatmap({
    entity: 'activities',
    range: '7d',
    buckets: [{ at: '2026-10-25T06:00:00Z', severity: null }],
    now: NOW,
  });
  assert.equal(activities.entityLabel, 'activités');
  assert.equal(activities.cells[0].severity, null);
  assert.equal(activities.cells[0].count, 1);

  // Le drapeau échantillon est simplement recopié.
  const sampled = buildHeatmap({ entity: 'threats', range: '7d', buckets: [], sampled: true, now: NOW });
  assert.equal(sampled.sampled, true);
});

test('heatmap : gravité inconnue = rang 0 (jamais confondue avec « sans gravité »)', () => {
  const payload = buildHeatmap({
    entity: 'threats',
    range: '7d',
    buckets: [
      { at: '2026-10-25T08:00:00Z', severity: 'unknown' },
      { at: '2026-10-25T08:30:00Z', severity: 'info' },
    ],
    now: NOW,
  });
  assert.equal(payload.cells[0].count, 2);
  assert.equal(payload.cells[0].severity, 'info', 'info (rang 1) l’emporte sur unknown (rang 0)');

  const onlyUnknown = buildHeatmap({
    entity: 'threats',
    range: '7d',
    buckets: [{ at: '2026-10-25T08:00:00Z', severity: 'unknown' }],
    now: NOW,
  });
  assert.equal(onlyUnknown.cells[0].severity, 'unknown', 'la cellule reste renseignée, pas null');
});

test('sampleBuckets : date et gravité selon l’entité', () => {
  assert.deepEqual(sampleBuckets('threats', [{ createdAt: '2026-10-25T01:00:00Z', severity: 'high' }]), [
    { at: '2026-10-25T01:00:00Z', severity: 'high' },
  ]);
  assert.deepEqual(sampleBuckets('alerts', [{ detectedAt: '2026-10-25T02:00:00Z', severity: 'low' }]), [
    { at: '2026-10-25T02:00:00Z', severity: 'low' },
  ]);
  assert.deepEqual(sampleBuckets('threats', [{ createdAt: null, severity: null }]), [
    { at: null, severity: null },
  ]);
  assert.deepEqual(sampleBuckets('activities', [{ createdAt: '2026-10-25T03:00:00Z' }]), [
    { at: '2026-10-25T03:00:00Z', severity: null },
  ]);
});

test('radar : ratios exacts, axes indisponibles et score', () => {
  const payload = buildRadar({
    counts: {
      agents: { total: 10, online: 8, aligned: 6, activeThreatAgents: 2 },
      threats: { total: 4, mitigated: 1 },
      alerts: { total: 5, closed: 2 },
      applications: { covered: 7 },
    },
    now: NOW,
  });

  assert.equal(payload.sampled, false);
  assert.equal(payload.axes.length, 6);

  const byKey = Object.fromEntries(payload.axes.map((axis) => [axis.key, axis]));
  assert.equal(byKey.online.value, 80);
  assert.equal(byKey.clean.value, 80, '10 − 2 endpoints sous menace active = 80 %');
  assert.equal(byKey.aligned.value, 60);
  assert.equal(byKey.mitigated.value, 25);
  assert.equal(byKey.closed.value, 40);
  assert.equal(byKey.inventoried.value, 70);

  // Détail chiffré en français, jamais une estimation.
  assert.equal(byKey.online.detail, '8 / 10 endpoints connectés');
  assert.equal(byKey.mitigated.detail, '1 / 4 menaces atténuées');
  assert.equal(byKey.inventoried.detail, '7 / 10 endpoints avec inventaire');

  // score = moyenne des axes disponibles.
  assert.equal(payload.score, Math.round((80 + 80 + 60 + 25 + 40 + 70) / 6));

  assert.deepEqual(payload.counts, {
    agents: { total: 10, online: 8, aligned: 6, activeThreatAgents: 2 },
    threats: { total: 4, mitigated: 1 },
    alerts: { total: 5, closed: 2 },
    applications: { covered: 7 },
  });
});

test('radar : dénominateur nul ⇒ axe indisponible, jamais 0 %', () => {
  const payload = buildRadar({
    counts: {
      agents: { total: 0, online: 0, aligned: 0, activeThreatAgents: 0 },
      threats: { total: 0, mitigated: 0 },
      alerts: { total: 0, closed: 0 },
      applications: { covered: 0 },
    },
    now: NOW,
  });

  assert.equal(payload.score, null, 'sans axe exploitable, pas de score');
  for (const axis of payload.axes) {
    assert.equal(axis.available, false, `${axis.key} doit être indisponible`);
    assert.equal(axis.value, null);
    assert.ok(axis.detail.length > 0, 'un motif FR explique l’indisponibilité');
  }
  assert.equal(
    payload.axes.find((axis) => axis.key === 'inventoried').detail,
    'Inventaire non synchronisé',
  );

  // Inventaire vide alors que le parc existe : idem, pas de faux 0 %.
  const noApps = buildRadar({
    counts: {
      agents: { total: 5, online: 5, aligned: 5, activeThreatAgents: 0 },
      threats: { total: 0, mitigated: 0 },
      alerts: { total: 0, closed: 0 },
      applications: { covered: 0 },
    },
    now: NOW,
  });
  assert.equal(noApps.axes.find((axis) => axis.key === 'inventoried').available, false);
  assert.equal(noApps.axes.find((axis) => axis.key === 'online').value, 100);
  assert.equal(noApps.axes.find((axis) => axis.key === 'mitigated').available, false);
  assert.equal(noApps.score, 100, 'seuls les axes exploitables comptent dans le score');
});

test('sampleRadarCounts : mêmes prédicats que l’aperçu (échantillon)', () => {
  const counts = sampleRadarCounts({
    agents: [
      { online: true, version: '24.1.2' },
      { online: true, version: '24.1.2' },
      { online: false, version: '23.4.1' },
      { online: false, version: '' },
    ],
    threats: [
      { agentId: 'a1', mitigationStatus: 'not_mitigated', incidentStatus: 'unresolved' },
      { agentId: 'a2', mitigationStatus: 'mitigated', incidentStatus: 'resolved' },
      { agentId: 'a1', mitigationStatus: '—', incidentStatus: '—' },
      { agentId: 'a3', mitigationStatus: 'marked_as_benign', incidentStatus: 'unresolved' },
    ],
    alerts: [{ status: 'unresolved' }, { status: 'resolved' }, { status: 'dismissed' }, { status: 'closed' }],
  });

  assert.equal(counts.agents.total, 4);
  assert.equal(counts.agents.online, 2);
  assert.equal(counts.agents.aligned, 2, 'version majoritaire = 24.1.2 (2 occurrences)');
  assert.equal(counts.agents.activeThreatAgents, 1, 'seul a1 porte une menace active');

  assert.equal(counts.threats.total, 4);
  assert.equal(counts.threats.mitigated, 2, 'mitigated + marked_as_benign');

  assert.equal(counts.alerts.total, 4);
  assert.equal(counts.alerts.closed, 3, 'resolved + dismissed + closed');

  assert.equal(counts.applications.covered, 0, 'pas d’inventaire sans base : axe indisponible');
});

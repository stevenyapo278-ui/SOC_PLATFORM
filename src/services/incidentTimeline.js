'use strict';

// Timeline d'incident — fusion pure (détections, alertes, notes, activités)
// en une chronologie ascendante. Sans base ni S1 : testable isolément (tests/timeline.test.js).

const TYPE_LABELS = {
  detection: 'Détection',
  alert: 'Alerte',
  note: 'Note',
  activity: 'Activité',
};

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function truncate(text, max) {
  const value = String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function atOf(value) {
  if (!value) return null;
  const ms = value instanceof Date ? value.getTime() : Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function frDate(ms) {
  if (ms == null) return 'date inconnue';
  return new Date(ms).toISOString().substring(0, 10);
}

function joinFr(items) {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} et ${items[items.length - 1]}`;
}

function plural(count, word) {
  return `${count} ${word}${count > 1 ? 's' : ''}`;
}

function scopeLabel(scope) {
  if (!scope) return 'Périmètre inconnu';
  if (scope.threatId) return `Menace ${scope.threatId}${scope.agentName ? ` (${scope.agentName})` : ''}`;
  if (scope.storyline) return `Storyline ${scope.storyline}${scope.agentName ? ` (${scope.agentName})` : ''}`;
  if (scope.agentName) return `Endpoint ${scope.agentName}`;
  return 'Périmètre inconnu';
}

// ── Construction de la chronologie ───────────────────────────────────────────
function buildIncidentTimeline({ threats = [], alerts = [], notes = [], activities = [], scope = {}, limit = 25 } = {}) {
  const maxEvents = clampInt(limit, 5, 60, 25);
  const events = [];

  for (const t of threats) {
    events.push({
      at: atOf(t.created_at),
      type: 'detection',
      typeLabel: TYPE_LABELS.detection,
      severity: t.severity || 'unknown',
      title: truncate(t.name || 'Menace', 90),
      detail: truncate([t.severity, t.mitigation_status, t.analyst_verdict, t.agent_name].filter(Boolean).join(' · '), 140),
      threatId: t.id || null,
      agentName: t.agent_name || null,
    });
  }

  for (const a of alerts) {
    events.push({
      at: atOf(a.created_at),
      type: 'alert',
      typeLabel: TYPE_LABELS.alert,
      severity: a.severity || 'unknown',
      title: truncate(a.name || a.event_type || 'Alerte', 90),
      detail: truncate([a.event_type, a.severity, a.process_name].filter(Boolean).join(' · '), 140),
      threatId: null,
      agentName: a.agent_name || null,
    });
  }

  for (const n of notes) {
    events.push({
      at: atOf(n.created_at),
      type: 'note',
      typeLabel: TYPE_LABELS.note,
      severity: null,
      title: truncate(`Note de ${n.creator || 'analyste'}`, 90),
      detail: truncate(n.text, 140),
      threatId: n.threat_id || null,
      agentName: null,
    });
  }

  for (const act of activities) {
    events.push({
      at: atOf(act.created_at),
      type: 'activity',
      typeLabel: TYPE_LABELS.activity,
      severity: null,
      title: truncate(act.description || 'Activité', 90),
      detail: truncate([act.user, act.details].filter(Boolean).join(' · '), 140),
      threatId: act.threat_id || null,
      agentName: act.agent_name || null,
    });
  }

  // Ordre chronologique ascendant ; les dates inconnues (null) ferment la série.
  events.sort((a, b) => {
    if (a.at == null && b.at == null) return 0;
    if (a.at == null) return 1;
    if (b.at == null) return -1;
    return a.at - b.at;
  });

  const counts = {
    detections: threats.length,
    alerts: alerts.length,
    notes: notes.length,
    activities: activities.length,
    events: events.length,
  };

  let kept = events;
  let truncated = false;
  if (events.length > maxEvents) {
    kept = events.slice(events.length - maxEvents);
    truncated = true;
  }

  const dated = kept.map((e) => e.at).filter((at) => at != null);
  const firstAt = dated.length ? new Date(Math.min(...dated)).toISOString() : null;
  const lastAt = dated.length ? new Date(Math.max(...dated)).toISOString() : null;

  const parts = [
    plural(counts.detections, 'détection'),
    plural(counts.alerts, 'alerte'),
    plural(counts.notes, 'note'),
    plural(counts.activities, 'activité'),
  ];
  const period = firstAt && lastAt ? ` entre le ${frDate(atOf(firstAt))} et le ${frDate(atOf(lastAt))}` : '';
  const summary =
    `${scopeLabel(scope)} : ${joinFr(parts)}${period}` +
    ` (${plural(counts.events, 'événement')} au total${truncated ? `, ${kept.length} affichés` : ''}).`;

  return {
    scope: { ...scope, label: scopeLabel(scope) },
    counts,
    firstAt,
    lastAt,
    truncated,
    maxEvents,
    summary,
    events: kept,
  };
}

module.exports = { buildIncidentTimeline, TYPE_LABELS, scopeLabel };

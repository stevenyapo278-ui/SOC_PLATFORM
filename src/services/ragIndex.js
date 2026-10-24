'use strict';

// Indexation RAG : synthèse de chaque entité synchro → embedding → table embeddings.
// Déclenchée après chaque runSync (si un modèle EMBEDDING est configuré).
// Idempotent : re-indexe seulement si le contenu a changé (hash SHA-256 du texte).

const { query } = require('../db');
const log = require('../logger');
const { generateEmbedding, toVectorLiteral } = require('../ai/embeddings');
const { buildEmbeddingContent } = require('./embeddings');
const { normalizeThreatDetail, normalizeCloudAlert, normalizeThreatNote, normalizeActivity } = require('../sentinelone/normalize');

const BATCH_LIMIT = 200;

function contentHash(text) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(text).digest('hex');
}

async function upsertEmbedding(entityType, entityId, content, vector, model) {
  await query(
    `INSERT INTO embeddings (entity_type, entity_id, content, embedding, model)
     VALUES ($1, $2, $3, $4::vector, $5)
     ON CONFLICT (entity_type, entity_id) DO UPDATE SET
       content = EXCLUDED.content,
       embedding = EXCLUDED.embedding,
       model = EXCLUDED.model,
       embedded_at = now()`,
    [entityType, entityId, content, toVectorLiteral(vector), model || ''],
  );
}

// Entité déjà indexée avec le même contenu ? (évitement d'appel API inutile)
async function needsEmbedding(entityType, entityId, content) {
  const { rows } = await query(
    `SELECT content FROM embeddings WHERE entity_type = $1 AND entity_id = $2`,
    [entityType, entityId],
  );
  if (rows.length === 0) return true;
  return rows[0].content !== content;
}

async function indexThreats() {
  const { rows } = await query(
    `SELECT id, raw FROM threats WHERE synced_at > now() - interval '2 days' ORDER BY updated_at DESC NULLS LAST LIMIT ${BATCH_LIMIT}`,
  );
  let indexed = 0;
  let skipped = 0;
  for (const row of rows) {
    try {
      const detail = normalizeThreatDetail(row.raw);
      const content = buildEmbeddingContent('threat', detail);
      if (!content || !(await needsEmbedding('threat', row.id, content))) {
        skipped += 1;
        continue;
      }
      const vector = await generateEmbedding(content, 'RETRIEVAL_DOCUMENT');
      await upsertEmbedding('threat', row.id, content, vector);
      indexed += 1;
    } catch (error) {
      log.warn('Indexation menace impossible', { threatId: row.id, error: error.message });
      break; // provider indisponible → on arrête le batch, on reprendra au prochain run
    }
  }
  return { indexed, skipped };
}

async function indexAlerts() {
  const { rows } = await query(
    `SELECT id, raw FROM alerts WHERE synced_at > now() - interval '2 days' ORDER BY created_at DESC NULLS LAST LIMIT ${BATCH_LIMIT}`,
  );
  let indexed = 0;
  let skipped = 0;
  for (const row of rows) {
    try {
      const alert = normalizeCloudAlert(row.raw);
      const content = buildEmbeddingContent('alert', alert);
      if (!content || !(await needsEmbedding('alert', row.id, content))) {
        skipped += 1;
        continue;
      }
      const vector = await generateEmbedding(content, 'RETRIEVAL_DOCUMENT');
      await upsertEmbedding('alert', row.id, content, vector);
      indexed += 1;
    } catch (error) {
      log.warn('Indexation alerte impossible', { alertId: row.id, error: error.message });
      break;
    }
  }
  return { indexed, skipped };
}

async function indexNotes() {
  const { rows } = await query(
    `SELECT n.id, n.threat_id, n.text, n.creator, t.name AS threat_name
     FROM threat_notes n JOIN threats t ON t.id = n.threat_id
     ORDER BY n.synced_at DESC LIMIT ${BATCH_LIMIT}`,
  );
  let indexed = 0;
  let skipped = 0;
  for (const row of rows) {
    try {
      const note = { text: row.text, creator: row.creator, threatName: row.threat_name };
      const content = buildEmbeddingContent('note', note);
      if (!content || !(await needsEmbedding('note', row.id, content))) {
        skipped += 1;
        continue;
      }
      const vector = await generateEmbedding(content, 'RETRIEVAL_DOCUMENT');
      await upsertEmbedding('note', row.id, content, vector);
      indexed += 1;
    } catch (error) {
      log.warn('Indexation note impossible', { noteId: row.id, error: error.message });
      break;
    }
  }
  return { indexed, skipped };
}

async function indexActivities() {
  const { rows } = await query(
    `SELECT id, raw FROM activities ORDER BY created_at DESC NULLS LAST LIMIT ${BATCH_LIMIT}`,
  );
  let indexed = 0;
  let skipped = 0;
  for (const row of rows) {
    try {
      const activity = normalizeActivity(row.raw);
      const content = buildEmbeddingContent('activity', activity);
      if (!content || !(await needsEmbedding('activity', row.id, content))) {
        skipped += 1;
        continue;
      }
      const vector = await generateEmbedding(content, 'RETRIEVAL_DOCUMENT');
      await upsertEmbedding('activity', row.id, content, vector);
      indexed += 1;
    } catch (error) {
      log.warn('Indexation activité impossible', { activityId: row.id, error: error.message });
      break;
    }
  }
  return { indexed, skipped };
}

// Passe d'indexation complète — appelee apres runSync. Ne bloque jamais la synchro :
// les erreurs provider sont journalisées et reprises au prochain run.
async function runRagIndex() {
  const startedAt = Date.now();
  try {
    const threats = await indexThreats();
    const alerts = await indexAlerts();
    const notes = await indexNotes();
    const activities = await indexActivities();
    const totals = {
      threats: threats.indexed,
      alerts: alerts.indexed,
      notes: notes.indexed,
      activities: activities.indexed,
    };
    if (totals.threats + totals.alerts + totals.notes + totals.activities > 0) {
      log.info('Indexation RAG terminée', { ...totals, durationMs: Date.now() - startedAt });
    }
    return totals;
  } catch (error) {
    log.warn('Indexation RAG impossible', { error: error.message });
    return null;
  }
}

module.exports = { runRagIndex };

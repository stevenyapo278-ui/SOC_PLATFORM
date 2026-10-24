'use strict';

// Recherche hybride RAG sur la table embeddings (pgvector + FTS français).
// Score combiné : 0.7 × (1 - cosine) + 0.3 × ts_rank — porté de IA_Hub (knowledgeSearch).

const { query } = require('../db');
const log = require('../logger');
const { generateEmbedding, toVectorLiteral } = require('../ai/embeddings');

const MIN_SCORE = 0.12;
const MIN_VECTOR_SCORE = 0.2;
const RELATIVE_FLOOR = 0.3;

async function searchRag(userQuery, options = {}) {
  const topK = Math.min(Math.max(Number(options.topK) || 8, 1), 30);
  const entityTypes = Array.isArray(options.entityTypes) && options.entityTypes.length > 0 ? options.entityTypes : null;

  const trimmed = String(userQuery || '').trim();
  if (!trimmed) return [];

  // 1. Branche vecteur (si un provider EMBEDDING est configuré)
  let vectorRows = [];
  let vectorOk = false;
  try {
    const vector = await generateEmbedding(trimmed, 'RETRIEVAL_QUERY');
    const typeFilter = entityTypes ? `AND entity_type = ANY($3)` : '';
    const params = [toVectorLiteral(vector), String(Math.max(topK * 3, 30))];
    if (entityTypes) params.push(entityTypes);
    const { rows } = await query(
      `SELECT entity_type, entity_id, content, model,
              1 - (embedding <=> $1::vector) AS vector_score
       FROM embeddings
       WHERE embedding IS NOT NULL ${typeFilter}
       ORDER BY embedding <=> $1::vector
       LIMIT $2`,
      params,
    );
    vectorRows = rows;
    vectorOk = true;
  } catch (error) {
    log.debug('Recherche vectorielle indisponible', { error: error.message });
  }

  // 2. Branche FTS français (repli ou complément)
  let ftsRows = [];
  try {
    const typeFilter = entityTypes ? `AND entity_type = ANY($2)` : '';
    const params = [trimmed];
    if (entityTypes) params.push(entityTypes);
    const { rows } = await query(
      `SELECT entity_type, entity_id, content,
              ts_rank(to_tsvector('french', content), plainto_tsquery('french', $1)) AS fts_score
       FROM embeddings
       WHERE to_tsvector('french', content) @@ plainto_tsquery('french', $1) ${typeFilter}
       ORDER BY fts_score DESC
       LIMIT $${entityTypes ? 3 : 2}`,
      params,
    );
    ftsRows = rows;
  } catch (error) {
    log.debug('Recherche plein texte indisponible', { error: error.message });
  }

  // 3. Combinaison des scores
  const combined = new Map();
  const keyOf = (row) => `${row.entity_type}:${row.entity_id}`;

  if (vectorOk) {
    for (const row of vectorRows) {
      const vs = Number(row.vector_score) || 0;
      if (vs < MIN_VECTOR_SCORE) continue;
      combined.set(keyOf(row), { ...row, vectorScore: vs, ftsScore: 0, score: 0.7 * vs });
    }
  }
  for (const row of ftsRows) {
    const fs = Number(row.fts_score) || 0;
    const existing = combined.get(keyOf(row));
    if (existing) {
      existing.ftsScore = fs;
      existing.score += 0.3 * fs;
    } else {
      combined.set(keyOf(row), { ...row, vectorScore: 0, ftsScore: fs, score: 0.3 * fs });
    }
  }

  let results = Array.from(combined.values());

  // 4. Seuils : plancher absolu + coupe relative au meilleur
  results = results.filter((r) => r.score >= MIN_SCORE || r.vectorScore >= 0.5 || r.ftsScore >= 0.2);
  if (results.length > 0) {
    const best = Math.max(...results.map((r) => r.score));
    results = results.filter((r) => r.score >= best * RELATIVE_FLOOR);
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, topK).map((row) => ({
    kind: row.entity_type,
    id: row.entity_id,
    content: row.content,
    score: Math.round(row.score * 1000) / 1000,
    vectorScore: Math.round(row.vectorScore * 1000) / 1000,
    ftsScore: Math.round(row.ftsScore * 1000) / 1000,
  }));
}

module.exports = { searchRag, MIN_SCORE, MIN_VECTOR_SCORE, RELATIVE_FLOOR };

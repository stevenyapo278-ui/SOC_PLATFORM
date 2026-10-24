'use strict';

// Embeddings RAG — candidats pilotés en base (ai_models de type EMBEDDING),
// cache mémoire, littéral pgvector. Dimension figée par EMBEDDINGS_DIM (migration).

const crypto = require('crypto');
const { query } = require('../db');
const config = require('../config');
const log = require('../logger');
const { getActiveProviders, PROVIDERS_WITHOUT_EMBEDDINGS, DEFAULT_EMBEDDING_MODEL } = require('../ai/providers');
const { trackAiUsage } = require('../ai/usageTracker');

const DIMENSION = () => config.embeddings.dimension;
const CACHE_PREFIX = 'embeddings:';
const CACHE_TTL = 3600;
const CACHE_MAX = 2000;
const cache = new Map();

function cacheKey(text, scope) {
  const normalized = (text || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const digest = crypto.createHash('sha256').update(normalized).digest('hex');
  return `${CACHE_PREFIX}${scope}:${digest}`;
}

function cacheGet(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    cache.delete(key);
    return null;
  }
  return entry.value;
}

function cacheSet(key, value) {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
  cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL * 1000 });
}

// TOUS les candidats essayables : provider actif + clé active + modèle EMBEDDING.
async function listEmbeddingCandidates() {
  const providers = await getActiveProviders({ modelType: 'EMBEDDING' });
  const candidates = [];
  for (const provider of providers) {
    if (PROVIDERS_WITHOUT_EMBEDDINGS.has(provider.name)) continue;
    const models = provider.models.length > 0
      ? provider.models.map((m) => m.name)
      : DEFAULT_EMBEDDING_MODEL[provider.name]
        ? [DEFAULT_EMBEDDING_MODEL[provider.name]]
        : [];
    for (const model of models) {
      candidates.push({ providerName: provider.name, kind: provider.kind, baseUrl: provider.baseUrl, apiKey: provider.apiKey, model });
    }
  }
  return candidates;
}

async function embedWithGemini(candidate, text, taskType) {
  const base = candidate.baseUrl || 'https://generativelanguage.googleapis.com/v1beta';
  const body = {
    model: `models/${candidate.model}`,
    content: { parts: [{ text }] },
    outputDimensionality: DIMENSION(),
  };
  if (taskType) body.taskType = taskType;
  const startedAt = Date.now();
  const res = await fetch(`${base}/models/${candidate.model}:embedContent`, {
    method: 'POST',
    signal: AbortSignal.timeout(30000),
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': candidate.apiKey },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Gemini embeddings HTTP ${res.status}`);
  const data = await res.json();
  const totalTokens = (data.usageMetadata && data.usageMetadata.totalTokenCount) || 0;
  if (totalTokens > 0) {
    trackAiUsage({ promptTokens: totalTokens, completionTokens: 0, totalTokens }, candidate.providerName, 'embedding', {
      model: candidate.model,
      durationMs: Date.now() - startedAt,
      source: 'embeddings',
    }).catch(() => {});
  }
  return data.embedding.values;
}

async function embedWithOpenAICompat(candidate, text) {
  const base = candidate.baseUrl || 'https://api.openai.com/v1';
  const body = { model: candidate.model, input: text };
  if (candidate.providerName === 'openai') body.dimensions = DIMENSION();
  if (candidate.providerName === 'nvidia') body.input_type = 'document';

  const startedAt = Date.now();
  const res = await fetch(`${base}/embeddings`, {
    method: 'POST',
    signal: AbortSignal.timeout(30000),
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${candidate.apiKey}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Embeddings ${candidate.providerName} HTTP ${res.status}`);
  const data = await res.json();
  const promptTokens = (data.usage && data.usage.prompt_tokens) || 0;
  if (promptTokens > 0) {
    trackAiUsage({ promptTokens, completionTokens: 0, totalTokens: promptTokens }, candidate.providerName, 'embedding', {
      model: candidate.model,
      durationMs: Date.now() - startedAt,
      source: 'embeddings',
    }).catch(() => {});
  }
  return data.data && data.data[0] && data.data[0].embedding;
}

async function trialEmbedding(candidate, text, taskType) {
  const vector =
    candidate.kind === 'gemini'
      ? await embedWithGemini(candidate, text, taskType)
      : await embedWithOpenAICompat(candidate, text);
  if (!Array.isArray(vector) || vector.length !== DIMENSION()) {
    throw new Error(`vecteur de ${vector ? vector.length : 0} dimensions, ${DIMENSION()} attendues`);
  }
  return vector;
}

// Génère l'embedding en essayant TOUS les candidats actifs jusqu'au premier compatible.
async function generateEmbedding(text, taskType = 'RETRIEVAL_DOCUMENT') {
  const candidates = await listEmbeddingCandidates();
  if (candidates.length === 0) {
    throw new Error('Aucun provider IA actif ne supporte les embeddings (modèle de type EMBEDDING requis).');
  }

  const nominal = candidates[0];
  const readKey = cacheKey(text, `${nominal.providerName}/${nominal.model}:${taskType}`);
  const cached = cacheGet(readKey);
  if (cached) return cached;

  const failures = [];
  for (const candidate of candidates) {
    try {
      const vector = await trialEmbedding(candidate, text, taskType);
      cacheSet(cacheKey(text, `${candidate.providerName}/${candidate.model}:${taskType}`), vector);
      return vector;
    } catch (error) {
      failures.push(`${candidate.providerName}/${candidate.model} : ${error.message}`);
    }
  }
  throw new Error(`Aucun embedding compatible (${DIMENSION()} dimensions). ${failures.join(' | ')}`);
}

function toVectorLiteral(vector) {
  return `[${vector.join(',')}]`;
}

module.exports = { generateEmbedding, toVectorLiteral, listEmbeddingCandidates };

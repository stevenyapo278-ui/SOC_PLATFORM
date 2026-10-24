'use strict';

// Couche providers IA multi-fournisseurs — les providers/clés/modèles vivent en
// base (tables ai_providers/ai_keys/ai_models, gérées via Paramètres), jamais en .env.
// Porté de Projet_IA_Hub (mailAnalyzer.js) et adapté : SQL brut pg, pas de Prisma.

const { query } = require('../db');
const config = require('../config');
const log = require('../logger');
const { getBreaker } = require('./circuitBreaker');
const { trackAiUsage } = require('./usageTracker');

const PROVIDER_KINDS = {
  openai: 'openai_compat',
  mistral: 'openai_compat',
  nvidia: 'openai_compat',
  cohere: 'openai_compat',
  anthropic: 'anthropic',
  gemini: 'gemini',
};

// Anthropic n'a pas d'API d'embeddings.
const PROVIDERS_WITHOUT_EMBEDDINGS = new Set(['anthropic']);

const DEFAULT_BASE_URLS = {
  openai: 'https://api.openai.com/v1',
  anthropic: 'https://api.anthropic.com/v1',
  gemini: 'https://generativelanguage.googleapis.com/v1beta',
  mistral: 'https://api.mistral.ai/v1',
  nvidia: 'https://integrate.api.nvidia.com/v1',
  cohere: 'https://api.cohere.com/v2',
};

const DEFAULT_EMBEDDING_MODEL = {
  gemini: 'gemini-embedding-001',
  openai: 'text-embedding-3-small',
  nvidia: 'nvidia/nv-embedqa-e5-v5',
  mistral: 'mistral-embed',
};

// ── Cache des providers actifs (30 s) ────────────────────────────────────────
let providerCache = null;
let providerCacheAt = 0;
const PROVIDER_CACHE_TTL = 30000;

function invalidateProviderCache() {
  providerCache = null;
  providerCacheAt = 0;
}

async function getActiveProviders(options = {}) {
  const now = Date.now();
  const wantedType = options.modelType || 'CHAT';
  if (providerCache && now - providerCacheAt < PROVIDER_CACHE_TTL && wantedType === 'CHAT') {
    return providerCache;
  }

  const { rows } = await query(
    `SELECT p.id, p.name, p.label, p.kind, p.base_url, p.priority, p.is_default,
            k.api_key,
            COALESCE(
              (SELECT json_agg(json_build_object('name', m.name, 'type', m.type, 'isDefault', m.is_default)
                 ORDER BY m.is_default DESC, m.id ASC)
               FROM ai_models m
               WHERE m.provider_id = p.id AND m.is_active AND NOT m.is_deleted AND m.type = $1),
              '[]'::json
            ) AS models
     FROM ai_providers p
     JOIN ai_keys k ON k.provider_id = p.id AND k.is_active
     WHERE p.is_active
     ORDER BY p.is_default DESC, p.priority ASC, p.label ASC`,
    [wantedType],
  );

  const providers = rows.map((row) => ({
    id: Number(row.id),
    name: row.name,
    label: row.label,
    kind: PROVIDER_KINDS[row.name] || row.kind || 'openai_compat',
    baseUrl: row.base_url || DEFAULT_BASE_URLS[row.name] || '',
    priority: row.priority,
    isDefault: row.is_default === true,
    apiKey: row.api_key,
    models: row.models || [],
  }));

  if (wantedType === 'CHAT') {
    providerCache = providers;
    providerCacheAt = now;
  }
  return providers;
}

// ── Extraction Retry-After ───────────────────────────────────────────────────
function retryAfterMs(res, bodyText) {
  const header = res.headers.get('retry-after');
  if (header) {
    const seconds = Number(header);
    if (Number.isFinite(seconds)) return Math.min(seconds * 1000, 60000);
  }
  try {
    const parsed = JSON.parse(bodyText);
    const retry = parsed && (parsed.error && parsed.error.retry_after || parsed.retry_after);
    if (retry) return Math.min(Number(retry) * 1000, 60000);
  } catch {
    /* body illisible : on se fie au backoff par défaut */
  }
  return null;
}

class AiHttpError extends Error {
  constructor(message, status, retryAfter) {
    super(message);
    this.name = 'AiHttpError';
    this.status = status;
    this.retryAfterMs = retryAfter;
  }
}

function throwHttpError(provider, status, bodyText) {
  let detail = '';
  try {
    const parsed = JSON.parse(bodyText);
    detail = (parsed.error && (parsed.error.message || parsed.error.msg)) || parsed.message || '';
  } catch {
    detail = bodyText.substring(0, 300);
  }
  const err = new AiHttpError(`${provider.label} (HTTP ${status})${detail ? ` : ${detail}` : ''}`, status, null);
  err.retryAfterMs = null;
  throw err;
}

// ── JSON Schema → Gemini OpenAPI 3.0 ────────────────────────────────────────
function convertToGeminiSchema(schema) {
  if (!schema || schema.type === 'string') return schema;
  const geminiTypeMap = {
    string: 'STRING',
    integer: 'INTEGER',
    number: 'NUMBER',
    boolean: 'BOOLEAN',
    array: 'ARRAY',
    object: 'OBJECT',
  };
  const result = { type: geminiTypeMap[schema.type] || schema.type };
  if (schema.description) result.description = schema.description;
  if (schema.properties) {
    result.properties = {};
    for (const [key, val] of Object.entries(schema.properties)) {
      result.properties[key] = convertToGeminiSchema(val);
    }
  }
  if (schema.items) result.items = convertToGeminiSchema(schema.items);
  if (schema.required) result.required = schema.required;
  return result;
}

function breakerFor(provider, usage) {
  return getBreaker(`ai-${provider.name}-${usage}`, { maxFailures: 3, resetTimeoutMs: 30000 });
}

// ── Appel OpenAI-compatible (openai, mistral, nvidia, cohere chat) ───────────
async function callOpenAICompat(provider, model, options, usage) {
  return breakerFor(provider, usage).call(async () => {
    const baseUrl = provider.baseUrl || DEFAULT_BASE_URLS.openai;
    const apiMessages = options.messages
      ? (options.system ? [{ role: 'system', content: options.system }, ...options.messages] : options.messages)
      : [{ role: 'system', content: options.system }, { role: 'user', content: options.prompt }].filter((m) => m.content);

    const body = {
      model,
      messages: apiMessages,
      temperature: options.temperature ?? 0.2,
      max_tokens: options.maxTokens ?? 4096,
    };
    if (options.responseFormat) body.response_format = options.responseFormat;
    if (options.tools) {
      body.tools = options.tools;
      if (options.toolChoice) body.tool_choice = options.toolChoice;
    }

    const startedAt = Date.now();
    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      signal: AbortSignal.timeout(60000),
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${provider.apiKey}` },
      body: JSON.stringify(body),
    });
    const bodyText = await res.text();
    if (!res.ok) {
      const err = new AiHttpError(`${provider.label} (HTTP ${res.status})`, res.status, retryAfterMs(res, bodyText));
      throw err;
    }
    const data = JSON.parse(bodyText);
    const choice = data.choices && data.choices[0] && data.choices[0].message;
    const tokenUsage = data.usage
      ? {
          promptTokens: data.usage.prompt_tokens || 0,
          completionTokens: data.usage.completion_tokens || 0,
          totalTokens: data.usage.total_tokens || 0,
        }
      : null;
    if (tokenUsage && tokenUsage.totalTokens > 0) {
      trackAiUsage(tokenUsage, provider.name, usage, {
        model,
        durationMs: Date.now() - startedAt,
        source: options.source || 'chat',
        userId: options.userId,
      }).catch(() => {});
    }
    return { text: (choice && choice.content) || '', toolCalls: (choice && choice.tool_calls) || null, usage: tokenUsage };
  });
}

// ── Appel Anthropic (Messages API) ───────────────────────────────────────────
async function callAnthropic(provider, model, options, usage) {
  return breakerFor(provider, usage).call(async () => {
    const baseUrl = provider.baseUrl || DEFAULT_BASE_URLS.anthropic;
    const apiMessages = options.messages
      ? options.messages.filter((m) => m.role !== 'system')
      : [{ role: 'user', content: options.prompt }];

    const body = {
      model,
      max_tokens: options.maxTokens ?? 4096,
      temperature: options.temperature ?? 0.2,
      messages: apiMessages,
    };
    if (options.system) body.system = options.system;
    if (options.tools) {
      body.tools = options.tools.map((tool) => ({
        name: tool.function.name,
        description: tool.function.description,
        input_schema: tool.function.parameters,
      }));
    }

    const startedAt = Date.now();
    const res = await fetch(`${baseUrl}/messages`, {
      method: 'POST',
      signal: AbortSignal.timeout(60000),
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': provider.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });
    const bodyText = await res.text();
    if (!res.ok) throw new AiHttpError(`${provider.label} (HTTP ${res.status})`, res.status, retryAfterMs(res, bodyText));

    const data = JSON.parse(bodyText);
    const text = (data.content || [])
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
    const toolCalls = (data.content || [])
      .filter((block) => block.type === 'tool_use')
      .map((block) => ({
        id: block.id,
        type: 'function',
        function: { name: block.name, arguments: JSON.stringify(block.input) },
      }));
    const tokenUsage = data.usage
      ? {
          promptTokens: data.usage.input_tokens || 0,
          completionTokens: data.usage.output_tokens || 0,
          totalTokens: (data.usage.input_tokens || 0) + (data.usage.output_tokens || 0),
        }
      : null;
    if (tokenUsage && tokenUsage.totalTokens > 0) {
      trackAiUsage(tokenUsage, provider.name, usage, {
        model,
        durationMs: Date.now() - startedAt,
        source: options.source || 'chat',
        userId: options.userId,
      }).catch(() => {});
    }
    return { text, toolCalls: toolCalls.length > 0 ? toolCalls : null, usage: tokenUsage };
  });
}

// ── Appel Gemini (generateContent) ───────────────────────────────────────────
async function callGemini(provider, model, options, usage) {
  return breakerFor(provider, usage).call(async () => {
    const base = provider.baseUrl || DEFAULT_BASE_URLS.gemini;
    const modelName = model || 'gemini-2.5-flash';

    let contents;
    if (options.messages) {
      contents = options.messages.map((m) => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));
    } else {
      contents = [{ role: 'user', parts: [{ text: options.prompt }] }];
    }

    const payload = {
      contents,
      generationConfig: {
        temperature: options.temperature ?? 0.2,
        maxOutputTokens: options.maxTokens ?? 4096,
      },
    };

    // Thinking déductif de maxOutputTokens sur les modèles Flash → on le coupe.
    const lower = modelName.toLowerCase();
    if (lower.includes('gemini') && !lower.includes('pro')) {
      payload.generationConfig.thinkingConfig = { thinkingBudget: 0 };
    }

    if (options.system) payload.systemInstruction = { parts: [{ text: options.system }] };
    if (options.responseFormat && options.responseFormat.type === 'json_object') {
      payload.generationConfig.responseMimeType = 'application/json';
      if (options.responseFormat.schema) {
        payload.generationConfig.responseSchema = convertToGeminiSchema(options.responseFormat.schema);
      }
    }
    if (options.tools) {
      payload.tools = [
        {
          functionDeclarations: options.tools.map((t) => ({
            name: t.function.name,
            description: t.function.description,
            parameters: t.function.parameters ? convertToGeminiSchema(t.function.parameters) : undefined,
          })),
        },
      ];
    }

    const startedAt = Date.now();
    const res = await fetch(`${base}/models/${modelName}:generateContent`, {
      method: 'POST',
      signal: AbortSignal.timeout(60000),
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': provider.apiKey },
      body: JSON.stringify(payload),
    });
    const bodyText = await res.text();
    if (!res.ok) throw new AiHttpError(`${provider.label} (HTTP ${res.status})`, res.status, retryAfterMs(res, bodyText));

    const data = JSON.parse(bodyText);
    const candidate = data.candidates && data.candidates[0];
    const parts = (candidate && candidate.content && candidate.content.parts) || [];
    const text = parts
      .filter((p) => p.text && !p.functionCall)
      .map((p) => p.text)
      .join('');
    const toolCalls = parts
      .filter((p) => p.functionCall)
      .map((p, index) => ({
        id: `call_${index}`,
        type: 'function',
        function: { name: p.functionCall.name, arguments: JSON.stringify(p.functionCall.args || {}) },
      }));

    const ut = data.usageMetadata;
    if (ut && ut.totalTokenCount) {
      trackAiUsage(
        {
          promptTokens: ut.promptTokenCount || 0,
          completionTokens: ut.candidatesTokenCount || 0,
          totalTokens: ut.totalTokenCount,
        },
        provider.name,
        usage,
        { model: modelName, durationMs: Date.now() - startedAt, source: options.source || 'chat', userId: options.userId },
      ).catch(() => {});
    }

    // Structured output : renvoyer le JSON brut si demandé sans tools.
    return { text, toolCalls: toolCalls.length > 0 ? toolCalls : null, usage: null };
  });
}

async function callProvider(provider, model, options, usage) {
  if (provider.kind === 'gemini') return callGemini(provider, model, options, usage);
  if (provider.kind === 'anthropic') return callAnthropic(provider, model, options, usage);
  return callOpenAICompat(provider, model, options, usage);
}

function pickModel(provider, forcedModelId) {
  if (forcedModelId) {
    const found = provider.models.find((m) => m.name === forcedModelId);
    if (found) return found.name;
  }
  const def = provider.models.find((m) => m.isDefault);
  if (def) return def.name;
  if (provider.models.length > 0) return provider.models[0].name;
  // Repli par défaut selon le provider si aucun modèle enregistré.
  const fallback = { gemini: 'gemini-2.5-flash', openai: 'gpt-4o-mini', mistral: 'mistral-large-latest', nvidia: 'meta/llama-3.1-70b-instruct', cohere: 'command-r-plus' };
  return fallback[provider.name] || '';
}

// ── Appel avec fallback circulaire sur les providers actifs ──────────────────
async function callProviderWithFallback(prompt, usage = 'chatbot', options = {}) {
  const providers = await getActiveProviders({ modelType: 'CHAT' });
  const ordered = options.forcedProvider
    ? [...providers].sort((a, b) => (b.name === options.forcedProvider) - (a.name === options.forcedProvider))
    : providers;

  if (ordered.length === 0) {
    throw new Error('Aucun provider IA actif configuré — ajoutez une clé API dans Paramètres > IA.');
  }

  const failures = [];
  for (const provider of ordered) {
    const model = pickModel(provider, options.forcedModelId);
    if (!model) continue;
    try {
      return await callProvider(provider, model, options, usage);
    } catch (error) {
      failures.push(`${provider.name}/${model} : ${error.message}`);
      log.warn('Provider IA en échec — passage au suivant', { provider: provider.name, model, error: error.message });
    }
  }
  throw new Error(`Tous les providers IA ont échoué. Détails : ${failures.join(' | ')}`);
}

// ── Retry exponentiel avec respect de Retry-After ────────────────────────────
async function callAiWithRetry(fn, options = {}) {
  const maxRetries = options.maxRetries ?? 2;
  const baseDelay = options.baseDelay ?? 1500;

  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const retriable =
        error.code === 'CIRCUIT_OPEN' ||
        error.status === 429 ||
        error.status >= 500 ||
        (error.retryAfterMs != null);
      if (!retriable || attempt === maxRetries) break;
      const delay = error.retryAfterMs || baseDelay * 2 ** attempt;
      log.info('Retry appel IA', { attempt: attempt + 1, delayMs: delay, error: error.message });
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}

module.exports = {
  getActiveProviders,
  invalidateProviderCache,
  callProviderWithFallback,
  callAiWithRetry,
  convertToGeminiSchema,
  PROVIDERS_WITHOUT_EMBEDDINGS,
  DEFAULT_EMBEDDING_MODEL,
  DEFAULT_BASE_URLS,
};

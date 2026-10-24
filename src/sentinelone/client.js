'use strict';

const { Agent } = require('undici');
const log = require('../logger');

class SentinelOneError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'SentinelOneError';
    this.status = options.status || 502;
    this.code = options.code || 'S1_ERROR';
    this.endpoint = options.endpoint || null;
  }
}

class SentinelOneConfigError extends SentinelOneError {
  constructor(message) {
    super(message, { status: 503, code: 'S1_NOT_CONFIGURED' });
    this.name = 'SentinelOneConfigError';
  }
}

// SentinelOne exige un ISO 8601 à microsecondes (ex. 2018-02-27T04:49:26.257525Z) ;
// String(date) produirait « Sat Oct 24 2026 … » → 400 « Not a valid datetime ».
function formatParam(value) {
  if (value instanceof Date) return `${value.toISOString().slice(0, -1)}000Z`;
  return String(value);
}

function buildQuery(params) {
  const search = new URLSearchParams();
  if (!params) return '';
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, formatParam(value));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}

function extractErrorMessage(body) {
  if (!body || typeof body !== 'object') return '';
  if (Array.isArray(body.errors) && body.errors.length > 0) {
    const first = body.errors[0] || {};
    return first.detail || first.title || first.code || '';
  }
  return body.message || body.error || '';
}

class SentinelOneClient {
  constructor(options) {
    this.baseUrl = options.baseUrl;
    this.apiToken = options.apiToken;
    this.timeoutMs = options.timeoutMs || 15000;
    this.cacheTtlMs = options.cacheTtlMs || 0;
    this.sampleLimit = options.sampleLimit || 500;
    this.defaultPageSize = options.defaultPageSize || 25;
    this.cache = new Map();
    this.inflight = new Map();
    this.dispatcher = options.tlsInsecure
      ? new Agent({ connect: { rejectUnauthorized: false } })
      : undefined;
  }

  get configured() {
    return Boolean(this.baseUrl && this.apiToken);
  }

  assertConfigured() {
    if (!this.configured) {
      throw new SentinelOneConfigError(
        'SentinelOne n’est pas configuré : renseignez S1_URL et S1_API_TOKEN dans .env.',
      );
    }
  }

  async request(path, params, options = {}) {
    this.assertConfigured();

    const query = buildQuery(params);
    const cacheKey = `${path}${query}`;
    const now = Date.now();

    if (!options.force && this.cacheTtlMs > 0) {
      const cached = this.cache.get(cacheKey);
      if (cached && cached.expiresAt > now) return cached.value;
      if (cached) this.cache.delete(cacheKey);
    }

    if (this.inflight.has(cacheKey)) return this.inflight.get(cacheKey);

    const promise = this.#fetchJson(path, query)
      .then((value) => {
        if (this.cacheTtlMs > 0) {
          this.cache.set(cacheKey, { value, expiresAt: Date.now() + this.cacheTtlMs });
        }
        return value;
      })
      .finally(() => this.inflight.delete(cacheKey));

    this.inflight.set(cacheKey, promise);
    return promise;
  }

  async #fetchJson(path, query) {
    const url = `${this.baseUrl}${path}${query}`;
    const startedAt = Date.now();

    let response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `ApiToken ${this.apiToken}`,
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(this.timeoutMs),
        ...(this.dispatcher ? { dispatcher: this.dispatcher } : {}),
      });
    } catch (error) {
      const isTimeout = error && (error.name === 'TimeoutError' || error.name === 'AbortError');
      log.error('SentinelOne request failed', {
        endpoint: path,
        error: error.message,
        durationMs: Date.now() - startedAt,
      });
      throw new SentinelOneError(
        isTimeout
          ? `SentinelOne n’a pas répondu en ${Math.round(this.timeoutMs / 1000)} s.`
          : `Connexion à SentinelOne impossible (${error.message}).`,
        { status: isTimeout ? 504 : 502, code: isTimeout ? 'S1_TIMEOUT' : 'S1_UNREACHABLE', endpoint: path },
      );
    }

    const text = await response.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
    }

    if (!response.ok) {
      const detail = extractErrorMessage(body);
      const messages = {
        400: 'Requête refusée par SentinelOne (paramètres invalides).',
        401: 'Token API SentinelOne refusé.',
        403: 'Le token API n’a pas les droits nécessaires.',
        404: 'Endpoint indisponible sur cette instance SentinelOne (version ou licence).',
        429: 'Quota d’appels SentinelOne atteint, réessayez dans quelques instants.',
      };
      const message = messages[response.status] || detail || `Erreur SentinelOne (HTTP ${response.status}).`;
      log.warn('SentinelOne API error', {
        endpoint: path,
        status: response.status,
        detail: detail || undefined,
      });
      throw new SentinelOneError(detail && messages[response.status] ? `${messages[response.status]} ${detail}` : message, {
        status: response.status === 401 || response.status === 403 ? 502 : response.status,
        code: `S1_HTTP_${response.status}`,
        endpoint: path,
      });
    }

    return body || {};
  }

  #page(body) {
    const data = Array.isArray(body && body.data) ? body.data : [];
    const pagination = (body && body.pagination) || {};
    return {
      data,
      pagination: {
        totalItems: Number.isFinite(Number(pagination.totalItems)) ? Number(pagination.totalItems) : data.length,
        nextCursor: pagination.nextCursor || null,
      },
    };
  }

  async listAgents(options = {}) {
    const body = await this.request(
      '/agents',
      {
        limit: options.limit || this.defaultPageSize,
        cursor: options.cursor,
        query: options.query,
        // Delta de synchro : seuls les agents modifiés depuis cette date.
        updatedAt__gte: options.updatedAtGte,
        sortBy: 'computerName',
        sortOrder: 'asc',
      },
      options,
    );
    return this.#page(body);
  }

  async listThreats(options = {}) {
    const body = await this.request(
      '/threats',
      {
        limit: options.limit || this.defaultPageSize,
        cursor: options.cursor,
        query: options.query,
        ids: options.ids,
        agentIds: options.agentIds,
        storylines: options.storylines,
        analystVerdicts: options.analystVerdicts,
        mitigationStatuses: options.mitigationStatuses,
        // updatedAt (et non createdAt) : capte aussi les changements de statut.
        updatedAt__gte: options.updatedAtGte,
        sortBy: 'createdAt',
        sortOrder: 'desc',
      },
      options,
    );
    return this.#page(body);
  }

  // Pas de GET /threats/{id} en v2.1 : on filtre la liste par ids.
  async getThreat(threatId, options = {}) {
    const page = await this.listThreats({ ...options, ids: threatId, limit: 1 });
    return page.data[0] || null;
  }

  async listThreatTimeline(threatId, options = {}) {
    const body = await this.request(
      `/threats/${encodeURIComponent(threatId)}/timeline`,
      { limit: options.limit || this.defaultPageSize, cursor: options.cursor },
      options,
    );
    return this.#page(body);
  }

  async listThreatNotes(threatId, options = {}) {
    const body = await this.request(
      `/threats/${encodeURIComponent(threatId)}/notes`,
      { limit: options.limit || this.defaultPageSize, cursor: options.cursor },
      options,
    );
    return this.#page(body);
  }

  // Alertes STAR (cloud-detection) — filtres de corrélation : storyline, hash, agent.
  async listCloudAlerts(options = {}) {
    const body = await this.request(
      '/cloud-detection/alerts',
      {
        limit: options.limit || this.defaultPageSize,
        cursor: options.cursor,
        query: options.query,
        severity: options.severity,
        analystVerdict: options.analystVerdict,
        reportedAt__gte: options.reportedAtGte,
        sourceProcessStoryline__contains: options.storyline,
        sourceProcessFileHashSha256__contains: options.sha256,
        origAgentUuid__contains: options.agentUuid,
        origAgentName__contains: options.agentName,
        // Enum Swagger de /cloud-detection/alerts : pas de "reportedAt".
        sortBy: 'alertInfoReportedAt',
        sortOrder: 'desc',
      },
      options,
    );
    return this.#page(body);
  }

  async listAlerts(options = {}) {
    // La console n'expose que l'API STAR (/cloud-detection/alerts) ; l'ancien /alerts a disparu du Swagger.
    const body = await this.request(
      '/cloud-detection/alerts',
      {
        limit: options.limit || this.defaultPageSize,
        cursor: options.cursor,
        query: options.query,
        reportedAt__gte: options.reportedAtGte,
        sortBy: 'alertInfoReportedAt',
        sortOrder: 'desc',
      },
      options,
    );
    return this.#page(body);
  }

  async listActivities(options = {}) {
    const body = await this.request(
      '/activities',
      {
        limit: options.limit || this.defaultPageSize,
        cursor: options.cursor,
        threatIds: options.threatIds,
        agentIds: options.agentIds,
        // Delta de synchro : seules les activités créées depuis cette date.
        createdAt__gte: options.createdAtGte,
        sortBy: 'createdAt',
        sortOrder: 'desc',
      },
      options,
    );
    return this.#page(body);
  }

  // SentinelOne expose ces listes par `?ids=` (query) et non par segment de
  // chemin : /agents/{id}/applications renvoie 404 sur les consoles réelles
  // (« Endpoint indisponible » affiché dans la fiche endpoint). Ces deux routes
  // n'acceptent QUE `ids` (Swagger) : limit/cursor déclenchent un 400
  // « dict_values(['limit']): Unknown field ». Le découpage se fait donc ici.
  async #agentList(path, agentId, options = {}, fallbacks = []) {
    const params = { ids: agentId };
    let body = null;
    let lastError = null;
    for (const candidate of [path, ...fallbacks]) {
      try {
        body = await this.request(candidate, params, options);
        break;
      } catch (error) {
        lastError = error;
        const retriable =
          error instanceof SentinelOneError && ['S1_HTTP_404', 'S1_HTTP_403'].includes(error.code);
        if (!retriable) throw error;
      }
    }
    if (!body) throw lastError || new SentinelOneError('Source de données indisponible.');
    return this.#localPage(body, options);
  }

  // Pagination locale : l'API renvoie tout d'un coup (pas de cursor, pas de
  // total paginé) — offset et limit sont appliqués côté client.
  #localPage(body, options = {}) {
    const page = this.#page(body);
    const total = page.data.length;
    const limit = Number(options.limit) > 0 ? Number(options.limit) : total;
    const offset = Number(options.cursor) > 0 ? Number(options.cursor) : 0;
    const data = page.data.slice(offset, offset + limit);
    const nextOffset = offset + data.length;
    return {
      data,
      pagination: { totalItems: total, nextCursor: nextOffset < total ? String(nextOffset) : null },
    };
  }

  async listAgentProcesses(agentId, options = {}) {
    return this.#agentList('/agents/processes', agentId, options);
  }

  async listAgentApplications(agentId, options = {}) {
    return this.#agentList('/agents/applications', agentId, options, [
      '/application-management/inventory/applications',
    ]);
  }
}

module.exports = { SentinelOneClient, SentinelOneError, SentinelOneConfigError, buildQuery };

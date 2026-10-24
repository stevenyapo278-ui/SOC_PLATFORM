'use strict';

const express = require('express');
const config = require('../config');
const log = require('../logger');
const { dbEnabled } = require('../db');
const { requireApiAuth } = require('../middleware/auth');
const { SentinelOneError } = require('../sentinelone/client');
const { buildOverview } = require('../sentinelone/overview');
const {
  normalizeAgent,
  normalizeThreat,
  normalizeThreatDetail,
  normalizeCloudAlert,
  normalizeThreatNote,
  normalizeActivity,
  normalizeProcess,
  normalizeApplication,
} = require('../sentinelone/normalize');

function readPositiveInt(value, fallback, max) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, max);
}

function readCursor(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) return undefined;
  return value;
}

function readQuery(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 200) : undefined;
}

function readIsoDate(value) {
  if (typeof value !== 'string') return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
}

function wantsRefresh(req) {
  return req.query.refresh === '1' || req.query.refresh === 'true';
}

function validAgentId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

// Le token n'est jamais renvoyé en clair, seulement une forme masquée (même
// convention que les clés des providers IA).
function maskApiToken(token) {
  const value = String(token || '');
  if (!value) return '';
  if (value.length <= 8) return '••••••••';
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function pageResponse(page, normalizer, extra = {}) {
  return {
    data: page.data.map(normalizer),
    pagination: page.pagination,
    ...extra,
  };
}

// Chargement paresseux du store : l'app doit démarrer sans pg ni base (cf. AGENTS.md).
function loadStore() {
  if (!dbEnabled()) return null;
  try {
    return require('../db/store');
  } catch (error) {
    log.warn('Lecture PostgreSQL indisponible — lecture SentinelOne directe', { error: error.message });
    return null;
  }
}

// Source de lecture des vues :
//  - base active → PostgreSQL (données déjà synchronisées, requête locale) ;
//  - sinon, ou en cas d'échec SQL → client SentinelOne, comme avant.
// `force` (?refresh=1) déclenche d'abord un delta de synchro, puis relit la base.
// Les endpoints restés en direct (timeline, processes, applications, health)
// utilisent `client` et ne passent pas par ce lecteur.
function createReader(client) {
  const store = loadStore();
  if (!store) return client;

  let sync;
  try {
    sync = require('../services/sync');
  } catch (error) {
    log.warn('Synchro PostgreSQL indisponible — lecture SentinelOne directe', { error: error.message });
    return client;
  }

  const reader = Object.create(client);
  const methods = [
    'listAgents',
    'listThreats',
    'getThreat',
    'listThreatNotes',
    'listCloudAlerts',
    'listAlerts',
    'listActivities',
  ];

  for (const name of methods) {
    reader[name] = async (...args) => {
      const options = args[args.length - 1];
      if (options && options.force) {
        try {
          await sync.syncNow(client);
        } catch (error) {
          log.warn('Delta de synchro demandé par le refresh impossible', { error: error.message });
        }
      }
      try {
        return await store[name](...args);
      } catch (error) {
        log.warn('Lecture PostgreSQL impossible — repli sur SentinelOne', {
          method: name,
          error: error.message,
        });
        return client[name](...args);
      }
    };
  }

  return reader;
}

module.exports = function createSentinelRouter(client) {
  const router = express.Router();
  const read = createReader(client);
  router.use(requireApiAuth);

  router.get('/overview', async (req, res, next) => {
    const force = wantsRefresh(req);
    const warnings = [];
    const sampleLimit = config.sentinelone.sampleLimit;

    // Compteurs exacts (aggrégats SQL) lancés en parallèle des lectures
    // échantillon : les listes « récents » viennent du sample, les KPI du SQL.
    const store = loadStore();
    const countsPromise = store
      ? store.overviewCounts().catch((error) => {
          log.warn('Compteurs SQL indisponibles — repli sur échantillon', { error: error.message });
          return null;
        })
      : Promise.resolve(null);

    const jobs = await Promise.allSettled([
      read.listAgents({ limit: sampleLimit, maxLimit: sampleLimit, force }),
      read.listThreats({ limit: sampleLimit, maxLimit: sampleLimit, force }),
      read.listAlerts({ limit: 200, maxLimit: 200, force }),
      read.listActivities({ limit: 12, force }),
    ]);

    const labels = ['agents', 'threats', 'alerts', 'activities'];
    const pages = {};
    jobs.forEach((job, index) => {
      if (job.status === 'fulfilled') {
        pages[labels[index]] = job.value;
      } else {
        pages[labels[index]] = { data: [], pagination: { totalItems: 0, nextCursor: null } };
        warnings.push({
          source: labels[index],
          message: job.reason instanceof SentinelOneError ? job.reason.message : 'Données indisponibles.',
        });
      }
    });

    if (warnings.length === 4) {
      const first = jobs[0].status === 'rejected' ? jobs[0].reason : null;
      return next(first || new SentinelOneError('SentinelOne injoignable.'));
    }

    let exact = await countsPromise;
    // Base jamais remplie (synchro pas encore passée) alors que S1 répond :
    // afficher des zéros serait pire que l'échantillon.
    if (exact && exact.agents.total === 0 && exact.threats.total === 0 && exact.alerts.total === 0) {
      const hasSample = [pages.agents, pages.threats, pages.alerts].some((page) => page.data.length > 0);
      if (hasSample) exact = null;
    }

    return res.json(
      buildOverview({
        agentsPage: pages.agents,
        threatsPage: pages.threats,
        alertsPage: pages.alerts,
        activitiesPage: pages.activities,
        warnings,
        sampleLimit,
        exact,
      }),
    );
  });

  router.get('/agents', async (req, res, next) => {
    try {
      const page = await read.listAgents({
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        query: readQuery(req.query.query),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeAgent));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/agents/:id/processes', async (req, res, next) => {
    if (!validAgentId(req.params.id)) {
      return res.status(400).json({ error: 'Identifiant endpoint invalide.' });
    }
    try {
      const page = await client.listAgentProcesses(req.params.id, {
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeProcess));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/agents/:id/applications', async (req, res, next) => {
    if (!validAgentId(req.params.id)) {
      return res.status(400).json({ error: 'Identifiant endpoint invalide.' });
    }
    try {
      const page = await client.listAgentApplications(req.params.id, {
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeApplication));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/threats', async (req, res, next) => {
    try {
      const page = await read.listThreats({
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        query: readQuery(req.query.query),
        storylines: readQuery(req.query.storylines),
        agentIds: readQuery(req.query.agentIds),
        analystVerdicts: readQuery(req.query.analystVerdicts),
        mitigationStatuses: readQuery(req.query.mitigationStatuses),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeThreat));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/threats/:id', async (req, res, next) => {
    if (!validAgentId(req.params.id)) {
      return res.status(400).json({ error: 'Identifiant de menace invalide.' });
    }
    try {
      const raw = await read.getThreat(req.params.id, { force: wantsRefresh(req) });
      if (!raw) {
        return res.status(404).json({ error: 'Menace introuvable sur SentinelOne.' });
      }
      return res.json({ data: normalizeThreatDetail(raw) });
    } catch (error) {
      return next(error);
    }
  });

  router.get('/threats/:id/timeline', async (req, res, next) => {
    if (!validAgentId(req.params.id)) {
      return res.status(400).json({ error: 'Identifiant de menace invalide.' });
    }
    try {
      const page = await client.listThreatTimeline(req.params.id, {
        limit: readPositiveInt(req.query.limit, 50, 200),
        cursor: readCursor(req.query.cursor),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeActivity));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/threats/:id/notes', async (req, res, next) => {
    if (!validAgentId(req.params.id)) {
      return res.status(400).json({ error: 'Identifiant de menace invalide.' });
    }
    try {
      const page = await read.listThreatNotes(req.params.id, {
        limit: readPositiveInt(req.query.limit, 50, 200),
        cursor: readCursor(req.query.cursor),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeThreatNote));
    } catch (error) {
      return next(error);
    }
  });

  // Enquête complète : menace + timeline + notes + alertes STAR et menaces liées (corrélation storyline).
  router.get('/threats/:id/investigate', async (req, res, next) => {
    if (!validAgentId(req.params.id)) {
      return res.status(400).json({ error: 'Identifiant de menace invalide.' });
    }
    const force = wantsRefresh(req);

    let raw;
    try {
      raw = await read.getThreat(req.params.id, { force });
    } catch (error) {
      return next(error);
    }
    if (!raw) {
      return res.status(404).json({ error: 'Menace introuvable sur SentinelOne.' });
    }

    const threat = normalizeThreatDetail(raw);
    const warnings = [];
    const relatedLimit = 25;

    const jobs = {
      // Timeline et applications : pas de table dédiée, lecture directe S1.
      timeline: client.listThreatTimeline(req.params.id, { limit: 50, force }),
      notes: read.listThreatNotes(req.params.id, { limit: 50, force }),
      activities: read.listActivities({ threatIds: req.params.id, limit: 50, force }),
    };
    if (threat.storyline) {
      jobs.alerts = read.listCloudAlerts({ storyline: threat.storyline, limit: relatedLimit, force });
      jobs.threats = read.listThreats({ storylines: threat.storyline, limit: relatedLimit, force });
    } else if (threat.sha256) {
      jobs.alerts = read.listCloudAlerts({ sha256: threat.sha256, limit: relatedLimit, force });
    }
    if (threat.agentId) {
      jobs.applications = client.listAgentApplications(threat.agentId, { limit: 50, force });
    }

    const entries = await Promise.allSettled(Object.values(jobs));
    const pages = {};
    Object.keys(jobs).forEach((key, index) => {
      const job = entries[index];
      if (job.status === 'fulfilled') {
        pages[key] = job.value;
      } else {
        pages[key] = { data: [], pagination: { totalItems: 0, nextCursor: null } };
        warnings.push({
          source: key,
          message: job.reason instanceof SentinelOneError ? job.reason.message : 'Données indisponibles.',
        });
      }
    });

    const relatedThreats = (pages.threats ? pages.threats.data : [])
      .map(normalizeThreat)
      .filter((item) => item.id !== threat.id);

    return res.json({
      threat,
      timeline: pageResponse(pages.timeline, normalizeActivity),
      notes: pageResponse(pages.notes, normalizeThreatNote),
      activities: pageResponse(pages.activities, normalizeActivity),
      applications: pages.applications
        ? pageResponse(pages.applications, normalizeApplication)
        : { data: [], pagination: { totalItems: 0, nextCursor: null } },
      relatedAlerts: pages.alerts
        ? pageResponse(pages.alerts, normalizeCloudAlert)
        : { data: [], pagination: { totalItems: 0, nextCursor: null } },
      relatedThreats: {
        data: relatedThreats,
        pagination: {
          totalItems: relatedThreats.length,
          nextCursor: pages.threats ? pages.threats.pagination.nextCursor : null,
        },
      },
      correlation: threat.storyline
        ? { key: 'storyline', value: threat.storyline }
        : threat.sha256
          ? { key: 'sha256', value: threat.sha256 }
          : null,
      warnings,
    });
  });

  // Alertes STAR (cloud-detection) — filtrables pour la corrélation.
  router.get('/cloud-alerts', async (req, res, next) => {
    try {
      const page = await read.listCloudAlerts({
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        query: readQuery(req.query.query),
        severity: readQuery(req.query.severity),
        analystVerdict: readQuery(req.query.analystVerdict),
        reportedAtGte: readIsoDate(req.query.reportedAtGte),
        storyline: readQuery(req.query.storyline),
        sha256: readQuery(req.query.sha256),
        agentUuid: readQuery(req.query.agentUuid),
        agentName: readQuery(req.query.agentName),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeCloudAlert));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/alerts', async (req, res, next) => {
    try {
      // Même source que /cloud-alerts : l'API STAR est la seule disponible sur les consoles récentes.
      const page = await read.listCloudAlerts({
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        query: readQuery(req.query.query),
        severity: readQuery(req.query.severity),
        analystVerdict: readQuery(req.query.analystVerdict),
        reportedAtGte: readIsoDate(req.query.reportedAtGte),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeCloudAlert));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/activities', async (req, res, next) => {
    try {
      const page = await read.listActivities({
        limit: readPositiveInt(req.query.limit, config.sentinelone.defaultPageSize, 100),
        cursor: readCursor(req.query.cursor),
        threatIds: readQuery(req.query.threatIds),
        agentIds: readQuery(req.query.agentIds),
        force: wantsRefresh(req),
      });
      return res.json(pageResponse(page, normalizeActivity));
    } catch (error) {
      return next(error);
    }
  });

  router.get('/settings', (req, res) => {
    return res.json({
      consoleUrl: config.sentinelone.consoleUrl,
      sentineloneConfigured: client.configured,
      apiTokenMasked: maskApiToken(config.sentinelone.apiToken),
      apiBasePath: '/web/api/v2.1',
      sampleLimit: config.sentinelone.sampleLimit,
      defaultPageSize: config.sentinelone.defaultPageSize,
      cacheTtlMs: config.sentinelone.cacheTtlMs,
      tlsInsecure: config.sentinelone.tlsInsecure,
      migration: {
        enabled: config.migration.enabled,
        defaultDate: config.migration.defaultDate,
        retirementDate: config.migration.retirementDate,
        docUrl: config.migration.docUrl,
      },
    });
  });

  router.get('/health', async (req, res) => {
    if (!client.configured) {
      return res.status(503).json({ ok: false, message: 'SentinelOne non configuré.' });
    }
    try {
      await client.listAgents({ limit: 1, force: true });
      return res.json({ ok: true, message: 'API SentinelOne joignable.' });
    } catch (error) {
      return res.status(502).json({ ok: false, message: error.message });
    }
  });

  return router;
};

module.exports.maskApiToken = maskApiToken;

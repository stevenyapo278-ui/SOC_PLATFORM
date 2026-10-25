'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const config = require('./config');
const log = require('./logger');
const { SentinelOneClient, SentinelOneError } = require('./sentinelone/client');
const { readSession, requirePageAuth, requireApiAuth } = require('./middleware/auth');
const authRouter = require('./routes/auth.routes');
const createSentinelRouter = require('./routes/sentinel.routes');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const PAGE_FILES = {
  '/': 'index.html',
  '/agents': 'agents.html',
  '/applications': 'applications.html',
  '/threats': 'threats.html',
  '/alerts': 'alerts.html',
  '/activities': 'activities.html',
  '/chat': 'chat.html',
  '/settings': 'settings.html',
  '/api-docs': 'api-docs.html',
};

function createApp(options = {}) {
  const client =
    options.client ||
    new SentinelOneClient({
      baseUrl: config.sentinelone.baseUrl,
      apiToken: config.sentinelone.apiToken,
      timeoutMs: config.sentinelone.timeoutMs,
      cacheTtlMs: config.sentinelone.cacheTtlMs,
      sampleLimit: config.sentinelone.sampleLimit,
      defaultPageSize: config.sentinelone.defaultPageSize,
      tlsInsecure: config.sentinelone.tlsInsecure,
    });

  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", "'unsafe-inline'"],
          'style-src': ["'self'", "'unsafe-inline'"],
          'img-src': ["'self'", 'data:'],
          'font-src': ["'self'", 'data:'],
          'connect-src': ["'self'"],
          'object-src': ["'none'"],
          'base-uri': ["'self'"],
          'form-action': ["'self'"],
          'frame-ancestors': ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false,
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());

  app.use('/assets', express.static(path.join(PUBLIC_DIR, 'assets'), { index: false, maxAge: '7d' }));
  // JS/CSS applicatifs : revalidation à chaque requête (etag) — évite les caches
  // périmés après un déploiement (bug type SOC.formatLongDate is not a function).
  app.use('/js', express.static(path.join(PUBLIC_DIR, 'js'), { index: false, etag: true, maxAge: 0, fallthrough: true }));
  app.use('/css', express.static(path.join(PUBLIC_DIR, 'css'), { index: false, etag: true, maxAge: 0, fallthrough: true }));
  // Données de la documentation API (générées par scripts/build-api-docs.js)
  app.use(
    '/api-docs/data',
    requireApiAuth,
    express.static(path.join(PUBLIC_DIR, 'api-docs-data'), { index: false, etag: true, maxAge: 0 }),
  );

  app.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'assets', 'images', 'favicon.ico'));
  });

  app.get('/healthz', (req, res) => {
    res.json({
      status: 'ok',
      sentineloneConfigured: client.configured,
      ldapEnabled: config.ldap.enabled,
      authDevEnabled: config.devAuth.enabled,
    });
  });

  app.use('/api/auth', authRouter);
  app.use('/api', createSentinelRouter(client));
  // IA : providers (admin) + chat. Chargés paresseusement — échec de require BDD
  // ne doit pas casser l'app ni les tests (pg absent / DATABASE_URL vide).
  try {
    app.use('/api/ai', require('./routes/ai.routes'));
    app.use('/api/chat', require('./routes/chat.routes'));
    app.use('/api/voice', require('./routes/voice.routes'));
  } catch (error) {
    log.warn('Routes IA indisponibles', { error: error.message });
  }

  app.get('/login', (req, res) => {
    if (readSession(req)) return res.redirect('/');
    return res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
  });

  // Fiche endpoint : route paramétrée, PAGE_FILES ne compare que des chemins exacts.
  app.get('/endpoints/:id', requirePageAuth, (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'endpoint.html'));
  });

  for (const [route, file] of Object.entries(PAGE_FILES)) {
    app.get(route, requirePageAuth, (req, res) => {
      res.sendFile(path.join(PUBLIC_DIR, file));
    });
  }

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ error: 'Route API inconnue.' });
    }
    return res.status(404).type('text/plain').send('Page introuvable.');
  });

  // eslint-disable-next-line no-unused-vars
  app.use((error, req, res, next) => {
    const isSentinel = error instanceof SentinelOneError;
    const status = isSentinel ? error.status : error.status && error.status < 600 ? error.status : 500;

    if (status >= 500) {
      log.error('Request failed', {
        method: req.method,
        path: req.path,
        status,
        error: error.message,
      });
    } else {
      log.warn('Request rejected', {
        method: req.method,
        path: req.path,
        status,
        error: error.message,
      });
    }

    res.status(status).json({
      error: status >= 500 && !isSentinel ? 'Erreur interne du serveur.' : error.message,
      ...(isSentinel ? { code: error.code } : {}),
    });
  });

  app.locals.sentinelOneClient = client;
  return app;
}

module.exports = { createApp, PAGE_FILES };

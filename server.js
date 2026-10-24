'use strict';

require('dotenv').config();

const config = require('./src/config');
const log = require('./src/logger');
const { createApp } = require('./src/app');
const { dbEnabled, migrate, closePool } = require('./src/db');
const { startSyncScheduler, stopSyncScheduler } = require('./src/services/sync');
const { setupVoiceLive, stopVoiceLive } = require('./src/voice/live');

const app = createApp();
const server = app.listen(config.port, config.host, () => {
  log.info('SOC Platform started', {
    url: `http://${config.host}:${config.port}`,
    env: config.env,
    sentineloneConfigured: Boolean(config.sentinelone.baseUrl && config.sentinelone.apiToken),
    ldapEnabled: config.ldap.enabled,
    devAuthEnabled: config.devAuth.enabled,
    databaseEnabled: dbEnabled(),
  });

  if (!config.sentinelone.baseUrl || !config.sentinelone.apiToken) {
    log.warn('SentinelOne non configuré — renseignez S1_URL et S1_API_TOKEN dans .env');
  }
  if (config.sentinelone.tlsInsecure) {
    log.warn('S1_TLS_INSECURE=true — la vérification du certificat SentinelOne est désactivée.');
  }
  if (config.session.ephemeralSecret) {
    log.warn('SESSION_SECRET absent — un secret éphémère est utilisé (sessions perdues au redémarrage).');
  }
  if (!config.devAuth.enabled && (!config.ldap.enabled || !config.ldap.url)) {
    log.warn('Aucun fournisseur d’authentification actif : la connexion sera impossible.');
  }
  if (config.devAuth.enabled && config.env === 'production') {
    log.warn('AUTH_DEV_LOGIN activé en production — compte par défaut utilisable (risque de sécurité).');
  }

  if (dbEnabled()) {
    migrate()
      .then(() => startSyncScheduler(app.locals.sentinelOneClient))
      .catch((error) => log.error('Initialisation base de données impossible', { error: error.message }));
  }

  // Voix live (WebSocket sur le serveur principal, même origine) — best effort.
  try {
    setupVoiceLive(server);
  } catch (error) {
    log.error('Démarrage voix live impossible', { error: error.message });
  }
});

function shutdown(signal) {
  log.info('Shutting down', { signal });
  stopSyncScheduler();
  stopVoiceLive();
  server.close(() => {
    const client = app.locals.sentinelOneClient;
    if (client && client.dispatcher) {
      client.dispatcher.close().catch(() => {});
    }
    closePool()
      .catch(() => {})
      .finally(() => process.exit(0));
  });
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

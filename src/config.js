'use strict';

const crypto = require('crypto');

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function int(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeSentinelOneBaseUrl(raw) {
  let url = String(raw || '').trim().replace(/\/+$/, '');
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  if (!/\/web\/api\/v2\.1$/i.test(url)) url = `${url}/web/api/v2.1`;
  return url;
}

function consoleUrlFromBase(baseUrl) {
  return baseUrl ? baseUrl.replace(/\/web\/api\/v2\.1$/i, '') : '';
}

const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

const sentineloneBaseUrl = normalizeSentinelOneBaseUrl(process.env.S1_URL);

// En production le secret de session est obligatoire : un secret aléatoire régénéré au
// redémarrage déconnecterait tout le monde, et un secret par défaut serait une faille.
if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET est obligatoire en production.');
}

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');

const devAuthRequested = bool(process.env.AUTH_DEV_LOGIN, false);
const devAuthConfigured = Boolean(process.env.AUTH_DEV_USER && process.env.AUTH_DEV_PASSWORD);
const devAuthEnabled = devAuthRequested && devAuthConfigured;

module.exports = {
  env: NODE_ENV,
  isProduction,
  host: process.env.HOST || '0.0.0.0',
  port: int(process.env.PORT, 3000),
  trustProxy: bool(process.env.TRUST_PROXY, false),

  session: {
    secret: sessionSecret,
    ephemeralSecret: !process.env.SESSION_SECRET,
    cookieName: 'soc_session',
    ttlMs: int(process.env.SESSION_TTL_HOURS, 8) * 60 * 60 * 1000,
    secure: bool(process.env.SESSION_COOKIE_SECURE, isProduction),
  },

  ldap: {
    enabled: bool(process.env.LDAP_ENABLED, true),
    url: process.env.LDAP_URL || '',
    emailDomain: process.env.LDAP_EMAIL_DOMAIN || '',
    bindDomain: process.env.LDAP_BIND_DOMAIN || process.env.LDAP_EMAIL_DOMAIN || '',
    bindFormat: process.env.LDAP_BIND_FORMAT || '{username}@{domain}',
    baseDn: process.env.LDAP_BASE_DN || '',
    startTls: bool(process.env.LDAP_STARTTLS, true),
    tlsStrict: bool(process.env.LDAP_TLS_STRICT, false),
    adminUsernames: (process.env.LDAP_ADMIN_USERNAMES || '')
      .split(',')
      .map((u) => u.trim().toLowerCase())
      .filter(Boolean),
    connectTimeoutMs: int(process.env.LDAP_CONNECT_TIMEOUT_MS, 5000),
    timeoutMs: int(process.env.LDAP_TIMEOUT_MS, 12000),
  },

  devAuth: {
    enabled: devAuthEnabled,
    disabledInProduction: false,
    misconfigured: devAuthRequested && !devAuthConfigured,
    username: process.env.AUTH_DEV_USER || '',
    password: process.env.AUTH_DEV_PASSWORD || '',
    displayName: process.env.AUTH_DEV_NAME || 'Développeur local',
  },

  sentinelone: {
    baseUrl: sentineloneBaseUrl,
    consoleUrl: consoleUrlFromBase(sentineloneBaseUrl),
    apiToken: (process.env.S1_API_TOKEN || '').trim(),
    timeoutMs: int(process.env.S1_TIMEOUT_MS, 15000),
    cacheTtlMs: int(process.env.S1_CACHE_TTL_MS, 20000),
    sampleLimit: Math.min(Math.max(int(process.env.S1_SAMPLE_LIMIT, 500), 50), 1000),
    tlsInsecure: bool(process.env.S1_TLS_INSECURE, false),
    defaultPageSize: Math.min(Math.max(int(process.env.S1_PAGE_SIZE, 25), 5), 100),
  },

  auth: {
    loginRateLimitWindowMs: int(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    loginRateLimitMax: int(process.env.AUTH_RATE_LIMIT_MAX, 10),
  },

  // Base PostgreSQL (optionnelle) — persistance pour l'historique SOC et le futur RAG.
  // Désactivée si DATABASE_URL est absent : la plateforme reste stateless.
  database: {
    url: (process.env.DATABASE_URL || '').trim(),
    enabled: bool(process.env.DB_ENABLED, Boolean((process.env.DATABASE_URL || '').trim())),
    poolMax: int(process.env.DB_POOL_MAX, 5),
    syncEnabled: bool(process.env.DB_SYNC_ENABLED, true),
    syncIntervalMs: int(process.env.DB_SYNC_INTERVAL_MIN, 15) * 60 * 1000,
    syncPageSize: Math.min(Math.max(int(process.env.DB_SYNC_PAGE_SIZE, 100), 25), 1000),
    syncMaxPages: Math.min(Math.max(int(process.env.DB_SYNC_MAX_PAGES, 5), 1), 50),
    // Fenêtre de recouvrement du delta : une donnée modifiée dans les N minutes
    // qui suivent sa création est re-fetchée (l'upsert est idempotent).
    syncOverlapMs: Math.min(Math.max(int(process.env.DB_SYNC_OVERLAP_MIN, 15), 1), 240) * 60 * 1000,
    // Passe de réconciliation (fetch complet) toutes les N minutes.
    syncReconcileMs: Math.min(Math.max(int(process.env.DB_SYNC_RECONCILE_MIN, 60), 5), 1440) * 60 * 1000,
    // Anti-rafale du bouton « Rafraîchir » : un seul delta toutes les N ms.
    syncRefreshMinMs: Math.min(Math.max(int(process.env.DB_SYNC_REFRESH_MIN_MS, 10000), 0), 300000),
  },

  // Embeddings RAG — seul la dimension compte (les modèles/keys viennent de la BDD).
  embeddings: {
    dimension: int(process.env.EMBEDDINGS_DIM, 1536),
  },

  // IA / chatbot — providers pilotés en base (tables ai_providers/ai_keys/ai_models).
  ai: {
    chatEnabled: bool(process.env.AI_CHAT_ENABLED, true),
    ragIndexEnabled: bool(process.env.AI_RAG_INDEX_ENABLED || process.env.RAG_INDEX_ENABLED, true),
    dailyQuota: int(process.env.AI_CHAT_DAILY_QUOTA, 500),
    rateLimitMax: int(process.env.AI_CHAT_RATE_LIMIT, 120),
    maxToolRounds: Math.min(Math.max(int(process.env.AI_MAX_TOOL_ROUNDS, 6), 1), 12),
    temperature: Number.parseFloat(process.env.AI_TEMPERATURE || '0.2') || 0.2,
    maxTokens: Math.min(Math.max(int(process.env.AI_MAX_TOKENS, 4096), 256), 32768),
    dailyTokenBudget: int(process.env.AI_DAILY_TOKEN_BUDGET, 0),
    tokenAlertThreshold: Number.parseFloat(process.env.AI_TOKEN_ALERT_THRESHOLD || '0.8') || 0.8,
    voice: {
      // WebSocket live : montée sur le serveur HTTP principal (même origine que
      // l'app → Traefik, CSP connect-src 'self'). Pas de port dédié.
      livePath: process.env.VOICE_LIVE_PATH || '/voice-live',
      livePort: int(process.env.VOICE_LIVE_PORT, 3213),
      liveModel: process.env.VOICE_LIVE_MODEL || 'gemini-2.5-flash-native-audio-preview-09-2025',
      ttsModel: process.env.VOICE_TTS_MODEL || 'gemini-2.5-flash-preview-tts',
      ttsVoice: process.env.VOICE_TTS_VOICE || 'Kore',
      sttModel: process.env.VOICE_STT_MODEL || 'gemini-2.5-flash',
      liveVoice: process.env.VOICE_LIVE_VOICE || 'Aoede',
      enabled: bool(process.env.VOICE_ENABLED, true),
    },
  },

  // Migration Singularity Operations Center — bannière d'information.
  // Désactivable via S1_MIGRATION_BANNER=false (paramètres de déploiement).
  migration: {
    enabled: bool(process.env.S1_MIGRATION_BANNER, true),
    defaultDate: process.env.S1_MIGRATION_DEFAULT_DATE || '2026-11-02',
    retirementDate: process.env.S1_MIGRATION_RETIREMENT_DATE || '2027-06-01',
    docUrl: (process.env.S1_MIGRATION_DOC_URL || '').trim(),
  },
};

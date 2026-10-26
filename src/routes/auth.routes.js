'use strict';

const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const log = require('../logger');
const { dbEnabled } = require('../db');
const { authenticateLdap, isConfigured } = require('../auth/ldap');
const { createSessionToken, cookieOptions, toPublicUser } = require('../auth/session');
const { requireApiAuth } = require('../middleware/auth');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: config.auth.loginRateLimitWindowMs,
  limit: config.auth.loginRateLimitMax,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    res.status(429).json({ error: 'Trop de tentatives de connexion. Réessayez dans quelques minutes.' });
  },
});

function safeEqual(left, right) {
  const a = crypto.createHash('sha256').update(String(left)).digest();
  const b = crypto.createHash('sha256').update(String(right)).digest();
  return crypto.timingSafeEqual(a, b);
}

function validateCredentials(body) {
  const username = typeof body?.username === 'string' ? body.username.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!username || username.length > 128 || /[\u0000-\u001f\u007f]/.test(username)) return null;
  if (!password || password.length > 256) return null;
  return { username, password };
}

function roleFor(username) {
  return config.ldap.adminUsernames.includes(username.toLowerCase()) ? 'admin' : 'analyst';
}

// Roster local des techniciens (`app_users`) : alimenté à chaque connexion pour
// les sélecteurs d'attribution des dossiers. La base peut être absente (app
// stateless) ou l'écriture échouer — dans les deux cas on journalise et on
// laisse le login passer : la collaboration est optionnelle, la connexion non.
async function rememberUser(user) {
  if (!dbEnabled()) return;
  try {
    const { upsertAppUser } = require('../db/store');
    await upsertAppUser(user);
  } catch (error) {
    log.warn('Roster des comptes non mis à jour', { username: user && user.username, error: error.message });
  }
}

async function establishSession(res, user) {
  const token = createSessionToken(user);
  res.cookie(config.session.cookieName, token, cookieOptions());
  await rememberUser(user);
  return toPublicUser({
    sub: user.username,
    name: user.displayName,
    email: user.email,
    role: user.role,
  });
}

router.post('/login', loginLimiter, async (req, res) => {
  const credentials = validateCredentials(req.body);
  if (!credentials) {
    return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
  }

  const { username, password } = credentials;

  try {
    if (config.devAuth.enabled && safeEqual(username, config.devAuth.username)) {
      if (!safeEqual(password, config.devAuth.password)) {
        log.warn('Dev login rejected', { username, ip: req.ip });
        return res.status(401).json({ error: 'Identifiants invalides.' });
      }
      const user = await establishSession(res, {
        username: config.devAuth.username,
        displayName: config.devAuth.displayName,
        email: '',
        role: 'admin',
      });
      log.info('Dev login succeeded', { username });
      return res.json({ user });
    }

    if (!config.ldap.enabled || !isConfigured(config.ldap)) {
      return res.status(503).json({
        error: 'Authentification Active Directory non configurée. Renseignez LDAP_URL et LDAP_BASE_DN.',
      });
    }

    const ldapUser = await authenticateLdap(username, password, config.ldap);
    if (!ldapUser) {
      log.warn('Login rejected', { username, ip: req.ip });
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    const user = await establishSession(res, {
      ...ldapUser,
      role: roleFor(ldapUser.username),
    });
    log.info('Login succeeded', { username: ldapUser.username, email: ldapUser.email, role: user.role });
    return res.json({ user });
  } catch (error) {
    log.error('Login error', { username, error: error.message });
    if (error.code === 'LDAP_NOT_CONFIGURED') {
      return res.status(503).json({ error: 'Authentification Active Directory non configurée.' });
    }
    return res.status(502).json({
      error: 'Annuaire Active Directory injoignable. Vérifiez LDAP_URL, le réseau et le certificat.',
    });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie(config.session.cookieName, { ...cookieOptions(), maxAge: undefined });
  res.json({ ok: true });
});

router.get('/me', requireApiAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
module.exports._private = { validateCredentials, safeEqual, roleFor };

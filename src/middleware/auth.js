'use strict';

const config = require('../config');
const { verifySessionToken, toPublicUser } = require('../auth/session');

function readSession(req) {
  const token = req.cookies ? req.cookies[config.session.cookieName] : null;
  const payload = verifySessionToken(token);
  return payload ? toPublicUser(payload) : null;
}

function requireApiAuth(req, res, next) {
  const user = readSession(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }
  req.user = user;
  return next();
}

function requirePageAuth(req, res, next) {
  const user = readSession(req);
  if (!user) {
    const target = req.originalUrl && req.originalUrl !== '/' ? `?next=${encodeURIComponent(req.originalUrl)}` : '';
    return res.redirect(`/login${target}`);
  }
  req.user = user;
  return next();
}

module.exports = { readSession, requireApiAuth, requirePageAuth };

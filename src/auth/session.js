'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

function createSessionToken(user) {
  return jwt.sign(
    {
      sub: user.username,
      name: user.displayName,
      email: user.email,
      role: user.role,
    },
    config.session.secret,
    {
      algorithm: 'HS256',
      expiresIn: Math.floor(config.session.ttlMs / 1000),
      issuer: 'soc-platform',
    },
  );
}

function verifySessionToken(token) {
  if (!token) return null;
  try {
    return jwt.verify(token, config.session.secret, {
      algorithms: ['HS256'],
      issuer: 'soc-platform',
    });
  } catch {
    return null;
  }
}

function toPublicUser(payload) {
  return {
    username: payload.sub,
    displayName: payload.name || payload.sub,
    email: payload.email || '',
    role: payload.role === 'admin' ? 'admin' : 'analyst',
  };
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.session.secure,
    maxAge: config.session.ttlMs,
    path: '/',
  };
}

module.exports = { createSessionToken, verifySessionToken, toPublicUser, cookieOptions };

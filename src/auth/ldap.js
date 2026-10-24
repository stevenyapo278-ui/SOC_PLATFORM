'use strict';

// Authentification Active Directory — même mécanisme que Projet_IA_Hub :
// bind UPN « username@domaine » (ou format NTLM via LDAP_BIND_FORMAT), puis relecture de
// l'entrée AD pour le nom affiché et l'email. Le mot de passe n'est jamais stocké ni loggé.

const { Client } = require('ldapts');
const log = require('../logger');

function ldapEscape(value) {
  return String(value).replace(/([\\()*\x00])/g, '\\$1');
}

function attr(entry, name) {
  if (!entry) return undefined;
  const lower = name.toLowerCase();
  const key = Object.keys(entry).find((k) => k.toLowerCase() === lower);
  return key ? entry[key] : undefined;
}

function candidateBindDns(username, ldap) {
  const name = String(username).trim();
  const format = ldap.bindFormat || '{username}@{domain}';
  if (!format.includes('{domain}')) {
    return [format.replace('{username}', name)].filter(Boolean);
  }
  const domains = [];
  for (const domain of [ldap.bindDomain, ldap.emailDomain]) {
    if (domain && !domains.includes(domain)) domains.push(domain);
  }
  if (domains.length === 0) return [name];
  return domains.map((domain) => format.replace('{username}', name).replace('{domain}', domain));
}

function fallbackEmail(username, ldap) {
  return ldap.emailDomain ? `${String(username).trim().toLowerCase()}@${ldap.emailDomain}` : '';
}

function resolveUser(entry, username, ldap) {
  const mail = attr(entry, 'mail');
  const email = typeof mail === 'string' && mail.includes('@') ? mail.trim().toLowerCase() : fallbackEmail(username, ldap);
  const display = attr(entry, 'displayName') || attr(entry, 'cn') || username;
  return {
    username: String(username).trim(),
    displayName: String(display).trim() || String(username).trim(),
    email,
  };
}

function isConfigured(ldap) {
  return Boolean(ldap && ldap.enabled && ldap.url);
}

function isInvalidCredentialError(error) {
  if (!error) return false;
  if (error.code === 49) return true;
  if (/invalidcredential/i.test(String(error.name || ''))) return true;
  if (/invalid credentials/i.test(String(error.message || ''))) return true;
  return /data 52e/i.test(String(error.message || ''));
}

async function authenticateLdap(username, password, ldap) {
  if (!isConfigured(ldap)) {
    const error = new Error('Authentification AD non configurée (LDAP_URL manquant).');
    error.code = 'LDAP_NOT_CONFIGURED';
    throw error;
  }

  const client = new Client({
    url: ldap.url,
    connectTimeout: ldap.connectTimeoutMs,
    timeout: ldap.timeoutMs,
  });

  const candidates = candidateBindDns(username, ldap);
  let lastError = null;
  let invalidCredentials = false;

  log.info('LDAP bind attempt', { url: ldap.url, candidates: candidates.length });

  try {
    if (!/^ldaps:/i.test(ldap.url) && ldap.startTls) {
      await client.startTLS({ rejectUnauthorized: ldap.tlsStrict });
    }

    for (const bindDn of candidates) {
      try {
        await client.bind(bindDn, password);
        log.info('LDAP bind succeeded', { username });

        let resolved = null;
        if (ldap.baseDn) {
          try {
            const { searchEntries } = await client.search(ldap.baseDn, {
              scope: 'sub',
              filter: `(&(objectClass=user)(sAMAccountName=${ldapEscape(username.trim())}))`,
              attributes: ['sAMAccountName', 'mail', 'displayName', 'cn', 'userPrincipalName'],
            });
            const entry = searchEntries.find((item) => attr(item, 'sAMAccountName'));
            if (entry) resolved = resolveUser(entry, username, ldap);
          } catch (searchError) {
            log.warn('LDAP directory search failed, using bind identity', {
              username,
              error: searchError.message,
            });
          }
        }

        return (
          resolved || {
            username: String(username).trim(),
            displayName: String(username).trim(),
            email: fallbackEmail(username, ldap),
          }
        );
      } catch (error) {
        lastError = error;
        if (isInvalidCredentialError(error)) invalidCredentials = true;
        log.warn('LDAP bind rejected', {
          username,
          candidate: bindDn.replace(/^[^@\\]+/, '***'),
          code: error.code || error.name,
          message: error.message,
        });
      }
    }

    if (!invalidCredentials && lastError) {
      throw lastError;
    }
    return null;
  } finally {
    try {
      await client.unbind();
    } catch {
      // socket déjà fermée, sans conséquence
    }
  }
}

module.exports = {
  authenticateLdap,
  candidateBindDns,
  ldapEscape,
  isConfigured,
  _private: { resolveUser, fallbackEmail, attr },
};

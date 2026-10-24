'use strict';

// Couche PostgreSQL minimale : pool pg, migrations SQL simples, prêt pour pgvector.
// Désactivée si DATABASE_URL est absent — la plateforme reste stateless.

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const config = require('../config');
const log = require('../logger');

let pool = null;

function dbEnabled() {
  return Boolean(config.database.enabled && config.database.url);
}

function getPool() {
  if (!dbEnabled()) {
    throw new Error('Base de données non configurée : renseignez DATABASE_URL dans .env.');
  }
  if (!pool) {
    pool = new Pool({
      connectionString: config.database.url,
      max: config.database.poolMax,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    pool.on('error', (error) => log.error('PostgreSQL pool error', { error: error.message }));
  }
  return pool;
}

async function query(text, params) {
  return getPool().query(text, params);
}

async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

// Migrations ordonnées : fichiers numérotés appliqués une fois, suivis dans schema_migrations.
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

function listMigrations() {
  if (!fs.existsSync(MIGRATIONS_DIR)) return [];
  return fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((file) => file.endsWith('.sql'))
    .sort();
}

async function migrate() {
  if (!dbEnabled()) return { applied: 0, skipped: true };

  const p = getPool();
  await p.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const { rows } = await p.query('SELECT name FROM schema_migrations');
  const applied = new Set(rows.map((row) => row.name));
  const pending = listMigrations().filter((name) => !applied.has(name));

  for (const name of pending) {
    const sqlPath = path.join(MIGRATIONS_DIR, name);
    let sql = fs.readFileSync(sqlPath, 'utf8');
    // Dimension des embeddings configurable (vector(N)) — substituée à l'application.
    sql = sql.replace(/\$\{EMBEDDINGS_DIM\}/g, String(config.embeddings.dimension));
    const client = await p.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [name]);
      await client.query('COMMIT');
      log.info('Migration PostgreSQL appliquée', { migration: name });
    } catch (error) {
      await client.query('ROLLBACK');
      log.error('Échec de migration PostgreSQL', { migration: name, error: error.message });
      throw error;
    } finally {
      client.release();
    }
  }

  return { applied: pending.length, skipped: false };
}

module.exports = { dbEnabled, getPool, query, closePool, migrate };

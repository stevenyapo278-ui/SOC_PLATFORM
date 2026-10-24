-- 001_init.sql — schéma initial SOC Sentinel
-- Persistance de l'historique SOC (sync SentinelOne) + socle RAG (embeddings pgvector).

-- ── Suivi des synchronisations ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sync_runs (
  id BIGSERIAL PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'running', -- running | success | partial | error
  threats_count INTEGER NOT NULL DEFAULT 0,
  alerts_count INTEGER NOT NULL DEFAULT 0,
  notes_count INTEGER NOT NULL DEFAULT 0,
  activities_count INTEGER NOT NULL DEFAULT 0,
  error TEXT
);

-- ── Endpoints (cache des agents pour corrélations) ───────────────────────────
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  os_type TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'offline',
  site TEXT NOT NULL DEFAULT '',
  account TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  domain TEXT NOT NULL DEFAULT '',
  machine_type TEXT NOT NULL DEFAULT '',
  infected BOOLEAN NOT NULL DEFAULT false,
  last_active_at TIMESTAMPTZ,
  registered_at TIMESTAMPTZ,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Menaces ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threats (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'unknown',
  classification TEXT NOT NULL DEFAULT '',
  confidence TEXT NOT NULL DEFAULT '',
  mitigation_status TEXT NOT NULL DEFAULT '',
  incident_status TEXT NOT NULL DEFAULT '',
  analyst_verdict TEXT NOT NULL DEFAULT '',
  agent_id TEXT,
  agent_name TEXT NOT NULL DEFAULT '',
  agent_uuid TEXT,
  site TEXT NOT NULL DEFAULT '',
  storyline TEXT,
  file_path TEXT NOT NULL DEFAULT '',
  file_extension TEXT NOT NULL DEFAULT '',
  md5 TEXT,
  sha1 TEXT,
  sha256 TEXT,
  process_user TEXT NOT NULL DEFAULT '',
  originator_process TEXT NOT NULL DEFAULT '',
  process_arguments TEXT NOT NULL DEFAULT '',
  publisher TEXT NOT NULL DEFAULT '',
  initiating_username TEXT NOT NULL DEFAULT '',
  external_ticket_id TEXT NOT NULL DEFAULT '',
  agent_os TEXT NOT NULL DEFAULT '',
  agent_ip TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  agent_network_status TEXT NOT NULL DEFAULT '',
  agent_infected BOOLEAN NOT NULL DEFAULT false,
  mitigation_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threats_storyline ON threats (storyline);
CREATE INDEX IF NOT EXISTS idx_threats_sha256 ON threats (sha256);
CREATE INDEX IF NOT EXISTS idx_threats_agent_id ON threats (agent_id);
CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats (created_at DESC);

-- ── Alertes STAR ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  event_type TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'unknown',
  indicator_category TEXT NOT NULL DEFAULT '',
  indicator_name TEXT NOT NULL DEFAULT '',
  indicator_description TEXT NOT NULL DEFAULT '',
  analyst_verdict TEXT NOT NULL DEFAULT '',
  incident_status TEXT NOT NULL DEFAULT '',
  agent_uuid TEXT,
  agent_name TEXT NOT NULL DEFAULT '',
  agent_os TEXT NOT NULL DEFAULT '',
  site_id TEXT NOT NULL DEFAULT '',
  rule_description TEXT NOT NULL DEFAULT '',
  process_name TEXT NOT NULL DEFAULT '',
  process_path TEXT NOT NULL DEFAULT '',
  process_command_line TEXT NOT NULL DEFAULT '',
  process_user TEXT NOT NULL DEFAULT '',
  sha256 TEXT,
  storyline TEXT,
  dst_ip TEXT NOT NULL DEFAULT '',
  dst_port TEXT NOT NULL DEFAULT '',
  dns_request TEXT NOT NULL DEFAULT '',
  registry_key_path TEXT NOT NULL DEFAULT '',
  login_username TEXT NOT NULL DEFAULT '',
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_storyline ON alerts (storyline);
CREATE INDEX IF NOT EXISTS idx_alerts_sha256 ON alerts (sha256);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_uuid ON alerts (agent_uuid);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);

-- ── Notes d'équipe sur menaces ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_notes (
  id TEXT PRIMARY KEY,
  threat_id TEXT NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
  text TEXT NOT NULL DEFAULT '',
  creator TEXT NOT NULL DEFAULT '',
  edited BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_notes_threat_id ON threat_notes (threat_id);

-- ── Activités console ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activities (
  id TEXT PRIMARY KEY,
  type INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '',
  agent_id TEXT,
  agent_name TEXT NOT NULL DEFAULT '',
  site TEXT NOT NULL DEFAULT '',
  "user" TEXT NOT NULL DEFAULT '',
  threat_id TEXT,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_activities_threat_id ON activities (threat_id);
CREATE INDEX IF NOT EXISTS idx_activities_agent_id ON activities (agent_id);
CREATE INDEX IF NOT EXISTS idx_activities_created_at ON activities (created_at DESC);

-- ── Embeddings (socle RAG — provider branché plus tard) ──────────────────────
-- vector(${EMBEDDINGS_DIM}) : dimension substituée depuis EMBEDDINGS_DIM (défaut 1536).
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS embeddings (
  id BIGSERIAL PRIMARY KEY,
  entity_type TEXT NOT NULL,           -- threat | alert | note | activity
  entity_id TEXT NOT NULL,
  content TEXT NOT NULL,               -- texte source embeddé
  embedding vector(${EMBEDDINGS_DIM}),
  model TEXT NOT NULL DEFAULT '',
  embedded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_embeddings_entity ON embeddings (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_embeddings_vector ON embeddings
  USING hnsw (embedding vector_cosine_ops);

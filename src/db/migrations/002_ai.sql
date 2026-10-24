-- 002_ai.sql — socle IA : providers multi-clés, télémétrie, conversations chatbot.

-- ── Providers IA (pilotés par l'admin, clés en base) ────────────────────────
CREATE TABLE IF NOT EXISTS ai_providers (
  id BIGSERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,              -- openai | anthropic | gemini | mistral | nvidia | cohere
  label TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'openai_compat', -- openai_compat | gemini | anthropic
  base_url TEXT NOT NULL DEFAULT '',
  priority INTEGER NOT NULL DEFAULT 100,  -- plus petit = essayé en premier
  is_active BOOLEAN NOT NULL DEFAULT false,
  is_default BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_keys (
  id BIGSERIAL PRIMARY KEY,
  provider_id BIGINT NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT '',
  api_key TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  is_default BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_keys_provider ON ai_keys (provider_id, is_active);

CREATE TABLE IF NOT EXISTS ai_models (
  id BIGSERIAL PRIMARY KEY,
  provider_id BIGINT NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'CHAT',      -- CHAT | EMBEDDING | RERANK
  is_active BOOLEAN NOT NULL DEFAULT true,
  is_default BOOLEAN NOT NULL DEFAULT false,
  is_deleted BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider_id, name)
);

CREATE INDEX IF NOT EXISTS idx_ai_models_provider ON ai_models (provider_id, type, is_active);

-- ── Télémétrie de consommation ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_usage_log (
  id BIGSERIAL PRIMARY KEY,
  provider TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  usage_context TEXT NOT NULL DEFAULT '', -- chatbot | embedding | voice | background
  source TEXT NOT NULL DEFAULT '',
  user_id TEXT,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  estimated BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_usage_created ON ai_usage_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_usage_context ON ai_usage_log (usage_context, created_at DESC);

-- ── Conversations du chatbot ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS conversations (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT 'Nouvelle conversation',
  pinned BOOLEAN NOT NULL DEFAULT false,
  archived BOOLEAN NOT NULL DEFAULT false,
  summary TEXT,
  state JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations (user_id, archived, updated_at DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
  id BIGSERIAL PRIMARY KEY,
  conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL,                     -- user | assistant
  content TEXT NOT NULL DEFAULT '',
  sources JSONB NOT NULL DEFAULT '[]'::jsonb,
  intent TEXT,
  rating INTEGER,                         -- 1 | -1
  flagged BOOLEAN NOT NULL DEFAULT false,
  tokens_used INTEGER,
  duration_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_conv ON chat_messages (conversation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_chat_messages_user ON chat_messages (user_id, role, created_at DESC);

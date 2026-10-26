-- 009_collaboration.sql — dossiers d'incident locaux : attribution, suivi
-- collaboratif et rapports joints.
--
-- Écriture LOCALE uniquement : SentinelOne n'est jamais contacté (la console
-- reste en lecture seule). Le roster `app_users` est rempli à chaque connexion
-- (LDAP ou compte de dev) — c'est lui qui alimente les sélecteurs de technicien.

-- ── Comptes vus aux connexions ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS app_users (
  username TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'analyst',
  first_login_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Dossier d'incident : 1 ligne par menace attribuée ───────────────────────
CREATE TABLE IF NOT EXISTS incident_cases (
  id BIGSERIAL PRIMARY KEY,
  threat_id TEXT NOT NULL UNIQUE REFERENCES threats(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'nouveau',
  priority TEXT NOT NULL DEFAULT 'moyenne',
  assignee TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incident_cases_assignee ON incident_cases (lower(assignee));
CREATE INDEX IF NOT EXISTS idx_incident_cases_status ON incident_cases (status);
CREATE INDEX IF NOT EXISTS idx_incident_cases_updated ON incident_cases (updated_at DESC);

-- ── Journal immuable du traitement ──────────────────────────────────────────
-- Un COMMENTAIRE est un événement de type `comment` : une seule table sert le
-- fil d'activité et les messages de l'équipe, les deux rendus ne font que
-- filtrer sur `type`. `payload` porte l'avant/après des changements
-- ({"from":"nouveau","to":"en_cours"}).
CREATE TABLE IF NOT EXISTS case_events (
  id BIGSERIAL PRIMARY KEY,
  case_id BIGINT NOT NULL REFERENCES incident_cases(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  author TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events (case_id, created_at DESC, id DESC);

-- ── Rapports d'incident joints au dossier ───────────────────────────────────
-- Octets stockés en PostgreSQL : le container applicatif n'a aucun volume
-- persistant en dehors de soc-pgdata, un rapport doit survivre au rebuild.
CREATE TABLE IF NOT EXISTS case_attachments (
  id BIGSERIAL PRIMARY KEY,
  case_id BIGINT NOT NULL REFERENCES incident_cases(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  size INTEGER NOT NULL DEFAULT 0,
  data BYTEA NOT NULL,
  uploaded_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_attachments_case ON case_attachments (case_id, created_at DESC, id DESC);

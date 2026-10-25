-- 004_applications.sql — inventaire des applications installées par endpoint.
-- Source : GET /agents/applications?ids=<agentId> (1 appel par endpoint, lancé
-- en arrière-plan par src/services/applicationsSync.js). La vue « Applications »
-- se lit ensuite intégralement en SQL, avec jointure sur `agents` pour le nom,
-- l'OS, le site et le statut de la machine.

CREATE TABLE IF NOT EXISTS endpoint_applications (
  agent_id TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  publisher TEXT NOT NULL DEFAULT '',
  size BIGINT,
  installed_at TIMESTAMPTZ,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_applications_name ON endpoint_applications (lower(name));
CREATE INDEX IF NOT EXISTS idx_endpoint_applications_publisher ON endpoint_applications (lower(publisher));
CREATE INDEX IF NOT EXISTS idx_endpoint_applications_agent ON endpoint_applications (agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_applications_synced ON endpoint_applications (synced_at);

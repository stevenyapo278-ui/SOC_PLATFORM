-- 007_agent_history.sql — historique d'identité et de cycle de vie d'un agent.
--
-- Période couverte : ce que SentinelOne ne conserve pas (ou pas au bon endroit)
-- et que l'on peut déduire d'une synchro à l'autre : changement de nom, de série,
-- de MAC, d'IP, de site, d'OS, de version d'agent, première observation,
-- décommission, désinstallation, infection/cure, agent jumeau (même machine_key).
--
-- ON NE TRACE PAS les bascles online/offline : elles ne sont pas une info
-- d'inventaire, juste le bruit du réseau. Re-jouable : IF NOT EXISTS partout.

CREATE TABLE IF NOT EXISTS agent_history (
  id BIGSERIAL PRIMARY KEY,
  agent_id TEXT NOT NULL,
  event TEXT NOT NULL,
  old_value TEXT NOT NULL DEFAULT '',
  new_value TEXT NOT NULL DEFAULT '',
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_history_agent
  ON agent_history (agent_id, detected_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_agent_history_event ON agent_history (event);

-- 005_endpoint_identity.sql — réparation + colonnes d'identité machine.
--
-- 1) Réparations : sur la console réelle, le nom / l'id / le site de l'endpoint
--    d'une menace vivent dans `agentRealtimeInfo` (jamais dans `threatInfo`) et
--    ceux d'une alerte dans `agentDetectionInfo.name` + `agentRealtimeInfo.id`.
--    Les colonnes dénormalisées restaient donc vides : colonne Endpoint vide sur
--    les listes, recherche « par endpoint » inopérante, filtre agentIds mort.
--    Backfill direct depuis le JSONB stocké — aucune re-synchronisation.
-- 2) Identité machine : SentinelOne expose la série (`serialNumber`, 1 311/1 320),
--    les MAC (`networkInterfaces[].physical`, 1 320/1 320), les IP, le modèle,
--    le uuid et le SID sur `/agents`, mais refuse ces champs en filtre (400) :
--    on les projette ici pour pouvoir chercher et regrouper côté SQL.

/* ──────────────────────────── 1. réparations ─────────────────────────────── */

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS agent_id TEXT;

UPDATE threats
   SET agent_id = raw #>> '{agentRealtimeInfo,agentId}'
 WHERE (agent_id IS NULL OR agent_id = '')
   AND raw #>> '{agentRealtimeInfo,agentId}' IS NOT NULL;

UPDATE threats
   SET agent_name = raw #>> '{agentRealtimeInfo,agentComputerName}'
 WHERE agent_name = ''
   AND raw #>> '{agentRealtimeInfo,agentComputerName}' IS NOT NULL;

UPDATE threats
   SET site = COALESCE(raw #>> '{agentRealtimeInfo,siteName}', raw #>> '{agentDetectionInfo,siteName}')
 WHERE site = ''
   AND COALESCE(raw #>> '{agentRealtimeInfo,siteName}', raw #>> '{agentDetectionInfo,siteName}') IS NOT NULL;

UPDATE alerts
   SET agent_id = raw #>> '{agentRealtimeInfo,id}'
 WHERE agent_id IS NULL
   AND raw #>> '{agentRealtimeInfo,id}' IS NOT NULL;

UPDATE alerts
   SET agent_name = COALESCE(raw #>> '{agentDetectionInfo,name}', raw #>> '{agentRealtimeInfo,name}')
 WHERE agent_name = ''
   AND COALESCE(raw #>> '{agentDetectionInfo,name}', raw #>> '{agentRealtimeInfo,name}') IS NOT NULL;

UPDATE alerts
   SET site_id = COALESCE(NULLIF(site_id, ''), raw #>> '{agentDetectionInfo,siteId}')
 WHERE site_id = ''
   AND raw #>> '{agentDetectionInfo,siteId}' IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts (agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_name ON alerts (lower(agent_name)) WHERE agent_name <> '';

/* ─────────────────────── 2. identité machine (agents) ────────────────────── */

ALTER TABLE agents ADD COLUMN IF NOT EXISTS serial_number TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS mac_addresses TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS ip_addresses TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS machine_uuid TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS machine_sid TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS external_id TEXT NOT NULL DEFAULT '';
-- Clé d'identité : `sn:<série>` (une machine peut changer de nom mais garde sa
-- série), sinon `sid:<SID>`, sinon `nom|domaine` (identité approximative).
ALTER TABLE agents ADD COLUMN IF NOT EXISTS machine_key TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS machine_key_source TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_agents_serial_number ON agents (lower(serial_number)) WHERE serial_number <> '';
CREATE INDEX IF NOT EXISTS idx_agents_machine_key ON agents (machine_key) WHERE machine_key <> '';
CREATE INDEX IF NOT EXISTS idx_agents_mac_addresses ON agents USING gin (mac_addresses);

-- 003_sync_cursors.sql — synchro incrémentale (delta) + colonnes manquantes.
--
-- sync_cursors : pointeur « dernière fenêtre synchronisée » par entité. Il vit
-- en base (et pas en mémoire) pour survivre aux redéploiements.
-- Les vues lisent ensuite la base : seules les données manquantes partent vers
-- SentinelOne, filtrées par createdAt/updatedAt/reportedAt.

CREATE TABLE IF NOT EXISTS sync_cursors (
  entity TEXT PRIMARY KEY,
  watermark TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Les agents n'étaient pas persistés (jamais upsertés) : colonne de delta en plus.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_agents_updated_at ON agents (updated_at DESC);

-- Les notes gardaient uniquement les colonnes projetées : on stocke le brut
-- pour pouvoir les relire avec le même normaliseur que l'API.
ALTER TABLE threat_notes ADD COLUMN IF NOT EXISTS raw JSONB;

-- Filtres des vues (tri par gravité / verdict sur les listes).
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_analyst_verdict ON alerts (analyst_verdict);
CREATE INDEX IF NOT EXISTS idx_threats_analyst_verdict ON threats (analyst_verdict);

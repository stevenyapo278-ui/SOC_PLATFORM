-- 006_machine_tags.sql — étiquettes SOC posées à la main sur une machine.
--
-- La plateforme reste 100 % lecture seule côté SentinelOne : ces tags vivent
-- UNIQUEMENT dans notre base, ne sont jamais renvoyés à l'API et survit donc à
-- une réinstallation d'agent tant que la clé d'identité (machine_key) est
-- conservée. Re-jouable : IF NOT EXISTS partout.

CREATE TABLE IF NOT EXISTS machine_tags (
  machine_key TEXT NOT NULL,
  tag TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (machine_key, tag)
);

CREATE INDEX IF NOT EXISTS idx_machine_tags_tag ON machine_tags (lower(tag));
CREATE INDEX IF NOT EXISTS idx_machine_tags_machine ON machine_tags (machine_key);

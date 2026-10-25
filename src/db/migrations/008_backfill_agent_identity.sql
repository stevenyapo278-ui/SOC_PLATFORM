-- 008_backfill_agent_identity.sql — identité machine recalculée depuis `raw`.
--
-- Les agents enregistrés avant l'ajout des colonnes d'identité (1 252 des
-- 1 321 endpoints) n'avaient jamais été relu : la synchro delta ne retombe sur
-- un agent que si SentinelOne signale une modification récente. Ces lignes
-- gardaient donc machine_key / serial_number vides, et la vue Machines — qui
-- ne regroupe que les lignes ayant une clé — n'affichait que 69 machines là où
-- le dashboard annonce 1 321 endpoints.
--
-- Calcul 100 % SQL, sans appel à SentinelOne, strictement équivalent à
-- normalizeAgent() + machineIdentity() :
--   série (hors valeurs BIOS poubelle) → SID → nom|domaine → id.
-- Re-jouable : ne cible que les lignes dont la clé est encore vide.

WITH target AS (
  SELECT
    a.id,
    a.raw,
    btrim(COALESCE(a.raw #>> '{computerName}', a.raw #>> '{name}', '')) AS raw_name,
    btrim(COALESCE(a.raw ->> 'domain', '')) AS raw_domain,
    btrim(COALESCE(a.raw ->> 'serialNumber', '')) AS serial_raw,
    btrim(COALESCE(a.raw ->> 'modelName', '')) AS model,
    btrim(COALESCE(a.raw ->> 'uuid', '')) AS machine_uuid,
    btrim(COALESCE(a.raw ->> 'machineSid', '')) AS machine_sid,
    btrim(COALESCE(a.raw ->> 'externalId', '')) AS external_id
  FROM agents a
  WHERE a.machine_key = ''
    AND a.raw IS NOT NULL
    AND jsonb_typeof(a.raw) = 'object'
),

-- Nom / domaine normalisés exactement comme normalizeAgent() (valeurs par
-- défaut incluses) : la clé `name:` en dépend.
norm AS (
  SELECT
    t.*,
    CASE WHEN t.raw_name = '' THEN 'Endpoint inconnu' ELSE t.raw_name END AS name,
    CASE WHEN t.raw_domain = '' THEN '—' ELSE t.raw_domain END AS domain
  FROM target t
),

serials AS (
  SELECT
    id,
    CASE
      WHEN lower(serial_raw) IN (
        'default string', 'to be filled by o.e.m.', 'system serial number',
        'chassis serial number', 'not specified', 'not applicable', 'none',
        'null', 'n/a', 'na', 'oem', 'invalid', '0', '123456789', '0123456789'
      ) THEN ''
      ELSE serial_raw
    END AS serial
  FROM norm
),

-- MAC : networkInterfaces[].physical, minuscules + tirets normalisés, loopback
-- retirée, doublons éliminés (première occurrence conservée) puis majuscules.
mac_source AS (
  SELECT
    n.id,
    lower(replace(btrim(elem.value #>> '{physical}'), '-', ':')) AS mac,
    min(elem.ord::int) AS ord
  FROM norm n
  LEFT JOIN LATERAL jsonb_array_elements(
    CASE
      WHEN jsonb_typeof(n.raw -> 'networkInterfaces') = 'array'
        THEN n.raw -> 'networkInterfaces'
      ELSE '[]'::jsonb
    END
  ) WITH ORDINALITY AS elem(value, ord) ON true
  WHERE elem.value #>> '{physical}' IS NOT NULL
  GROUP BY n.id, lower(replace(btrim(elem.value #>> '{physical}'), '-', ':'))
),
macs AS (
  SELECT id, array_agg(upper(mac) ORDER BY ord) AS mac_addresses
  FROM mac_source
  WHERE mac ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
    AND mac <> '00:00:00:00:00:00'
  GROUP BY id
),

-- IPv4 : toutes les inet de chaque interface, puis lastIpToMgmt et externalIp,
-- doublons retirés en conservant l'ordre de découverte.
ip_source AS (
  SELECT
    n.id,
    btrim(ip_el.value) AS ip,
    (e.ord::int * 1000 + ip_el.ord::int) AS ord
  FROM norm n
  LEFT JOIN LATERAL jsonb_array_elements(
    CASE
      WHEN jsonb_typeof(n.raw -> 'networkInterfaces') = 'array'
        THEN n.raw -> 'networkInterfaces'
      ELSE '[]'::jsonb
    END
  ) WITH ORDINALITY AS e(value, ord) ON true
  LEFT JOIN LATERAL jsonb_array_elements_text(
    CASE
      WHEN jsonb_typeof(e.value -> 'inet') = 'array'
        THEN e.value -> 'inet'
      ELSE '[]'::jsonb
    END
  ) WITH ORDINALITY AS ip_el(value, ord) ON true
  WHERE ip_el.value IS NOT NULL
  UNION ALL
  SELECT n.id, btrim(n.raw ->> 'lastIpToMgmt'), 100000
  FROM norm n
  WHERE btrim(COALESCE(n.raw ->> 'lastIpToMgmt', '')) <> ''
  UNION ALL
  SELECT n.id, btrim(n.raw ->> 'externalIp'), 100001
  FROM norm n
  WHERE btrim(COALESCE(n.raw ->> 'externalIp', '')) <> ''
),
ip_dedup AS (
  SELECT id, ip, min(ord) AS ord
  FROM ip_source
  WHERE ip ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
    AND NOT EXISTS (
      SELECT 1 FROM unnest(string_to_array(ip, '.')) part WHERE part::int > 255
    )
  GROUP BY id, ip
),
ips AS (
  SELECT id, array_agg(ip ORDER BY ord) AS ip_addresses
  FROM ip_dedup
  GROUP BY id
)

UPDATE agents a
SET
  serial_number = s.serial,
  mac_addresses = COALESCE(m.mac_addresses, '{}'::text[]),
  ip_addresses = COALESCE(i.ip_addresses, '{}'::text[]),
  model = n.model,
  machine_uuid = n.machine_uuid,
  machine_sid = n.machine_sid,
  external_id = n.external_id,
  machine_key = CASE
    WHEN s.serial <> '' THEN 'sn:' || lower(s.serial)
    WHEN n.machine_sid <> '' THEN 'sid:' || lower(n.machine_sid)
    WHEN lower(n.name) <> 'endpoint inconnu'
      THEN 'name:' || lower(n.name) || '|' || lower(n.domain)
    ELSE 'id:' || n.id
  END,
  machine_key_source = CASE
    WHEN s.serial <> '' THEN 'serial'
    WHEN n.machine_sid <> '' THEN 'sid'
    WHEN lower(n.name) <> 'endpoint inconnu' THEN 'name'
    ELSE 'id'
  END,
  first_seen_at = COALESCE(a.first_seen_at, a.registered_at),
  last_seen_at = COALESCE(a.last_seen_at, a.last_active_at)
FROM norm n
JOIN serials s ON s.id = n.id
LEFT JOIN macs m ON m.id = n.id
LEFT JOIN ips i ON i.id = n.id
WHERE a.id = n.id
  AND a.machine_key = '';

'use strict';

// Administration des providers IA (Paramètres > IA) — réservé au rôle admin.
// Les clés API ne ressortent JAMAIS en clair : masquées côté lecture.

const { Router } = require('express');
const { query } = require('../db');
const { invalidateProviderCache, getActiveProviders } = require('../ai/providers');
const { getBreaker, allBreakerStatuses } = require('../ai/circuitBreaker');
const { getAiUsageStats } = require('../ai/usageTracker');
const log = require('../logger');

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès réservé aux administrateurs.' });
  }
  return next();
}

function maskKey(key) {
  if (!key || key.length < 8) return '••••';
  return `${key.substring(0, 4)}…${key.substring(key.length - 4)}`;
}

const PROVIDER_KIND_BY_NAME = {
  openai: 'openai_compat',
  mistral: 'openai_compat',
  nvidia: 'openai_compat',
  cohere: 'openai_compat',
  anthropic: 'anthropic',
  gemini: 'gemini',
};

const router = Router();
router.use(requireAdmin);

// GET /api/ai/providers — liste complète (clés masquées)
router.get('/providers', async (req, res) => {
  try {
    const { rows: providers } = await query(
      `SELECT id, name, label, kind, base_url, priority, is_active, is_default, created_at
       FROM ai_providers ORDER BY priority ASC, label ASC`,
    );
    const { rows: keys } = await query(
      `SELECT id, provider_id, label, api_key, is_active, is_default FROM ai_keys ORDER BY is_default DESC, id ASC`,
    );
    const { rows: models } = await query(
      `SELECT id, provider_id, name, label, type, is_active, is_default, is_deleted
       FROM ai_models ORDER BY type ASC, is_default DESC, id ASC`,
    );

    res.json(
      providers.map((p) => ({
        id: Number(p.id),
        name: p.name,
        label: p.label,
        kind: p.kind,
        baseUrl: p.base_url,
        priority: p.priority,
        isActive: p.is_active === true,
        isDefault: p.is_default === true,
        keys: keys
          .filter((k) => Number(k.provider_id) === Number(p.id))
          .map((k) => ({
            id: Number(k.id),
            label: k.label,
            masked: maskKey(k.api_key),
            isActive: k.is_active === true,
            isDefault: k.is_default === true,
          })),
        models: models
          .filter((m) => Number(m.provider_id) === Number(p.id) && m.is_deleted !== true)
          .map((m) => ({
            id: Number(m.id),
            name: m.name,
            label: m.label,
            type: m.type,
            isActive: m.is_active === true,
            isDefault: m.is_default === true,
          })),
      })),
    );
  } catch (error) {
    log.error('Lecture providers IA impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur de chargement des providers.' });
  }
});

// POST /api/ai/providers — créer un provider
router.post('/providers', async (req, res) => {
  try {
    const { name, label, baseUrl = '', priority = 100 } = req.body || {};
    const clean = String(name || '').trim().toLowerCase();
    if (!/^[a-z][a-z0-9_-]{1,40}$/.test(clean)) {
      return res.status(400).json({ error: 'Nom de provider invalide (lettres, chiffres, tirets).' });
    }
    const kind = PROVIDER_KIND_BY_NAME[clean] || req.body.kind || 'openai_compat';
    const { rows } = await query(
      `INSERT INTO ai_providers (name, label, kind, base_url, priority, is_active)
       VALUES ($1, $2, $3, $4, $5, false)
       ON CONFLICT (name) DO UPDATE SET label = EXCLUDED.label
       RETURNING id, name, label, kind, base_url, priority, is_active, is_default`,
      [clean, String(label || clean).trim(), kind, String(baseUrl || '').trim(), Number(priority) || 100],
    );
    invalidateProviderCache();
    const p = rows[0];
    res.status(201).json({
      id: Number(p.id),
      name: p.name,
      label: p.label,
      kind: p.kind,
      baseUrl: p.base_url,
      priority: p.priority,
      isActive: p.is_active === true,
      isDefault: p.is_default === true,
      keys: [],
      models: [],
    });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Ce provider existe déjà.' });
    log.error('Création provider IA impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur de création du provider.' });
  }
});

// PATCH /api/ai/providers/:id — activer/désactiver, priorité, défaut, base URL
router.patch('/providers/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { isActive, isDefault, priority, baseUrl, label } = req.body || {};
    const fields = [];
    const values = [];
    const add = (column, value) => {
      values.push(value);
      fields.push(`${column} = $${values.length}`);
    };
    if (isActive !== undefined) add('is_active', isActive === true);
    if (priority !== undefined) add('priority', Number(priority) || 100);
    if (baseUrl !== undefined) add('base_url', String(baseUrl).trim());
    if (label !== undefined) add('label', String(label).trim());
    if (isDefault === true) {
      await query(`UPDATE ai_providers SET is_default = false WHERE is_default`);
      add('is_default', true);
    } else if (isDefault === false) {
      add('is_default', false);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'Aucun champ à mettre à jour.' });
    values.push(id);
    const { rows } = await query(
      `UPDATE ai_providers SET ${fields.join(', ')}, updated_at = now() WHERE id = $${values.length} RETURNING id`,
      values,
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Provider introuvable.' });
    invalidateProviderCache();
    res.json({ ok: true });
  } catch (error) {
    log.error('Mise à jour provider IA impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur de mise à jour.' });
  }
});

// DELETE /api/ai/providers/:id
router.delete('/providers/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    await query(`DELETE FROM ai_providers WHERE id = $1`, [id]);
    invalidateProviderCache();
    res.json({ ok: true });
  } catch (error) {
    log.error('Suppression provider IA impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur de suppression.' });
  }
});

// POST /api/ai/providers/:id/keys — ajouter une clé
router.post('/providers/:id/keys', async (req, res) => {
  try {
    const providerId = Number(req.params.id);
    const apiKey = String((req.body && req.body.apiKey) || '').trim();
    const label = String((req.body && req.body.label) || '').trim();
    if (apiKey.length < 8) return res.status(400).json({ error: 'Clé API trop courte.' });
    const { rows } = await query(
      `INSERT INTO ai_keys (provider_id, label, api_key) VALUES ($1, $2, $3) RETURNING id`,
      [providerId, label, apiKey],
    );
    invalidateProviderCache();
    res.status(201).json({ id: Number(rows[0].id), masked: maskKey(apiKey) });
  } catch (error) {
    log.error('Ajout clé IA impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur d’ajout de la clé.' });
  }
});

// PATCH /api/ai/keys/:id — activer/désactiver
router.patch('/keys/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const isActive = req.body && req.body.isActive;
    await query(`UPDATE ai_keys SET is_active = $1 WHERE id = $2`, [isActive !== false, id]);
    invalidateProviderCache();
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de mise à jour.' });
  }
});

// DELETE /api/ai/keys/:id
router.delete('/keys/:id', async (req, res) => {
  try {
    await query(`DELETE FROM ai_keys WHERE id = $1`, [Number(req.params.id)]);
    invalidateProviderCache();
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de suppression.' });
  }
});

// POST /api/ai/providers/:id/models — ajouter un modèle
router.post('/providers/:id/models', async (req, res) => {
  try {
    const providerId = Number(req.params.id);
    const name = String((req.body && req.body.name) || '').trim();
    const label = String((req.body && req.body.label) || '').trim();
    const type = ['CHAT', 'EMBEDDING', 'RERANK'].includes(req.body && req.body.type) ? req.body.type : 'CHAT';
    if (!name) return res.status(400).json({ error: 'Nom de modèle requis.' });
    const { rows } = await query(
      `INSERT INTO ai_models (provider_id, name, label, type)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (provider_id, name) DO UPDATE SET label = EXCLUDED.label, type = EXCLUDED.type, is_deleted = false
       RETURNING id`,
      [providerId, name, label || name, type],
    );
    invalidateProviderCache();
    res.status(201).json({ id: Number(rows[0].id) });
  } catch (error) {
    log.error('Ajout modèle IA impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur d’ajout du modèle.' });
  }
});

// PATCH /api/ai/models/:id
router.patch('/models/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { isActive, isDefault, type } = req.body || {};
    const fields = [];
    const values = [];
    if (isActive !== undefined) {
      values.push(isActive === true);
      fields.push(`is_active = $${values.length}`);
    }
    if (type !== undefined && ['CHAT', 'EMBEDDING', 'RERANK'].includes(type)) {
      values.push(type);
      fields.push(`type = $${values.length}`);
    }
    if (isDefault === true) {
      const { rows: modelRows } = await query(`SELECT provider_id FROM ai_models WHERE id = $1`, [id]);
      if (modelRows.length > 0) {
        await query(`UPDATE ai_models SET is_default = false WHERE provider_id = $1`, [modelRows[0].provider_id]);
      }
      fields.push('is_default = true');
    } else if (isDefault === false) {
      fields.push('is_default = false');
    }
    if (fields.length === 0) return res.status(400).json({ error: 'Aucun champ à mettre à jour.' });
    values.push(id);
    await query(`UPDATE ai_models SET ${fields.join(', ')} WHERE id = $${values.length}`, values);
    invalidateProviderCache();
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de mise à jour.' });
  }
});

// DELETE /api/ai/models/:id (soft delete)
router.delete('/models/:id', async (req, res) => {
  try {
    await query(`UPDATE ai_models SET is_deleted = true, is_active = false WHERE id = $1`, [Number(req.params.id)]);
    invalidateProviderCache();
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de suppression.' });
  }
});

// GET /api/ai/usage?days=7 — consommation
router.get('/usage', async (req, res) => {
  try {
    const days = Math.min(Math.max(Number(req.query.days) || 7, 1), 90);
    const stats = await getAiUsageStats(days);
    res.json({ days, stats });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de chargement de la consommation.' });
  }
});

// GET /api/ai/status — providers actifs + disjoncteurs
router.get('/status', async (req, res) => {
  try {
    const providers = await getActiveProviders({ modelType: 'CHAT' });
    res.json({
      providers: providers.map((p) => ({
        name: p.name,
        label: p.label,
        kind: p.kind,
        models: p.models.map((m) => m.name),
      })),
      breakers: allBreakerStatuses(),
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de statut IA.' });
  }
});

// POST /api/ai/test — test d'appel simple sur le premier provider actif
router.post('/test', async (req, res) => {
  const { callProviderWithFallback, callAiWithRetry } = require('../ai/providers');
  try {
    const startedAt = Date.now();
    const result = await callAiWithRetry(
      () =>
        callProviderWithFallback('Réponds uniquement : OK', 'chattest', {
          messages: [{ role: 'user', content: 'Réponds uniquement : OK' }],
          maxTokens: 16,
          temperature: 0,
          source: 'test',
        }),
      { maxRetries: 1 },
    );
    res.json({ ok: true, reply: (result.text || '').substring(0, 200), durationMs: Date.now() - startedAt });
  } catch (error) {
    res.status(502).json({ ok: false, error: error.message });
  }
});

module.exports = router;

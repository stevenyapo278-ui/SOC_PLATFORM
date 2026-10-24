'use strict';

// Chat SOC : conversations, messages, streaming SSE, quota, feedback.

const { Router } = require('express');
const rateLimit = require('express-rate-limit');
const { query } = require('../db');
const config = require('../config');
const { requireApiAuth } = require('../middleware/auth');
const { handleMessage } = require('../services/chatbotService');
const log = require('../logger');

const router = Router();
router.use(requireApiAuth);

if (config.ai.chatEnabled) {
  router.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: config.ai.rateLimitMax,
      keyGenerator: (req) => `chat:${req.user.username}`,
      message: { error: 'Trop de messages. Réessayez dans quelques minutes.' },
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );
}

// ── Détection d'injection (log uniquement) ───────────────────────────────────
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
  /you\s+are\s+now\s+(a|an|the)/i,
  /act\s+as\s+if\s+(you\s+are|you\s+were)/i,
  /disregard\s+(all|any|your)\s+(previous|prior|instructions?)/i,
  /system\s*:\s*/i,
  /reveal\s+(your|the)\s+(system|original)\s+prompt/i,
  /quel\s+est\s+(ton|votre)\s+prompt\s+(syst[eè]me|initial)/i,
  /donne[- ]moi\s+(ton|votre)\s+(prompt|instruction)/i,
];

function detectPromptInjection(message) {
  return INJECTION_PATTERNS.some((pattern) => pattern.test(message));
}

function generateTitle(message) {
  const clean = message.replace(/\n/g, ' ').trim();
  return clean.length <= 40 ? clean : `${clean.substring(0, 40).trim()}…`;
}

async function dailyQuotaCheck(req, res, next) {
  if (!config.ai.chatEnabled) {
    return res.status(503).json({ error: 'Assistant IA désactivé sur cette instance.' });
  }
  try {
    const { rows } = await query(
      `SELECT count(*)::int AS n FROM chat_messages
       WHERE user_id = $1 AND role = 'user' AND created_at >= date_trunc('day', now())`,
      [req.user.username],
    );
    if (rows[0].n >= config.ai.dailyQuota) {
      return res.status(429).json({
        error: `Quota journalier atteint (${config.ai.dailyQuota} messages/jour). Réessayez demain.`,
        quotaUsed: rows[0].n,
        quotaMax: config.ai.dailyQuota,
      });
    }
    req.chatQuotaUsed = rows[0].n;
    return next();
  } catch (error) {
    return next();
  }
}

// ── CRUD conversations ───────────────────────────────────────────────────────

router.get('/conversations', async (req, res) => {
  try {
    const archivedOnly = req.query.archived === 'true' || req.query.archived === 'only';
    const { rows } = await query(
      `SELECT c.id, c.title, c.pinned, c.archived, c.created_at, c.updated_at,
              (SELECT count(*)::int FROM chat_messages m WHERE m.conversation_id = c.id) AS message_count,
              (SELECT m.content FROM chat_messages m WHERE m.conversation_id = c.id AND m.role = 'assistant'
               ORDER BY m.created_at DESC LIMIT 1) AS last_reply
       FROM conversations c
       WHERE c.user_id = $1 AND c.archived = $2
       ORDER BY c.pinned DESC, c.updated_at DESC
       LIMIT 100`,
      [req.user.username, archivedOnly],
    );
    res.json(
      rows.map((c) => ({
        id: Number(c.id),
        title: c.title,
        pinned: c.pinned === true,
        archived: c.archived === true,
        messageCount: c.message_count,
        lastReply: c.last_reply ? c.last_reply.substring(0, 120) : null,
        createdAt: c.created_at,
        updatedAt: c.updated_at,
      })),
    );
  } catch (error) {
    log.error('Lecture conversations impossible', { error: error.message });
    res.status(500).json({ error: 'Erreur de chargement.' });
  }
});

router.post('/conversations', async (req, res) => {
  try {
    const { rows } = await query(
      `INSERT INTO conversations (user_id, title) VALUES ($1, 'Nouvelle conversation') RETURNING id, title, created_at`,
      [req.user.username],
    );
    res.status(201).json({ id: Number(rows[0].id), title: rows[0].title, createdAt: rows[0].created_at });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de création.' });
  }
});

router.patch('/conversations/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { title, pinned, archived } = req.body || {};
    const fields = [];
    const values = [];
    if (title !== undefined) {
      values.push(String(title).substring(0, 120));
      fields.push(`title = $${values.length}`);
    }
    if (pinned !== undefined) {
      values.push(pinned === true);
      fields.push(`pinned = $${values.length}`);
    }
    if (archived !== undefined) {
      values.push(archived === true);
      fields.push(`archived = $${values.length}`);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'Aucun champ.' });
    values.push(id, req.user.username);
    const { rows } = await query(
      `UPDATE conversations SET ${fields.join(', ')}, updated_at = now()
       WHERE id = $${values.length - 1} AND user_id = $${values.length}
       RETURNING id`,
      values,
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Conversation introuvable.' });
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de mise à jour.' });
  }
});

router.delete('/conversations/:id', async (req, res) => {
  try {
    const { rows } = await query(`DELETE FROM conversations WHERE id = $1 AND user_id = $2 RETURNING id`, [
      Number(req.params.id),
      req.user.username,
    ]);
    if (rows.length === 0) return res.status(404).json({ error: 'Conversation introuvable.' });
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur de suppression.' });
  }
});

// ── Envoi d'un message (SSE optionnel ?stream=1) ─────────────────────────────

router.post('/', dailyQuotaCheck, async (req, res) => {
  const startedAt = Date.now();
  const streaming = req.query.stream === '1' && req.accepts('text/event-stream') !== false;
  const sse = (event, data) => {
    if (!res.writableEnded) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  const onToolEvent = streaming ? ({ name, phase }) => sse('tool', { name, phase, elapsedMs: Date.now() - startedAt }) : undefined;

  if (streaming) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    const heartbeat = setInterval(() => {
      if (!res.writableEnded) res.write(': ping\n\n');
    }, 15000);
    res.on('close', () => clearInterval(heartbeat));
  }

  try {
    const { message, conversationId } = req.body || {};
    if (!message || !message.trim()) {
      const status = 400;
      if (streaming) {
        sse('error', { error: 'Le message ne peut pas être vide.' });
        res.end();
      } else {
        res.status(status).json({ error: 'Le message ne peut pas être vide.' });
      }
      return;
    }

    const flagged = detectPromptInjection(message);

    let convId = conversationId ? Number.parseInt(conversationId, 10) || null : null;
    if (convId) {
      const { rows } = await query(`SELECT id FROM conversations WHERE id = $1 AND user_id = $2`, [convId, req.user.username]);
      if (rows.length === 0) {
        if (streaming) {
          sse('error', { error: 'Conversation introuvable.' });
          res.end();
        } else {
          res.status(404).json({ error: 'Conversation introuvable.' });
        }
        return;
      }
    } else {
      const { rows } = await query(
        `INSERT INTO conversations (user_id, title) VALUES ($1, $2) RETURNING id`,
        [req.user.username, generateTitle(message.trim())],
      );
      convId = Number(rows[0].id);
    }

    await query(
      `INSERT INTO chat_messages (conversation_id, user_id, role, content, flagged) VALUES ($1, $2, 'user', $3, $4)`,
      [convId, req.user.username, message.trim(), flagged],
    );
    await query(`UPDATE conversations SET updated_at = now() WHERE id = $1`, [convId]);

    if (flagged) {
      log.warn('Tentative d’injection de prompt détectée', { user: req.user.username, message: message.substring(0, 200) });
    }

    const { rows: historyRows } = await query(
      `SELECT role, content FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at ASC LIMIT 40`,
      [convId],
    );
    const history = historyRows.map((m) => ({ role: m.role, content: m.content }));

    let result;
    try {
      result = await handleMessage(message.trim(), history, req.user, { onToolEvent });
    } catch (error) {
      log.error('Échec handleMessage', { error: error.message });
      result = {
        reply:
          'Désolé, je n’ai pas pu traiter cette demande (aucun provider IA disponible ou erreur interne). Réessayez ou vérifiez la configuration IA dans Paramètres.',
        sources: [],
        toolsUsed: [],
        durationMs: Date.now() - startedAt,
      };
    }

    const durationMs = Date.now() - startedAt;
    const tokensUsed = Math.ceil(message.length / 4) + Math.ceil((result.reply || '').length / 4);

    await query(
      `INSERT INTO chat_messages (conversation_id, user_id, role, content, sources, tokens_used, duration_ms)
       VALUES ($1, $2, 'assistant', $3, $4::jsonb, $5, $6)`,
      [convId, req.user.username, result.reply, JSON.stringify(result.sources || []), tokensUsed, durationMs],
    );

    const payload = {
      reply: result.reply,
      sources: result.sources || [],
      toolsUsed: result.toolsUsed || [],
      conversationId: convId,
      durationMs,
    };

    if (streaming) {
      sse('final', payload);
      res.end();
    } else {
      res.json(payload);
    }
  } catch (error) {
    log.error('Erreur /api/chat', { error: error.message });
    if (streaming) {
      sse('error', { error: 'Erreur interne du chatbot.' });
      res.end();
    } else {
      res.status(500).json({ error: 'Erreur interne du chatbot.' });
    }
  }
});

// ── Historique ───────────────────────────────────────────────────────────────

router.get('/history', async (req, res) => {
  try {
    const { conversationId } = req.query;
    const limit = conversationId ? 200 : 50;
    const params = [req.user.username];
    let where = 'user_id = $1';
    if (conversationId) {
      params.push(Number(conversationId));
      where += ` AND conversation_id = $${params.length}`;
    }
    params.push(String(limit));
    const { rows } = await query(
      `SELECT id, conversation_id, role, content, sources, rating, created_at
       FROM chat_messages WHERE ${where} ORDER BY created_at ASC LIMIT $${params.length}`,
      params,
    );
    res.json(
      rows.map((m) => ({
        id: Number(m.id),
        conversationId: m.conversation_id ? Number(m.conversation_id) : null,
        role: m.role,
        content: m.content,
        sources: m.sources || [],
        rating: m.rating,
        createdAt: m.created_at,
      })),
    );
  } catch (error) {
    res.status(500).json({ error: 'Erreur de chargement.' });
  }
});

router.delete('/history', async (req, res) => {
  try {
    const { conversationId } = req.query;
    if (conversationId) {
      await query(`DELETE FROM conversations WHERE id = $1 AND user_id = $2`, [Number(conversationId), req.user.username]);
    } else {
      await query(`DELETE FROM chat_messages WHERE user_id = $1`, [req.user.username]);
      await query(`DELETE FROM conversations WHERE user_id = $1`, [req.user.username]);
    }
    res.json({ ok: true, message: 'Historique réinitialisé.' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur.' });
  }
});

// ── Feedback ─────────────────────────────────────────────────────────────────

router.post('/feedback', async (req, res) => {
  try {
    const { messageId, rating } = req.body || {};
    if (!messageId || ![1, -1].includes(rating)) {
      return res.status(400).json({ error: 'Paramètres invalides.' });
    }
    await query(
      `UPDATE chat_messages SET rating = $1 WHERE id = $2 AND user_id = $3 AND role = 'assistant'`,
      [rating, Number(messageId), req.user.username],
    );
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur.' });
  }
});

module.exports = router;

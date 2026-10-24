'use strict';

// Chatbot SOC — assistant d'analyste en français, lecture seule.
// Boucle agentic bornée (tools désactivés au dernier tour), sources RAG citées.

const config = require('../config');
const log = require('../logger');
const { query } = require('../db');
const { callProviderWithFallback, callAiWithRetry } = require('../ai/providers');
const { searchRag } = require('./ragSearch');

// ── Prompt système ───────────────────────────────────────────────────────────
function getDateContextLine() {
  const now = new Date();
  const days = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
  const months = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
  return `[Date du jour : ${days[now.getDay()]} ${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()}]`;
}

const SYSTEM_PROMPT = `Tu es l'assistant IA de la plateforme SOC Sentinel, une console de supervision SentinelOne. Tu t'adresses à des analystes SOC en français.

Tes capacités :
- Rechercher des menaces, alertes STAR, activités et notes d'équipe (lecture seule — tu ne peux AUCUNE action sur SentinelOne).
- Consulter le détail d'une enquête (menace, timeline, corrélation storyline/hash).
- Calculer des statistiques (gravité, verdicts, endpoints infectés).
- Rechercher dans la base sémantique (RAG) : notes d'équipe et synthèses passées.

Règles :
- Réponds toujours en français, de façon concise et factuelle.
- Cite systématiquement tes sources (menaces, alertes, notes) quand tu en utilises.
- N'invente JAMAIS de donnée : si un outil ne renvoie rien, dis-le clairement.
- Pour une question temporelle, interprète-la par rapport à la date injectée ci-dessous.
- Tu es en lecture seule : propose plutôt ce qu'un analyste pourrait faire manuellement dans la console.`;

// ── Outils (lecture seule) ──────────────────────────────────────────────────
const ALL_TOOLS = [
  {
    type: 'function',
    function: {
      name: 'search_rag',
      description: "Recherche sémantique dans la base SOC (notes d'équipe, synthèses, documents indexés). À utiliser pour les questions de type « qu'est-ce qu'on a déjà vu », « notes sur… ».",
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Requête de recherche en français' },
          topK: { type: 'integer', description: 'Nombre de résultats (5-15, défaut 8)' },
        },
        required: ['query'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'search_threats',
      description: 'Liste les menaces détectées avec filtres optionnels (gravité, verdict, endpoint, période en jours).',
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Filtre texte sur le nom de menace (optionnel)' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], description: 'Gravité' },
          analystVerdict: { type: 'string', enum: ['true_positive', 'false_positive', 'suspicious', 'undefined'], description: 'Verdict analyste' },
          agentName: { type: 'string', description: 'Nom d’endpoint' },
          days: { type: 'integer', description: 'Période en jours (défaut 30)' },
          limit: { type: 'integer', description: 'Nombre de résultats (défaut 10, max 50)' },
        },
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_threat',
      description: "Détail complet d'une menace par son identifiant : fichier, process, agent, mitigation, storyline.",
      parameters: {
        type: 'object',
        properties: { threatId: { type: 'string', description: 'Identifiant de la menace (ex: t1)' } },
        required: ['threatId'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'search_alerts',
      description: 'Liste les alertes STAR avec filtres optionnels (gravité, verdict, période en jours).',
      parameters: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          analystVerdict: { type: 'string', enum: ['true_positive', 'false_positive', 'suspicious', 'undefined'] },
          days: { type: 'integer', description: 'Période en jours (défaut 30)' },
          limit: { type: 'integer', description: 'Nombre de résultats (défaut 10, max 50)' },
        },
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'search_activities',
      description: "Journal des activités console (actions des analystes, événements). Filtres : menace liée, endpoint, période.",
      parameters: {
        type: 'object',
        properties: {
          threatId: { type: 'string', description: 'Filtrer par menace liée' },
          agentName: { type: 'string', description: 'Filtrer par endpoint' },
          days: { type: 'integer', description: 'Période en jours (défaut 7)' },
          limit: { type: 'integer', description: 'Nombre de résultats (défaut 15, max 50)' },
        },
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'search_notes',
      description: "Notes d'équipe laissées sur les menaces. Utile pour retrouver le contexte d'analyse d'un analyste.",
      parameters: {
        type: 'object',
        properties: {
          threatId: { type: 'string', description: 'Filtrer par menace' },
          limit: { type: 'integer', description: 'Nombre de résultats (défaut 15, max 50)' },
        },
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_stats',
      description: 'Statistiques agrégées : menaces et alertes par gravité/verdict, endpoints les plus touchés, sur une période.',
      parameters: {
        type: 'object',
        properties: { days: { type: 'integer', description: 'Période en jours (défaut 30)' } },
        required: [],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'get_agent_context',
      description: "Contexte endpoint : nombre de menaces, dernière activité, menaces récentes sur une machine donnée.",
      parameters: {
        type: 'object',
        properties: { agentName: { type: 'string', description: 'Nom de l’endpoint' } },
        required: ['agentName'],
      },
    },
  },
];

// ── Exécution des outils ─────────────────────────────────────────────────────
async function execSearchRag(args) {
  const results = await searchRag(args.query, { topK: args.topK || 8 });
  return results.map((r) => ({ kind: r.kind, score: r.score, extrait: r.content.substring(0, 400) }));
}

async function execSearchThreats(args) {
  const limit = Math.min(Math.max(Number(args.limit) || 10, 1), 50);
  const days = Math.min(Math.max(Number(args.days) || 30, 1), 365);
  const conditions = [`created_at >= now() - ($${1} || ' days')::interval`];
  const params = [String(days)];
  if (args.severity) {
    params.push(args.severity);
    conditions.push(`severity = $${params.length}`);
  }
  if (args.analystVerdict) {
    params.push(args.analystVerdict);
    conditions.push(`analyst_verdict = $${params.length}`);
  }
  if (args.agentName) {
    params.push(`%${args.agentName}%`);
    conditions.push(`agent_name ILIKE $${params.length}`);
  }
  if (args.query) {
    params.push(`%${args.query}%`);
    conditions.push(`name ILIKE $${params.length}`);
  }
  params.push(String(limit));
  const { rows } = await query(
    `SELECT id, name, severity, analyst_verdict, mitigation_status, agent_name, site, storyline, created_at
     FROM threats
     WHERE ${conditions.join(' AND ')}
     ORDER BY created_at DESC NULLS LAST
     LIMIT $${params.length}`,
    params,
  );
  return rows;
}

async function execGetThreat(args) {
  const { rows } = await query(`SELECT id, name, severity, analyst_verdict, mitigation_status, incident_status, agent_name, agent_id, site, storyline, file_path, sha256, originator_process, process_user, created_at FROM threats WHERE id = $1`, [args.threatId]);
  if (rows.length === 0) return { error: `Menace ${args.threatId} introuvable.` };
  const threat = rows[0];
  const { rows: notes } = await query(`SELECT text, creator, created_at FROM threat_notes WHERE threat_id = $1 ORDER BY created_at DESC LIMIT 5`, [args.threatId]);
  const { rows: related } = await query(`SELECT id, name, severity, analyst_verdict FROM threats WHERE storyline IS NOT NULL AND storyline = (SELECT storyline FROM threats WHERE id = $1) AND id <> $1 LIMIT 5`, [args.threatId]);
  const { rows: acts } = await query(`SELECT description, details, "user", created_at FROM activities WHERE threat_id = $1 ORDER BY created_at DESC LIMIT 5`, [args.threatId]);
  return { ...threat, notes, relatedThreats: related, activities: acts };
}

async function execSearchAlerts(args) {
  const limit = Math.min(Math.max(Number(args.limit) || 10, 1), 50);
  const days = Math.min(Math.max(Number(args.days) || 30, 1), 365);
  const conditions = [`created_at >= now() - ($1 || ' days')::interval`];
  const params = [String(days)];
  if (args.severity) {
    params.push(args.severity);
    conditions.push(`severity = $${params.length}`);
  }
  if (args.analystVerdict) {
    params.push(args.analystVerdict);
    conditions.push(`analyst_verdict = $${params.length}`);
  }
  params.push(String(limit));
  const { rows } = await query(
    `SELECT id, name, event_type, severity, analyst_verdict, incident_status, agent_name, storyline, process_name, created_at
     FROM alerts WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC NULLS LAST LIMIT $${params.length}`,
    params,
  );
  return rows;
}

async function execSearchActivities(args) {
  const limit = Math.min(Math.max(Number(args.limit) || 15, 1), 50);
  const days = Math.min(Math.max(Number(args.days) || 7, 1), 365);
  const conditions = [`created_at >= now() - ($1 || ' days')::interval`];
  const params = [String(days)];
  if (args.threatId) {
    params.push(args.threatId);
    conditions.push(`threat_id = $${params.length}`);
  }
  if (args.agentName) {
    params.push(`%${args.agentName}%`);
    conditions.push(`agent_name ILIKE $${params.length}`);
  }
  params.push(String(limit));
  const { rows } = await query(
    `SELECT id, description, details, agent_name, "user", threat_id, created_at
     FROM activities WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC NULLS LAST LIMIT $${params.length}`,
    params,
  );
  return rows;
}

async function execSearchNotes(args) {
  const limit = Math.min(Math.max(Number(args.limit) || 15, 1), 50);
  const params = [];
  let where = '1=1';
  if (args.threatId) {
    params.push(args.threatId);
    where = `n.threat_id = $${params.length}`;
  }
  params.push(String(limit));
  const { rows } = await query(
    `SELECT n.id, n.threat_id, n.text, n.creator, n.created_at, t.name AS threat_name
     FROM threat_notes n JOIN threats t ON t.id = n.threat_id
     WHERE ${where} ORDER BY n.created_at DESC NULLS LAST LIMIT $${params.length}`,
    params,
  );
  return rows;
}

async function execGetStats(args) {
  const days = Math.min(Math.max(Number(args.days) || 30, 1), 365);
  const { rows: threatBySeverity } = await query(
    `SELECT severity, count(*)::int AS count FROM threats
     WHERE created_at >= now() - ($1 || ' days')::interval GROUP BY severity ORDER BY count DESC`,
    [String(days)],
  );
  const { rows: threatByVerdict } = await query(
    `SELECT analyst_verdict, count(*)::int AS count FROM threats
     WHERE created_at >= now() - ($1 || ' days')::interval GROUP BY analyst_verdict ORDER BY count DESC`,
    [String(days)],
  );
  const { rows: alertBySeverity } = await query(
    `SELECT severity, count(*)::int AS count FROM alerts
     WHERE created_at >= now() - ($1 || ' days')::interval GROUP BY severity ORDER BY count DESC`,
    [String(days)],
  );
  const { rows: topAgents } = await query(
    `SELECT agent_name, count(*)::int AS threats FROM threats
     WHERE created_at >= now() - ($1 || ' days')::interval AND agent_name <> ''
     GROUP BY agent_name ORDER BY threats DESC LIMIT 5`,
    [String(days)],
  );
  const { rows: totals } = await query(
    `SELECT
       (SELECT count(*)::int FROM threats WHERE created_at >= now() - ($1 || ' days')::interval) AS threats,
       (SELECT count(*)::int FROM alerts WHERE created_at >= now() - ($1 || ' days')::interval) AS alerts`,
    [String(days)],
  );
  return {
    periodDays: days,
    totals: totals[0],
    threatsBySeverity: threatBySeverity,
    threatsByVerdict: threatByVerdict,
    alertsBySeverity: alertBySeverity,
    topInfectedEndpoints: topAgents,
  };
}

async function execGetAgentContext(args) {
  const name = `%${String(args.agentName || '').trim()}%`;
  const { rows: agents } = await query(`SELECT id, name, os, status, site, ip, last_active_at FROM agents WHERE name ILIKE $1 OR id = $2 LIMIT 3`, [name, String(args.agentName || '').trim()]);
  const { rows: threats } = await query(
    `SELECT id, name, severity, analyst_verdict, created_at FROM threats
     WHERE agent_name ILIKE $1 ORDER BY created_at DESC NULLS LAST LIMIT 10`,
    [name],
  );
  const { rows: counts } = await query(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE analyst_verdict = 'true_positive')::int AS confirmed
     FROM threats WHERE agent_name ILIKE $1`,
    [name],
  );
  return { agents, recentThreats: threats, threatCount: counts[0] };
}

const TOOL_EXECUTORS = {
  search_rag: execSearchRag,
  search_threats: execSearchThreats,
  get_threat: execGetThreat,
  search_alerts: execSearchAlerts,
  search_activities: execSearchActivities,
  search_notes: execSearchNotes,
  get_stats: execGetStats,
  get_agent_context: execGetAgentContext,
};

// ── Boucle agentic ───────────────────────────────────────────────────────────
async function callAIWithTools(apiMessages, system, options = {}) {
  const maxRounds = Math.min(options.maxRounds || config.ai.maxToolRounds, config.ai.maxToolRounds);
  const collectedSources = [];
  const toolNamesUsed = [];
  let finalText = '';

  const trimMessages = (messages) => {
    const cleaned = messages.filter((m) => m.role && m.content != null);
    if (cleaned.length > 30) return cleaned.slice(-30);
    return cleaned;
  };

  for (let round = 0; round < maxRounds; round += 1) {
    const useTools = round < maxRounds - 1;
    const result = await callAiWithRetry(
      () =>
        callProviderWithFallback(null, 'chatbot', {
          messages: trimMessages(apiMessages),
          system,
          temperature: config.ai.temperature,
          maxTokens: config.ai.maxTokens,
          tools: useTools ? ALL_TOOLS : undefined,
          source: 'chatbotAnswer',
          userId: options.userId,
        }),
      { maxRetries: 2, baseDelay: 1500 },
    );

    if (!result.toolCalls || result.toolCalls.length === 0) {
      finalText = result.text || '';
      break;
    }

    for (const call of result.toolCalls) {
      const name = call.function.name;
      let args = {};
      try {
        args = JSON.parse(call.function.arguments || '{}');
      } catch {
        args = {};
      }
      toolNamesUsed.push(name);
      if (options.onToolEvent) options.onToolEvent({ name, phase: 'start' });

      let payload;
      const executor = TOOL_EXECUTORS[name];
      try {
        payload = executor ? await executor(args) : { error: `Outil ${name} inconnu.` };
      } catch (error) {
        payload = { error: error.message };
        log.warn('Échec outil chatbot', { tool: name, error: error.message });
      }
      if (options.onToolEvent) options.onToolEvent({ name, phase: 'done' });

      // Sources citées (RAG et entités référencées)
      if (name === 'search_rag' && Array.isArray(payload)) {
        for (const item of payload) collectedSources.push({ kind: item.kind, label: (item.extrait || '').substring(0, 80), score: item.score });
      } else if (name === 'search_threats' && Array.isArray(payload)) {
        for (const t of payload.slice(0, 3)) collectedSources.push({ kind: 'threat', id: t.id, label: `${t.name} (${t.agent_name || '—'})` });
      } else if (name === 'search_alerts' && Array.isArray(payload)) {
        for (const a of payload.slice(0, 3)) collectedSources.push({ kind: 'alert', id: a.id, label: a.name });
      } else if (name === 'search_notes' && Array.isArray(payload)) {
        for (const n of payload.slice(0, 3)) collectedSources.push({ kind: 'note', id: n.id, label: `Note sur ${n.threat_name}` });
      }

      apiMessages.push({
        role: 'assistant',
        content: `Résultat de ${name} :\n${JSON.stringify(payload).substring(0, 6000)}`,
      });
    }
  }

  // Sécurité : si aucun tour n'a produit de texte final, message de repli.
  if (!finalText) finalText = 'Je n’ai pas réussi à produire une réponse. Reformulez votre question ou réessayez.';

  // Déduplication des sources (max 8)
  const seen = new Set();
  const sources = [];
  for (const source of collectedSources) {
    const key = `${source.kind}:${source.id || source.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    sources.push(source);
    if (sources.length >= 8) break;
  }

  return { text: finalText, sources, toolsUsed: toolNamesUsed };
}

// ── Point d'entrée message ───────────────────────────────────────────────────
async function handleMessage(message, history, user, options = {}) {
  const startedAt = Date.now();

  const dbHistory = (history || [])
    .filter((m) => m.role === 'user' || m.role === 'assistant')
    .slice(-30)
    .map((m) => ({ role: m.role, content: m.content }));

  const apiMessages = [...dbHistory, { role: 'user', content: message }];
  const system = `${SYSTEM_PROMPT}\n\n${getDateContextLine()}`;

  const result = await callAIWithTools(apiMessages, system, {
    userId: user && user.username,
    onToolEvent: options.onToolEvent,
    maxRounds: options.voiceMode ? 3 : undefined,
  });

  return {
    reply: result.text,
    sources: result.sources,
    toolsUsed: result.toolsUsed,
    durationMs: Date.now() - startedAt,
  };
}

module.exports = { handleMessage, SYSTEM_PROMPT, ALL_TOOLS, TOOL_EXECUTORS };

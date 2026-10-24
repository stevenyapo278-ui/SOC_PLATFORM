'use strict';

// Télémétrie de consommation IA — table ai_usage_log.
// Budget journalier configurable (AI_DAILY_TOKEN_BUDGET, 0 = illimité).

const { query } = require('../db');
const config = require('../config');
const log = require('../logger');

async function trackAiUsage(usage, provider, usageContext, meta = {}) {
  const promptTokens = Number(usage.promptTokens) || 0;
  const completionTokens = Number(usage.completionTokens) || 0;
  const totalTokens = Number(usage.totalTokens) || promptTokens + completionTokens;
  if (totalTokens <= 0 && !meta.durationMs) return;

  try {
    await query(
      `INSERT INTO ai_usage_log (
         provider, model, usage_context, source, user_id,
         prompt_tokens, completion_tokens, total_tokens, duration_ms, estimated
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        provider || '',
        meta.model || '',
        usageContext || '',
        meta.source || '',
        meta.userId || null,
        promptTokens,
        completionTokens,
        totalTokens,
        Number(meta.durationMs) || 0,
        meta.estimated === true,
      ],
    );
    await checkTokenBudget();
  } catch (error) {
    log.warn('Enregistrement usage IA impossible', { error: error.message });
  }
}

// Alerte une fois par jour si le budget est dépassé (log warn — pas d'email ici).
let budgetAlertAt = 0;

async function checkTokenBudget() {
  const budget = config.ai.dailyTokenBudget;
  if (!budget || budget <= 0) return;
  if (Date.now() - budgetAlertAt < 6 * 60 * 60 * 1000) return;

  const { rows } = await query(
    `SELECT COALESCE(sum(total_tokens), 0)::bigint AS used
     FROM ai_usage_log
     WHERE created_at >= date_trunc('day', now())`,
  );
  const used = Number(rows[0].used);
  const ratio = used / budget;
  if (ratio >= (config.ai.tokenAlertThreshold || 0.8)) {
    budgetAlertAt = Date.now();
    log.warn('Budget journalier IA approché', { used, budget, ratio: Math.round(ratio * 100) });
  }
}

async function getAiUsageStats(days = 7) {
  const { rows } = await query(
    `SELECT
       provider,
       usage_context,
       source,
       model,
       count(*)::int AS calls,
       sum(total_tokens)::bigint AS total_tokens,
       avg(duration_ms)::int AS avg_duration_ms
     FROM ai_usage_log
     WHERE created_at >= now() - ($1 || ' days')::interval
     GROUP BY provider, usage_context, source, model
     ORDER BY total_tokens DESC`,
    [String(days)],
  );
  return rows.map((row) => ({ ...row, total_tokens: Number(row.total_tokens) }));
}

module.exports = { trackAiUsage, getAiUsageStats, checkTokenBudget };

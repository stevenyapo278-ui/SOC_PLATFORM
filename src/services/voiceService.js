'use strict';

// Voix batch — STT (transcription) et TTS (synthèse) via le provider Gemini actif.
// Porté de Projet_IA_Hub (voiceService.js), SQL brut ici.

const { query } = require('../db');
const config = require('../config');
const log = require('../logger');
const { getBreaker } = require('../ai/circuitBreaker');
const { trackAiUsage } = require('../ai/usageTracker');

const voiceBreaker = getBreaker('ai-voice', { maxFailures: 5, resetTimeoutMs: 30000, halfOpenMaxRequests: 1 });

async function getGeminiConfig() {
  const { rows } = await query(
    `SELECT p.base_url, k.api_key
     FROM ai_providers p JOIN ai_keys k ON k.provider_id = p.id AND k.is_active
     WHERE p.name = 'gemini' AND p.is_active
     ORDER BY k.is_default DESC LIMIT 1`,
  );
  if (rows.length === 0) {
    throw new Error('Aucun provider Gemini actif — ajoutez une clé Gemini dans Paramètres > IA pour utiliser la voix.');
  }
  return {
    apiKey: rows[0].api_key,
    baseUrl: rows[0].base_url || 'https://generativelanguage.googleapis.com/v1beta',
  };
}

// ── STT : audio → texte ──────────────────────────────────────────────────────
async function transcribeAudio(audioBuffer, mimeType = 'audio/webm') {
  return voiceBreaker.call(async () => {
    const { apiKey, baseUrl } = await getGeminiConfig();
    const model = config.ai.voice.sttModel;
    const audioBase64 = Buffer.isBuffer(audioBuffer) ? audioBuffer.toString('base64') : Buffer.from(audioBuffer).toString('base64');

    const payload = {
      contents: [
        {
          parts: [
            {
              text: "Transcris cet audio en texte exactement tel qu'il est dit. Si c'est en français, garde le français. Retourne UNIQUEMENT le texte transcrit, sans guillemets, sans commentaire.",
            },
            { inlineData: { mimeType, data: audioBase64 } },
          ],
        },
      ],
      generationConfig: { temperature: 0.1, maxOutputTokens: 4096, thinkingConfig: { thinkingBudget: 0 } },
    };

    const startedAt = Date.now();
    const res = await fetch(`${baseUrl}/models/${model}:generateContent`, {
      method: 'POST',
      signal: AbortSignal.timeout(30000),
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const bodyText = await res.text();
      log.error('STT impossible', { status: res.status, detail: bodyText.substring(0, 300) });
      throw new Error(`Transcription impossible (HTTP ${res.status}).`);
    }
    const data = await res.json();
    const text = (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts && data.candidates[0].content.parts[0] && data.candidates[0].content.parts[0].text || '').trim();

    const ut = data.usageMetadata;
    if (ut && ut.totalTokenCount) {
      trackAiUsage(
        { promptTokens: ut.promptTokenCount || 0, completionTokens: ut.candidatesTokenCount || 0, totalTokens: ut.totalTokenCount },
        'gemini',
        'voice',
        { model, durationMs: Date.now() - startedAt, source: 'voiceTranscription' },
      ).catch(() => {});
    }
    return { text };
  });
}

// ── TTS : texte → audio PCM ──────────────────────────────────────────────────
async function synthesizeAudio(text, voiceName) {
  return voiceBreaker.call(async () => {
    const { apiKey, baseUrl } = await getGeminiConfig();
    const model = config.ai.voice.ttsModel;
    const voice = voiceName || config.ai.voice.ttsVoice;

    const payload = {
      contents: [{ parts: [{ text }] }],
      generationConfig: {
        responseModalities: ['AUDIO'],
        speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: voice } } },
      },
    };

    const startedAt = Date.now();
    const res = await fetch(`${baseUrl}/models/${model}:generateContent`, {
      method: 'POST',
      signal: AbortSignal.timeout(60000),
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const bodyText = await res.text();
      log.error('TTS impossible', { status: res.status, detail: bodyText.substring(0, 300) });
      throw new Error(`Synthèse vocale impossible (HTTP ${res.status}).`);
    }
    const data = await res.json();
    const audioPart = data.candidates && data.candidates[0] && data.candidates[0].content && (data.candidates[0].content.parts || []).find((p) => p.inlineData);
    if (!audioPart || !audioPart.inlineData || !audioPart.inlineData.data) {
      throw new Error('Aucune donnée audio retournée.');
    }
    const ut = data.usageMetadata;
    if (ut && ut.totalTokenCount) {
      trackAiUsage(
        { promptTokens: ut.promptTokenCount || 0, completionTokens: ut.candidatesTokenCount || 0, totalTokens: ut.totalTokenCount },
        'gemini',
        'voice',
        { model, durationMs: Date.now() - startedAt, source: 'voiceSynthesis' },
      ).catch(() => {});
    }
    return { audio: audioPart.inlineData.data, mimeType: audioPart.inlineData.mimeType || 'audio/pcm', sampleRate: 24000, encoding: 'pcm_s16le' };
  });
}

const AVAILABLE_VOICES = [
  { name: 'Kore', label: 'Kore (Ferme)', style: 'Ferme et posée' },
  { name: 'Puck', label: 'Puck (Enthousiaste)', style: 'Enthousiaste et dynamique' },
  { name: 'Charon', label: 'Charon (Informatif)', style: 'Informatif et neutre' },
  { name: 'Fenrir', label: 'Fenrir (Excité)', style: 'Excité et énergique' },
  { name: 'Leda', label: 'Leda (Jeune)', style: 'Jeune et légère' },
  { name: 'Orus', label: 'Orus (Ferme)', style: 'Ferme et direct' },
  { name: 'Aoede', label: 'Aoede (Décontracté)', style: 'Décontracté et naturel' },
  { name: 'Callirrhoe', label: 'Callirrhoe (Facile)', style: 'Facile et amical' },
  { name: 'Autonoe', label: 'Autonoe (Clair)', style: 'Clair et vif' },
  { name: 'Enceladus', label: 'Enceladus (Respirant)', style: 'Respirant et doux' },
  { name: 'Iapetus', label: 'Iapetus (Clair)', style: 'Clair et précis' },
  { name: 'Umbriel', label: 'Umbriel (Facile)', style: 'Facile et naturel' },
  { name: 'Algieba', label: 'Algieba (Doux)', style: 'Doux et fluide' },
  { name: 'Despina', label: 'Despina (Doux)', style: 'Doux et agréable' },
  { name: 'Erinome', label: 'Erinome (Clair)', style: 'Clair et net' },
  { name: 'Sulafat', label: 'Sulafat (Chaleureux)', style: 'Chaleureux et accueillant' },
];

module.exports = { transcribeAudio, synthesizeAudio, AVAILABLE_VOICES, getGeminiConfig };

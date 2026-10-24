'use strict';

// Voix batch : STT (upload audio → texte) et TTS (texte → audio base64).
// Le mode live WebSocket vit dans src/voice/live.js (port dédié).

const { Router } = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const config = require('../config');
const { requireApiAuth } = require('../middleware/auth');
const { createSessionToken } = require('../auth/session');
const { transcribeAudio, synthesizeAudio, AVAILABLE_VOICES } = require('../services/voiceService');
const log = require('../logger');

const router = Router();
router.use(requireApiAuth);

if (config.ai.voice.enabled) {
  router.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 30,
      keyGenerator: (req) => `voice:${req.user.username}`,
      message: { error: 'Trop de requêtes vocales. Réessayez dans quelques minutes.' },
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

router.post('/stt', upload.single('audio'), async (req, res) => {
  if (!config.ai.voice.enabled) return res.status(503).json({ error: 'Voix désactivée sur cette instance.' });
  if (!req.file) return res.status(400).json({ error: 'Fichier audio manquant.' });
  try {
    const mimeType = req.file.mimetype || 'audio/webm';
    const result = await transcribeAudio(req.file.buffer, mimeType);
    res.json({ text: result.text });
  } catch (error) {
    log.warn('STT échoué', { user: req.user.username, error: error.message });
    res.status(502).json({ error: error.message });
  }
});

router.post('/tts', async (req, res) => {
  if (!config.ai.voice.enabled) return res.status(503).json({ error: 'Voix désactivée sur cette instance.' });
  try {
    const text = String((req.body && req.body.text) || '').trim();
    if (!text) return res.status(400).json({ error: 'Texte requis.' });
    if (text.length > 4000) return res.status(400).json({ error: 'Texte trop long (4000 caractères max).' });
    const voice = req.body && req.body.voice;
    const result = await synthesizeAudio(text, voice);
    res.json(result);
  } catch (error) {
    log.warn('TTS échoué', { user: req.user.username, error: error.message });
    res.status(502).json({ error: error.message });
  }
});

router.get('/voices', (req, res) => {
  res.json({ voices: AVAILABLE_VOICES });
});

// Jeton court pour la WebSocket live (le cookie de session est httpOnly).
router.get('/live-token', (req, res) => {
  if (!config.ai.voice.enabled) return res.status(503).json({ error: 'Voix désactivée sur cette instance.' });
  res.json({ token: createSessionToken(req.user), port: config.ai.voice.livePort, model: config.ai.voice.liveModel });
});

module.exports = router;

'use strict';

// Voix LIVE — WebSocket dédié (port VOICE_LIVE_PORT, défaut 3213).
// Session Gemini Live : PCM 16 kHz mono côté client (AudioWorklet), outils SOC
// en lecture seule, transcripts relayés (partial/final). Porté de IA_Hub,
// simplifié : pas de snapshot ERP, pas d'actions d'écriture.

const http = require('http');
const { WebSocketServer } = require('ws');
const { GoogleGenAI } = require('@google/genai');
const config = require('../config');
const log = require('../logger');
const { verifySessionToken } = require('../auth/session');
const { getGeminiConfig } = require('../services/voiceService');
const { handleMessage } = require('../services/chatbotService');
const { trackAiUsage } = require('../ai/usageTracker');

const LIVE_MODEL = config.ai.voice.liveModel || 'gemini-2.5-flash-native-audio-preview-09-2025';
const LIVE_VOICE = config.ai.voice.liveVoice || 'Aoede';
const CONNECT_TIMEOUT_MS = 10000;
const PARTIAL_THROTTLE_MS = 150;

// Outils vocaux : sous-ensemble lecture seule du chatbot.
const VOICE_TOOLS = [
  {
    functionDeclarations: [
      { name: 'search_threats', description: 'Liste les menaces détectées (filtres : severity, analystVerdict, agentName, days, limit).', parameters: { type: 'OBJECT', properties: { query: { type: 'STRING' }, severity: { type: 'STRING' }, analystVerdict: { type: 'STRING' }, agentName: { type: 'STRING' }, days: { type: 'INTEGER' }, limit: { type: 'INTEGER' } } } },
      { name: 'get_threat', description: 'Détail complet d’une menace par identifiant.', parameters: { type: 'OBJECT', properties: { threatId: { type: 'STRING' } }, required: ['threatId'] } },
      { name: 'search_alerts', description: 'Liste les alertes STAR (filtres : severity, analystVerdict, days, limit).', parameters: { type: 'OBJECT', properties: { severity: { type: 'STRING' }, analystVerdict: { type: 'STRING' }, days: { type: 'INTEGER' }, limit: { type: 'INTEGER' } } } },
      { name: 'search_activities', description: 'Journal des activités console (filtres : threatId, agentName, days, limit).', parameters: { type: 'OBJECT', properties: { threatId: { type: 'STRING' }, agentName: { type: 'STRING' }, days: { type: 'INTEGER' }, limit: { type: 'INTEGER' } } } },
      { name: 'search_notes', description: 'Notes d’équipe sur les menaces (filtres : threatId, limit).', parameters: { type: 'OBJECT', properties: { threatId: { type: 'STRING' }, limit: { type: 'INTEGER' } } } },
      { name: 'get_stats', description: 'Statistiques SOC (menaces/alertes par gravité et verdict, endpoints touchés).', parameters: { type: 'OBJECT', properties: { days: { type: 'INTEGER' } } } },
      { name: 'get_agent_context', description: 'Contexte d’un endpoint : menaces récentes, compteurs.', parameters: { type: 'OBJECT', properties: { agentName: { type: 'STRING' } }, required: ['agentName'] } },
      { name: 'search_rag', description: 'Recherche sémantique dans les notes et synthèses passées.', parameters: { type: 'OBJECT', properties: { query: { type: 'STRING' }, topK: { type: 'INTEGER' } }, required: ['query'] } },
      { name: 'ask_assistant', description: 'Question générale nécessitant raisonnement ou analyse libre — délègue au chatbot texte.', parameters: { type: 'OBJECT', properties: { question: { type: 'STRING' } }, required: ['question'] } },
    ],
  },
];

// Exécution d'un outil vocal → réponse Struct Gemini (objet PLAT requis par le proto).
async function executeVoiceTool(name, args, user) {
  if (name === 'ask_assistant') {
    const result = await handleMessage(String(args.question || ''), [], user, { voiceMode: true });
    return { reply: result.reply };
  }
  // Réutilise les exécuteurs du chatbot via handleMessage interne : on appelle
  // directement les fonctions exportées du service.
  const chatbot = require('../services/chatbotService');
  const executors = chatbot.TOOL_EXECUTORS || {};
  const executor = executors[name];
  if (!executor) return { error: `Outil ${name} inconnu.` };
  return executor(args || {});
}

function toGeminiResponse(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return { response: value };
  if (Array.isArray(value)) return { response: { items: value } };
  return { response: { text: String(value) } };
}

// Petit nettoyage du texte parlé (pas de markdown à l'oral).
function formatSpoken(text) {
  return text
    .replace(/[*_#`]/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

const SYSTEM_INSTRUCTION = [
  'Tu es l’assistant vocal de la plateforme SOC Sentinel (supervision SentinelOne). Tu réponds TOUJOURS en français.',
  'Parle clairement, concisement et naturellement à l’oral.',
  '══ FORME ══',
  '- Réponds en 1 à 3 phrases courtes. Pas de markdown, pas de listes, pas d’astérisques.',
  '- N’invente JAMAIS de donnée : si un outil ne trouve rien, dis-le en une phrase.',
  '- Tu es en lecture seule : tu ne peux AUCUNE action sur SentinelOne.',
  '- Évite « je vérifie », « un instant » : appelle l’outil puis réponds directement.',
  '══ OUTILS ══',
  '- Menaces, alertes, activités, notes, statistiques, endpoint → appelle l’outil correspondant.',
  '- Question générale d’analyse → ask_assistant.',
  '- Pour une date relative, base-toi sur la date injectée ci-dessous.',
].join('\n');

function getVoiceSystemInstruction() {
  const now = new Date();
  const days = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
  const months = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
  return `${SYSTEM_INSTRUCTION}\n\n[Date du jour : ${days[now.getDay()]} ${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()}]`;
}

let server = null;

function setupVoiceLive() {
  if (!config.ai.voice.enabled) {
    log.info('Voix live désactivée (VOICE_ENABLED=false).');
    return null;
  }

  const tlsCertPath = process.env.TLS_CERT_PATH;
  const tlsKeyPath = process.env.TLS_KEY_PATH;
  let httpServer;
  if (tlsCertPath && tlsKeyPath && require('fs').existsSync(tlsCertPath) && require('fs').existsSync(tlsKeyPath)) {
    try {
      httpServer = http.createServer(); // placeholder remplacé ci-dessous
    } catch {
      httpServer = http.createServer();
    }
    // HTTPS si les fichiers existent (nécessaire getUserMedia hors localhost).
    try {
      const https = require('https');
      httpServer = https.createServer({
        cert: require('fs').readFileSync(tlsCertPath),
        key: require('fs').readFileSync(tlsKeyPath),
      });
      log.info('Voix live : HTTPS activé');
    } catch (error) {
      log.warn('Voix live : fallback HTTP', { error: error.message });
      httpServer = http.createServer();
    }
  } else {
    httpServer = http.createServer();
  }

  httpServer.on('connection', (socket) => {
    try {
      socket.setNoDelay(true);
    } catch {
      /* best effort */
    }
  });

  const wss = new WebSocketServer({
    server: httpServer,
    maxPayload: 1024 * 1024,
    perMessageDeflate: { threshold: 256, zlibDeflateOptions: { level: 3 } },
  });

  const keepAlive = setInterval(() => {
    wss.clients.forEach((c) => {
      if (c.readyState === 1) {
        try {
          c.ping();
        } catch {
          /* ignore */
        }
      } else if (c.readyState !== 0) {
        try {
          c.terminate();
        } catch {
          /* ignore */
        }
      }
    });
  }, 30000);
  wss.on('close', () => clearInterval(keepAlive));

  wss.on('connection', async (ws, req) => {
    log.info('Voix live : client connecté');
    let session = null;
    let user = null;
    const sessionLog = [];

    // Auth : token JWT en query (?token=) — même secret que les sessions httpOnly.
    try {
      const url = new URL(req.url, 'http://localhost');
      const token = url.searchParams.get('token') || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const payload = verifySessionToken(token);
      if (payload) {
        user = {
          username: payload.sub,
          displayName: payload.name || payload.sub,
          email: payload.email || '',
          role: payload.role === 'admin' ? 'admin' : 'analyst',
        };
        log.info('Voix live : auth OK', { user: user.username });
      } else {
        log.warn('Voix live : session non authentifiée');
      }
    } catch (error) {
      log.warn('Voix live : auth échouée', { error: error.message });
    }

    let inputBuf = '';
    let outputBuf = '';
    let lastRelay = { user: 0, assistant: 0 };

    // Résumé de session via le chatbot texte.
    const handleSummary = async () => {
      const send = (payload) => {
        if (ws.readyState === 1) ws.send(JSON.stringify(payload));
      };
      if (sessionLog.length === 0) {
        send({ type: 'session_summary', text: '' });
        return;
      }
      const transcript = sessionLog.map((m) => `${m.role === 'user' ? 'Utilisateur' : 'Assistant'} : ${m.text}`).join('\n');
      try {
        const result = await handleMessage(
          "Résume en 4 à 6 phrases cet échange vocal avec l’assistant SOC : contexte, questions, réponses, suites possibles. Français simple, pas de markdown. Réponds UNIQUEMENT avec le résumé.",
          [{ role: 'user', content: transcript }],
          user,
          { voiceMode: false },
        );
        send({ type: 'session_summary', text: (result && result.reply) || '' });
      } catch (error) {
        log.warn('Voix live : résumé échoué', { error: error.message });
        send({ type: 'session_summary', text: '' });
      }
    };

    // Messages client : PCM brut (0x…) ou JSON de contrôle.
    ws.on('message', async (data) => {
      try {
        if (Buffer.isBuffer(data) && data.length > 2 && session) {
          if (data[0] === 0x7b) {
            let parsed = null;
            try {
              parsed = JSON.parse(data.toString());
            } catch {
              /* PCM brut dont le 1er octet est { */
            }
            if (parsed) {
              if (parsed.type === 'get_summary') handleSummary().catch(() => {});
              return;
            }
          }
          await session.sendRealtimeInput({
            audio: { data: data.toString('base64'), mimeType: 'audio/pcm;rate=16000' },
          });
        }
      } catch (error) {
        log.error('Voix live : erreur envoi audio', { error: error.message });
      }
    });

    const closeSession = () => {
      try {
        if (session && session.close) session.close();
      } catch {
        /* ignore */
      }
    };
    ws.on('close', () => {
      log.info('Voix live : client déconnecté');
      closeSession();
    });
    ws.on('error', (error) => {
      log.error('Voix live : erreur WS', { error: error.message });
      closeSession();
    });

    try {
      const geminiCfg = await getGeminiConfig();
      const genai = new GoogleGenAI({ apiKey: geminiCfg.apiKey });

      const connectPromise = genai.live.connect({
        model: LIVE_MODEL,
        config: {
          responseModalities: ['AUDIO'],
          systemInstruction: getVoiceSystemInstruction(),
          speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: LIVE_VOICE } } },
          realtimeInputConfig: {
            automaticActivityDetection: {
              disabled: false,
              startOfSpeechSensitivity: 'START_SENSITIVITY_HIGH',
              endOfSpeechSensitivity: 'END_SENSITIVITY_HIGH',
              prefixPaddingMs: 200,
              silenceDurationMs: 500,
            },
          },
          inputAudioTranscription: {},
          outputAudioTranscription: {},
          tools: VOICE_TOOLS,
        },
        callbacks: {
          onopen: () => log.debug('Voix live : session Gemini ouverte'),
          onmessage: async (msg) => {
            if (ws.readyState !== 1) return;
            try {
              if (msg.setupComplete) {
                log.info('Voix live : setupComplete');
                ws.send(JSON.stringify({ type: 'ready' }));
                return;
              }

              const sc = msg.serverContent;
              if (sc) {
                if (sc.inputTranscription && sc.inputTranscription.text) {
                  inputBuf += sc.inputTranscription.text;
                  if (inputBuf.length > 10000) inputBuf = inputBuf.slice(-10000);
                  const now = Date.now();
                  if (now - lastRelay.user >= PARTIAL_THROTTLE_MS) {
                    lastRelay.user = now;
                    ws.send(JSON.stringify({ type: 'transcript', role: 'user', text: inputBuf, partial: true }));
                  }
                }
                if (sc.outputTranscription && sc.outputTranscription.text) {
                  outputBuf += sc.outputTranscription.text;
                  if (outputBuf.length > 10000) outputBuf = outputBuf.slice(-10000);
                  const now = Date.now();
                  if (now - lastRelay.assistant >= PARTIAL_THROTTLE_MS) {
                    lastRelay.assistant = now;
                    ws.send(JSON.stringify({ type: 'transcript', role: 'assistant', text: formatSpoken(outputBuf), partial: true }));
                  }
                }
                if (sc.turnComplete || sc.interrupted) {
                  if (inputBuf || outputBuf) {
                    const tin = Math.ceil((inputBuf || '').length / 4);
                    const tout = Math.ceil((outputBuf || '').length / 4);
                    if (tin + tout > 0) {
                      trackAiUsage({ promptTokens: tin, completionTokens: tout, totalTokens: tin + tout }, 'gemini', 'voice', {
                        model: LIVE_MODEL,
                        estimated: true,
                        userId: user && user.username,
                        source: 'voiceLive',
                      }).catch(() => {});
                    }
                  }
                  if (inputBuf) {
                    ws.send(JSON.stringify({ type: 'transcript', role: 'user', text: inputBuf, final: true }));
                    sessionLog.push({ role: 'user', text: inputBuf });
                    if (sessionLog.length > 60) sessionLog.shift();
                    inputBuf = '';
                  }
                  if (outputBuf) {
                    const text = formatSpoken(outputBuf);
                    ws.send(JSON.stringify({ type: 'transcript', role: 'assistant', text, final: true }));
                    sessionLog.push({ role: 'assistant', text });
                    if (sessionLog.length > 60) sessionLog.shift();
                    outputBuf = '';
                  }
                }
                if (sc.modelTurn && sc.modelTurn.parts) {
                  // serverContent incrémental : relayer TOUTES les parts audio du message.
                  const pcmParts = sc.modelTurn.parts.filter((p) => p.inlineData && p.inlineData.data);
                  if (pcmParts.length > 0) {
                    const combined = Buffer.concat(pcmParts.map((p) => Buffer.from(p.inlineData.data, 'base64')));
                    ws.send(combined);
                  }
                }
                if (sc.interrupted) ws.send(JSON.stringify({ type: 'interrupted' }));
              }

              if (msg.toolCall && msg.toolCall.functionCalls) {
                const fcList = [...msg.toolCall.functionCalls];
                const results = await Promise.allSettled(
                  fcList.map(async (fc) => {
                    const name = String(fc.name || '');
                    const args = JSON.parse(JSON.stringify(fc.args || {}));
                    const id = String(fc.id || '');
                    if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'tool_starting', name }));
                    try {
                      const result = await executeVoiceTool(name, args, user);
                      if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'tool_finished', name }));
                      return { id, name, response: result };
                    } catch (error) {
                      log.error('Voix live : échec outil', { tool: name, error: error.message });
                      if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'tool_finished', name }));
                      return { id, name, response: { error: error.message, success: false } };
                    }
                  }),
                );
                const functionResponses = results.map((r) => toGeminiResponse(r.value || r.reason));
                try {
                  await session.sendToolResponse({ functionResponses });
                } catch (error) {
                  log.error('Voix live : sendToolResponse échoué', { error: error.message });
                }
              }
            } catch (error) {
              log.error('Voix live : erreur message', { error: error.message });
            }
          },
          onerror: (error) => {
            const message = (error && error.message) || 'Erreur Gemini';
            log.error('Voix live : erreur Gemini', { error: message });
            if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'error', message }));
          },
          onclose: (e) => {
            log.info('Voix live : session Gemini fermée', { code: e && e.code, reason: e && e.reason });
            if (ws.readyState === 1) {
              ws.send(JSON.stringify({ type: 'session_closed' }));
              ws.close();
            }
          },
        },
      });

      let connectTimedOut = false;
      let timeoutHandle;
      connectPromise
        .then((s) => {
          if (connectTimedOut) {
            try {
              if (s && s.close) s.close();
            } catch {
              /* ignore */
            }
          }
        })
        .catch(() => {});
      try {
        session = await Promise.race([
          connectPromise,
          new Promise((_, reject) => {
            timeoutHandle = setTimeout(() => {
              connectTimedOut = true;
              reject(new Error(`Connexion Gemini live timeout (${CONNECT_TIMEOUT_MS} ms)`));
            }, CONNECT_TIMEOUT_MS);
          }),
        ]);
      } finally {
        clearTimeout(timeoutHandle);
      }
    } catch (error) {
      log.error('Voix live : setup échoué', { error: error.message });
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'error', message: error.message }));
        ws.close();
      }
    }
  });

  server = httpServer;
  server.listen(config.ai.voice.livePort, () => {
    log.info('Voix live WebSocket démarrée', { port: config.ai.voice.livePort, model: LIVE_MODEL });
  });
  return server;
}

function stopVoiceLive() {
  if (server) {
    try {
      server.close();
    } catch {
      /* ignore */
    }
    server = null;
  }
}

module.exports = { setupVoiceLive, stopVoiceLive };

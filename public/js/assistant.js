/* Assistant SOC — widget flottant : chat texte (SSE), dictée, push-to-talk, voix live. */
(function () {
  'use strict';

  if (!window.SOC) return;
  const { api, escapeHtml } = window.SOC;

  const ICON = 'ti ti-sparkles';
  let panel = null;
  let listEl = null;
  let inputEl = null;
  let statusEl = null;
  let conversationId = null;
  let busy = false;
  let history = []; // [{role, content}] pour la voix live
  let ttsAudio = null;
  let liveSocket = null;
  let liveCtx = null;
  let recording = false;
  let mediaRecorder = null;
  let mediaStream = null;
  let sttMode = 'none'; // 'dictation' | 'push'
  let speechRec = null;

  /* ─────────────────────────── DOM ─────────────────────────── */

  function ensurePanel() {
    if (panel) return panel;
    panel = document.createElement('div');
    panel.id = 'soc-assistant';
    panel.setAttribute('aria-label', 'Assistant SOC');
    panel.innerHTML = `
      <button class="soc-assistant-fab" id="soc-assistant-toggle" type="button" title="Assistant SOC" aria-label="Ouvrir l'assistant">
        <i class="ti ti-sparkles"></i>
      </button>
      <div class="soc-assistant-panel" id="soc-assistant-panel" hidden>
        <div class="soc-assistant-head">
          <div class="d-flex align-items-center gap-2">
            <span class="avatar-title bg-primary text-white rounded fs-16" style="width:28px;height:28px"><i class="ti ti-sparkles"></i></span>
            <span class="fw-semibold fs-14">Assistant SOC</span>
            <span class="badge bg-primary-subtle text-primary" id="soc-assistant-badge">Texte</span>
          </div>
          <div class="d-flex align-items-center gap-1">
            <button class="btn btn-sm btn-outline-secondary btn-icon" id="soc-assistant-new" type="button" title="Nouvelle conversation"><i class="ti ti-plus"></i></button>
            <button class="btn btn-sm btn-outline-secondary btn-icon" id="soc-assistant-close" type="button" title="Fermer"><i class="ti ti-x"></i></button>
          </div>
        </div>
        <div class="soc-assistant-list" id="soc-assistant-list"></div>
        <div class="soc-assistant-status text-muted fs-12" id="soc-assistant-status" hidden></div>
        <div class="soc-assistant-tools">
          <button class="btn btn-sm btn-outline-secondary btn-icon" id="soc-assistant-dict" type="button" title="Dictée (reconnaissance vocale)"><i class="ti ti-microphone"></i></button>
          <button class="btn btn-sm btn-outline-secondary btn-icon" id="soc-assistant-talk" type="button" title="Parler (envoi vocal)"><i class="ti ti-microphone-2"></i></button>
          <button class="btn btn-sm btn-outline-primary" id="soc-assistant-live" type="button" title="Session vocale en direct"><i class="ti ti-broadcast"></i> Live</button>
          <input class="soc-assistant-input" id="soc-assistant-input" type="text" placeholder="Poser une question au SOC…" autocomplete="off" />
          <button class="btn btn-primary btn-icon" id="soc-assistant-send" type="button" title="Envoyer"><i class="ti ti-send"></i></button>
        </div>
      </div>`;
    document.body.appendChild(panel);

    document.getElementById('soc-assistant-toggle').addEventListener('click', toggle);
    document.getElementById('soc-assistant-close').addEventListener('click', toggle);
    document.getElementById('soc-assistant-new').addEventListener('click', resetConversation);
    document.getElementById('soc-assistant-send').addEventListener('click', sendText);
    document.getElementById('soc-assistant-dict').addEventListener('click', toggleDictation);
    document.getElementById('soc-assistant-talk').addEventListener('click', togglePushToTalk);
    document.getElementById('soc-assistant-live').addEventListener('click', toggleLive);
    inputEl = document.getElementById('soc-assistant-input');
    listEl = document.getElementById('soc-assistant-list');
    statusEl = document.getElementById('soc-assistant-status');
    inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendText();
      }
    });
    return panel;
  }

  function toggle() {
    ensurePanel();
    const p = document.getElementById('soc-assistant-panel');
    p.hidden = !p.hidden;
    if (!p.hidden) inputEl.focus();
  }

  function setStatus(text) {
    if (!statusEl) return;
    if (!text) {
      statusEl.hidden = true;
      statusEl.textContent = '';
      return;
    }
    statusEl.hidden = false;
    statusEl.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>${escapeHtml(text)}`;
  }

  function setBadge(text) {
    const badge = document.getElementById('soc-assistant-badge');
    if (badge) badge.textContent = text;
  }

  function resetConversation() {
    conversationId = null;
    history = [];
    if (listEl) listEl.innerHTML = '';
    addMessage('assistant', 'Bonjour ! Je suis l’assistant de la plateforme. Posez-moi une question sur les menaces, alertes ou activités SentinelOne.');
  }

  /* ─────────────────────────── Messages ─────────────────────────── */

  function addMessage(role, text) {
    const wrap = document.createElement('div');
    wrap.className = `soc-msg soc-msg-${role}`;
    wrap.innerHTML = `<div class="soc-msg-bubble">${formatText(text)}</div>`;
    listEl.appendChild(wrap);
    listEl.scrollTop = listEl.scrollHeight;
    return wrap;
  }

  // Markdown léger (FR) : **gras**, `code`, listes, liens [t](u) → texte.
  function formatText(text) {
    let html = escapeHtml(text || '');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/^[-•]\s+(.+)$/gm, '<div class="ms-2">• $1</div>');
    html = html.replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    return html.replace(/\n/g, '<br>');
  }

  function addToolChip(name) {
    const chip = document.createElement('div');
    chip.className = 'soc-msg-tool';
    chip.innerHTML = `<span class="spinner-border spinner-border-sm"></span> L’assistant utilise <code>${escapeHtml(name)}</code>`;
    listEl.appendChild(chip);
    listEl.scrollTop = listEl.scrollHeight;
    return chip;
  }

  function addSources(sources) {
    if (!sources || !sources.length) return;
    const wrap = document.createElement('div');
    wrap.className = 'soc-msg-sources';
    wrap.innerHTML = `<div class="fs-11 text-uppercase fw-semibold text-muted mb-1">Sources</div>` + sources
      .slice(0, 8)
      .map((s) => {
        const label = s.title || s.name || s.id || 'Document';
        const kind = s.entityType || s.type || '';
        const href = kind === 'threat' && s.id ? `/threats?investigate=${encodeURIComponent(s.id)}` : (kind === 'alert' && s.id ? `/alerts?investigate=${encodeURIComponent(s.id)}` : '');
        const body = `<span class="badge bg-secondary-subtle text-secondary me-1">${escapeHtml(kind || 'doc')}</span>${escapeHtml(label)}`;
        return href ? `<div class="soc-msg-source"><a href="${href}">${body}</a></div>` : `<div class="soc-msg-source">${body}</div>`;
      })
      .join('');
    listEl.appendChild(wrap);
    listEl.scrollTop = listEl.scrollHeight;
  }

  /* ─────────────────────────── Chat texte (SSE) ─────────────────────────── */

  async function sendText() {
    const text = (inputEl.value || '').trim();
    if (!text || busy) return;
    inputEl.value = '';
    await postMessage(text);
  }

  async function postMessage(text) {
    busy = true;
    addMessage('user', text);
    history.push({ role: 'user', content: text });
    const assistantWrap = addMessage('assistant', '');
    const bubble = assistantWrap.querySelector('.soc-msg-bubble');
    let reply = '';
    let sourcesWrap = null;

    try {
      setStatus('Réflexion en cours…');
      const response = await fetch('/api/chat?stream=1', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
        body: JSON.stringify({ message: text, conversationId }),
      });

      if (!response.ok) {
        let message = `Erreur ${response.status}.`;
        try {
          const payload = await response.json();
          if (payload && payload.error) message = payload.error;
        } catch {
          /* corps non JSON */
        }
        throw new Error(message);
      }

      // Lecture SSE (fetch POST — EventSource ne supporte pas POST).
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let chip = null;
      let lastToolAt = 0;

      const handleEvent = (event, data) => {
        let payload = {};
        try {
          payload = JSON.parse(data || '{}');
        } catch {
          payload = { text: data };
        }
        if (event === 'tool') {
          if (payload.phase === 'start') {
            chip = addToolChip(payload.name || 'outil');
            setStatus(`Utilisation de ${payload.name || 'un outil'}…`);
            lastToolAt = Date.now();
          } else if (chip) {
            chip.remove();
            chip = null;
          }
        } else if (event === 'final') {
          reply = payload.reply || reply;
          conversationId = payload.conversationId || conversationId;
          if (payload.sources && payload.sources.length) addSources(payload.sources);
          if (chip) {
            chip.remove();
            chip = null;
          }
        } else if (event === 'error') {
          throw new Error(payload.error || 'Erreur du serveur.');
        }
      };

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';
        for (const part of parts) {
          let event = 'message';
          let data = '';
          part.split('\n').forEach((line) => {
            if (line.startsWith('event:')) event = line.slice(6).trim();
            else if (line.startsWith('data:')) data += line.slice(5).trim();
          });
          if (data) handleEvent(event, data);
        }
        // affichage incrémental du brouillon si fourni
        if (!reply && listEl) {
          const draft = buffer.match(/"text":"((?:[^"\\]|\\.)*)"/);
          if (draft) {
            try {
              const partial = JSON.parse(`"${draft[1]}"`);
              bubble.innerHTML = formatText(partial);
              listEl.scrollTop = listEl.scrollHeight;
            } catch {
              /* brouillon incomplet */
            }
          }
        }
      }

      if (chip) chip.remove();
      bubble.innerHTML = formatText(reply || 'Réponse vide.');
      history.push({ role: 'assistant', content: reply });
    } catch (error) {
      bubble.innerHTML = `<span class="text-danger">${escapeHtml(error.message)}</span>`;
      history.pop(); // retire l'utilisateur orphelin
    } finally {
      busy = false;
      setStatus('');
      listEl.scrollTop = listEl.scrollHeight;
    }
  }

  async function loadSourcesFromHistory() {
    if (!conversationId) return;
    try {
      const data = await api(`/api/chat/conversations/${encodeURIComponent(conversationId)}/messages`);
      const messages = (data && data.messages) || [];
      const lastAssistant = [...messages].reverse().find((m) => m.role === 'assistant' && m.sources && m.sources.length);
      if (lastAssistant) addSources(lastAssistant.sources);
    } catch {
      /* best effort */
    }
  }

  /* ─────────────────────────── Voix : dictée (Web Speech) ─────────────────────────── */

  function toggleDictation() {
    if (sttMode === 'dictation') {
      stopDictation();
      return;
    }
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) {
      setStatus('Reconnaissance vocale non prise en charge par ce navigateur.');
      setTimeout(() => setStatus(''), 4000);
      return;
    }
    stopPushToTalk();
    speechRec = new SR();
    speechRec.lang = 'fr-FR';
    speechRec.continuous = false;
    speechRec.interimResults = true;
    let finalText = '';
    speechRec.onresult = (event) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i += 1) {
        const t = event.results[i][0].transcript;
        if (event.results[i].isFinal) finalText += t;
        else interim += t;
      }
      inputEl.value = (finalText + interim).trim();
    };
    speechRec.onerror = () => stopDictation();
    speechRec.onend = () => {
      if (sttMode === 'dictation') stopDictation(true);
    };
    speechRec.start();
    sttMode = 'dictation';
    document.getElementById('soc-assistant-dict').classList.add('active', 'btn-danger');
    document.getElementById('soc-assistant-dict').classList.remove('btn-outline-secondary');
    setBadge('Dictée');
    setStatus('Dictez votre question…');
  }

  function stopDictation(send) {
    if (speechRec) {
      try {
        speechRec.stop();
      } catch {
        /* ignore */
      }
      speechRec = null;
    }
    if (sttMode === 'dictation') sttMode = 'none';
    const btn = document.getElementById('soc-assistant-dict');
    if (btn) {
      btn.classList.remove('active', 'btn-danger');
      btn.classList.add('btn-outline-secondary');
    }
    setBadge('Texte');
    if (send && inputEl && inputEl.value.trim()) sendText();
    else setStatus('');
  }

  /* ─────────────────────────── Voix : push-to-talk (STT/TTS batch) ─────────────────────────── */

  async function togglePushToTalk() {
    if (recording) {
      stopPushToTalk(true);
      return;
    }
    stopDictation();
    try {
      mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch {
      setStatus('Accès au micro refusé.');
      setTimeout(() => setStatus(''), 4000);
      return;
    }
    const btn = document.getElementById('soc-assistant-talk');
    btn.classList.add('active', 'btn-danger');
    btn.classList.remove('btn-outline-secondary');
    setBadge('Écoute');
    recording = true;
    const chunks = [];
    mediaRecorder = new MediaRecorder(mediaStream);
    mediaRecorder.ondataavailable = (e) => {
      if (e.data && e.data.size) chunks.push(e.data);
    };
    mediaRecorder.onstop = async () => {
      mediaStream.getTracks().forEach((t) => t.stop());
      mediaStream = null;
      const blob = new Blob(chunks, { type: mediaRecorder.mimetype || 'audio/webm' });
      mediaRecorder = null;
      if (sttMode === 'push') {
        sttMode = 'none';
        await processVoiceBlob(blob);
      }
    };
    sttMode = 'push';
    mediaRecorder.start();
    setStatus('Parlez puis recliquez pour envoyer…');
  }

  function stopPushToTalk(send) {
    if (!recording) return;
    recording = false;
    const btn = document.getElementById('soc-assistant-talk');
    if (btn) {
      btn.classList.remove('active', 'btn-danger');
      btn.classList.add('btn-outline-secondary');
    }
    if (!send) sttMode = 'none';
    try {
      if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
    } catch {
      /* ignore */
    }
    setStatus('');
  }

  async function processVoiceBlob(blob) {
    busy = true;
    setStatus('Transcription de l’audio…');
    try {
      const form = new FormData();
      form.append('audio', blob, 'voice.webm');
      const stt = await fetch('/api/voice/stt', { method: 'POST', credentials: 'same-origin', body: form });
      const sttPayload = await stt.json();
      if (!stt.ok) throw new Error(sttPayload.error || 'Transcription impossible.');
      const text = (sttPayload.text || '').trim();
      if (!text) throw new Error('Aucune phrase reconnue.');
      await postMessage(text);
      const last = [...listEl.querySelectorAll('.soc-msg-assistant .soc-msg-bubble')].pop();
      if (last) speak(last.textContent);
    } catch (error) {
      setStatus(error.message);
      setTimeout(() => setStatus(''), 5000);
    } finally {
      busy = false;
      if (!statusEl.textContent) setStatus('');
    }
  }

  async function speak(text) {
    if (!text || !config_voice_enabled()) return;
    try {
      const response = await fetch('/api/voice/tts', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text.slice(0, 4000) }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Synthèse impossible.');
      const audio = payload.audioBase64 || payload.audio;
      if (!audio) return;
      stopSpeech();
      ttsAudio = new Audio(`data:audio/wav;base64,${audio}`);
      ttsAudio.play().catch(() => {});
    } catch (error) {
      console.warn('TTS', error.message);
    }
  }

  function stopSpeech() {
    if (ttsAudio) {
      try {
        ttsAudio.pause();
      } catch {
        /* ignore */
      }
      ttsAudio = null;
    }
  }

  function config_voice_enabled() {
    // Détecté côté serveur : 403/503 silencieux accepté.
    return true;
  }

  /* ─────────────────────────── Voix : live (WS dédiée) ─────────────────────────── */

  async function toggleLive() {
    if (liveSocket) {
      closeLive();
      return;
    }
    stopDictation();
    stopPushToTalk();
    stopSpeech();
    let tokenInfo;
    try {
      tokenInfo = await api('/api/voice/live-token');
    } catch (error) {
      setStatus(error.message);
      setTimeout(() => setStatus(''), 5000);
      return;
    }
    setStatus('Connexion à la session vocale…');
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    // Même origine (path sur le serveur principal) : requis par la CSP
    // connect-src 'self' et par le TLS terminé par Traefik.
    const liveUrl = tokenInfo.path
      ? `${proto}://${window.location.host}${tokenInfo.path}?token=${encodeURIComponent(tokenInfo.token)}`
      : `${proto}://${window.location.hostname}:${tokenInfo.port}/?token=${encodeURIComponent(tokenInfo.token)}`;
    liveSocket = new WebSocket(liveUrl);
    liveSocket.binaryType = 'arraybuffer';
    setBadge('Live');

    liveSocket.onopen = async () => {
      try {
        liveCtx = new AudioContext({ sampleRate: 16000 });
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true },
        });
        const source = liveCtx.createMediaStreamSource(stream);
        const processor = liveCtx.createScriptProcessor(4096, 1, 1);
        const workletSupported = typeof liveCtx.audioWorklet !== 'undefined';
        processor.onaudioprocess = (event) => {
          if (!liveSocket || liveSocket.readyState !== 1) return;
          const f32 = event.inputBuffer.getChannelData(0);
          const pcm = new Int16Array(f32.length);
          for (let i = 0; i < f32.length; i += 1) {
            pcm[i] = Math.max(-1, Math.min(1, f32[i])) * 0x7fff;
          }
          liveSocket.send(pcm.buffer);
        };
        source.connect(processor);
        processor.connect(liveCtx.destination);
        liveCtx._src = source;
        liveCtx._proc = processor;
        liveCtx._stream = stream;
        if (!workletSupported) {
          /* ScriptProcessor en fallback — OK partout */
        }
        setStatus('Parlez librement — session en cours.');
      } catch (error) {
        setStatus(`Micro : ${error.message}`);
      }
    };

    liveSocket.onmessage = (event) => {
      if (typeof event.data === 'string') {
        let msg;
        try {
          msg = JSON.parse(event.data);
        } catch {
          return;
        }
        if (msg.type === 'ready') {
          setStatus('Session vocale prête.');
          addMessage('assistant', 'Session vocale en direct démarrée. Parlez, je vous réponds à voix haute.');
        } else if (msg.type === 'transcript') {
          setStatus(msg.partial ? '' : '');
          let bubbleWrap = document.getElementById('soc-live-transcript');
          if (!bubbleWrap) {
            bubbleWrap = document.createElement('div');
            bubbleWrap.id = 'soc-live-transcript';
            bubbleWrap.className = `soc-msg soc-msg-${msg.role}`;
            listEl.appendChild(bubbleWrap);
          } else {
            bubbleWrap.className = `soc-msg soc-msg-${msg.role}`;
          }
          bubbleWrap.innerHTML = `<div class="soc-msg-bubble">${formatSpokenHtml(msg.text)}</div>`;
          listEl.scrollTop = listEl.scrollHeight;
          if (msg.final) {
            history.push({ role: msg.role === 'user' ? 'user' : 'assistant', content: msg.text });
            bubbleWrap.id = '';
            if (msg.role === 'assistant') speak(msg.text);
          }
        } else if (msg.type === 'error') {
          setStatus(`Erreur : ${msg.message}`);
        } else if (msg.type === 'session_closed') {
          setStatus('Session vocale terminée.');
          closeLive();
        } else if (msg.type === 'tool_starting') {
          addToolChip(msg.name);
        } else if (msg.type === 'tool_finished') {
          const chips = listEl.querySelectorAll('.soc-msg-tool');
          if (chips.length) chips[chips.length - 1].remove();
        } else if (msg.type === 'interrupted') {
          stopSpeech();
        }
      } else {
        // PCM 16 kHz mono → lecture.
        playPcm(event.data);
      }
    };

    liveSocket.onclose = () => closeLive();
    liveSocket.onerror = () => {
      setStatus('Connexion vocale impossible.');
      closeLive();
    };
  }

  function formatSpokenHtml(text) {
    return escapeHtml(text || '').replace(/\n/g, '<br>');
  }

  function playPcm(buffer) {
    if (!liveCtx || liveCtx.state === 'closed') return;
    const pcm = new Int16Array(buffer);
    const float32 = new Float32Array(pcm.length);
    for (let i = 0; i < pcm.length; i += 1) float32[i] = pcm[i] / 32768;
    const audioBuffer = liveCtx.createBuffer(1, float32.length, 16000);
    audioBuffer.getChannelData(0).set(float32);
    const source = liveCtx.createBufferSource();
    source.buffer = audioBuffer;
    source.connect(liveCtx.destination);
    source.start();
  }

  function closeLive() {
    if (liveSocket) {
      try {
        liveSocket.close();
      } catch {
        /* ignore */
      }
      liveSocket = null;
    }
    if (liveCtx) {
      try {
        if (liveCtx._stream) liveCtx._stream.getTracks().forEach((t) => t.stop());
        if (liveCtx._proc) liveCtx._proc.disconnect();
        if (liveCtx._src) liveCtx._src.disconnect();
        liveCtx.close();
      } catch {
        /* ignore */
      }
      liveCtx = null;
    }
    setBadge('Texte');
    setStatus('Session vocale fermée.');
    setTimeout(() => setStatus(''), 3000);
  }

  /* ─────────────────────────── Init ─────────────────────────── */

  function init() {
    // Ignorer sur la page de connexion.
    if (document.body && document.body.classList.contains('auth-page')) return;
    if (window.location.pathname.startsWith('/login')) return;
    ensurePanel();
    resetConversation();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  window.SOCAssistant = { toggle, send: postMessage };
})();

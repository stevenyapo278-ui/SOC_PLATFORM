/* Vue Assistant — conversation avec le chatbot SOC (SSE, sources, dictée). */
(function () {
  'use strict';

  if (!window.SOC) return;
  const { api, escapeHtml, showAlert, clearAlert } = window.SOC;

  const els = {};
  let conversationId = null;
  let busy = false;
  let recognition = null;

  const els$ = (id) => document.getElementById(id);

  function currentUserName() {
    const user = window.SOC.state.user;
    return (user && (user.displayName || user.username)) || 'Vous';
  }

  function initials() {
    const name = currentUserName();
    return (
      name
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((part) => part[0].toUpperCase())
        .join('') || '?'
    );
  }

  function timeLabel(value) {
    const date = value ? new Date(value) : new Date();
    if (Number.isNaN(date.getTime())) return '';
    return date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  }

  function setSubtitle(text) {
    const el = document.querySelector('[data-chat-subtitle]');
    if (el) el.textContent = text;
  }

  function scrollToBottom() {
    const scroll = els.scroll;
    if (scroll) scroll.scrollTop = scroll.scrollHeight;
  }

  function setStatus(text) {
    if (!els.status) return;
    if (!text) {
      els.status.hidden = true;
      els.status.textContent = '';
      return;
    }
    els.status.hidden = false;
    els.status.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>${escapeHtml(text)}`;
  }

  /* ─────────────────────────── Messages ─────────────────────────── */

  // Markdown léger (FR) : `code`, **gras**, listes, liens http.
  function formatText(text) {
    let html = escapeHtml(text || '');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/^[-•]\s+(.+)$/gm, '<div class="ms-2">• $1</div>');
    html = html.replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    return html.replace(/\n/g, '<br>');
  }

  function addMessage(role, text, createdAt) {
    const isUser = role === 'user';
    const li = document.createElement('li');
    li.className = `chat-group${isUser ? ' odd' : ''}`;
    li.innerHTML = `
      <span class="avatar-sm">
        <span class="avatar-title rounded-circle ${isUser ? 'bg-secondary' : 'bg-primary'} text-white">
          ${isUser ? escapeHtml(initials()) : '<i class="ti ti-sparkles"></i>'}
        </span>
      </span>
      <div class="chat-body">
        <div>
          <h6 class="d-inline-flex">${isUser ? escapeHtml(currentUserName()) : 'Assistant SOC'}</h6>
          <h6 class="d-inline-flex text-muted">${timeLabel(createdAt)}</h6>
        </div>
        <div class="chat-message">
          <div class="soc-chat-text">${formatText(text)}</div>
        </div>
      </div>`;
    els.messages.appendChild(li);
    scrollToBottom();
    return li;
  }

  function addToolChip(wrapper, name) {
    const body = wrapper.querySelector('.chat-body');
    if (!body) return null;
    const chip = document.createElement('div');
    chip.className = 'soc-msg-tool mt-1';
    chip.innerHTML = `<span class="spinner-border spinner-border-sm"></span> L’assistant consulte <code>${escapeHtml(name)}</code>`;
    body.appendChild(chip);
    scrollToBottom();
    return chip;
  }

  function addSources(wrapper, sources) {
    if (!sources || sources.length === 0) return;
    const body = wrapper.querySelector('.chat-body');
    if (!body) return;
    const block = document.createElement('div');
    block.className = 'soc-chat-sources';
    block.innerHTML =
      '<div class="fs-11 text-uppercase fw-semibold text-muted mb-1">Sources</div>' +
      sources
        .slice(0, 8)
        .map((source) => {
          const kind = source.kind || source.type || 'doc';
          const label = source.label || source.title || source.name || source.id || 'Document';
          let href = '';
          if (kind === 'threat' && source.id) href = `/threats?investigate=${encodeURIComponent(source.id)}`;
          else if (kind === 'alert' && source.id) href = `/alerts?investigate=${encodeURIComponent(source.id)}`;
          else if (kind === 'endpoint' && source.id) href = `/endpoints/${encodeURIComponent(source.id)}`;
          const badge = `<span class="badge bg-secondary-subtle text-secondary me-1">${escapeHtml(kind)}</span>`;
          const content = `${badge}${escapeHtml(label)}`;
          return `<div class="soc-chat-source">${
            href ? `<a href="${href}">${content}</a>` : content
          }</div>`;
        })
        .join('');
    body.appendChild(block);
    scrollToBottom();
  }

  function renderHistory(messages) {
    els.messages.innerHTML = '';
    for (const message of messages) {
      if (message.role !== 'user' && message.role !== 'assistant') continue;
      const li = addMessage(message.role, message.content, message.createdAt);
      if (message.role === 'assistant' && message.sources && message.sources.length) {
        addSources(li, message.sources);
      }
    }
    scrollToBottom();
  }

  function showWelcome(show) {
    if (els.welcome) els.welcome.hidden = !show;
  }

  /* ─────────────────────────── Chargement ─────────────────────────── */

  async function loadRecentConversation() {
    try {
      const conversations = await api('/api/chat/conversations');
      const list = Array.isArray(conversations) ? conversations : [];
      if (list.length === 0) {
        showWelcome(true);
        return;
      }
      conversationId = list[0].id;
      setSubtitle(list[0].title || 'Conversation');
      const history = await api(`/api/chat/history?conversationId=${encodeURIComponent(conversationId)}`);
      showWelcome(false);
      renderHistory(Array.isArray(history) ? history : []);
    } catch (error) {
      // BDD ou provider IA non configurés : on laisse la vue accueil utilisable.
      showAlert(
        '#chat-error',
        error.status === 401
          ? 'Session expirée.'
          : 'Assistant IA indisponible : la base de données ou un provider IA n’est pas configuré sur cette instance.',
      );
      showWelcome(true);
    }
  }

  function startNewConversation() {
    if (busy) return;
    conversationId = null;
    els.messages.innerHTML = '';
    setSubtitle('Prêt · lecture seule');
    clearAlert('#chat-error');
    showWelcome(true);
    setStatus('');
    els.input.value = '';
    els.input.focus();
  }

  /* ─────────────────────────── Envoi (SSE) ─────────────────────────── */

  async function sendMessage(text) {
    if (!text || busy) return;
    busy = true;
    els.send.disabled = true;
    clearAlert('#chat-error');
    showWelcome(false);

    addMessage('user', text);
    const assistant = addMessage('assistant', '');
    const bubble = assistant.querySelector('.soc-chat-text');
    let reply = '';
    let chip = null;

    try {
      setStatus('Réflexion en cours…');
      const response = await fetch('/api/chat?stream=1', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
        body: JSON.stringify({ message: text, conversationId }),
      });

      if (response.status === 401) {
        window.location.replace('/login');
        return;
      }

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

      const handleEvent = (event, data) => {
        let payload = {};
        try {
          payload = JSON.parse(data || '{}');
        } catch {
          payload = {};
        }
        if (event === 'tool') {
          if (payload.phase === 'start') {
            chip = addToolChip(assistant, payload.name || 'outil');
            setStatus(`Utilisation de ${payload.name || 'un outil'}…`);
          } else if (chip) {
            chip.remove();
            chip = null;
          }
        } else if (event === 'final') {
          reply = payload.reply || reply;
          if (payload.conversationId) {
            const created = conversationId === null;
            conversationId = payload.conversationId;
            if (created) setSubtitle(text.length > 40 ? `${text.substring(0, 40).trim()}…` : text);
          }
          if (chip) {
            chip.remove();
            chip = null;
          }
          addSources(assistant, payload.sources || []);
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
      }

      if (chip) chip.remove();
      if (!reply) {
        bubble.innerHTML = '<span class="text-danger">Réponse vide. Reformulez votre question.</span>';
      } else {
        bubble.innerHTML = formatText(reply);
      }
    } catch (error) {
      if (bubble) bubble.innerHTML = `<span class="text-danger">${escapeHtml(error.message)}</span>`;
    } finally {
      busy = false;
      els.send.disabled = false;
      setStatus('');
      scrollToBottom();
      els.input.focus();
    }
  }

  function onSubmit(event) {
    event.preventDefault();
    const text = (els.input.value || '').trim();
    if (!text || busy) return;
    els.input.value = '';
    sendMessage(text);
  }

  /* ─────────────────────────── Dictée ─────────────────────────── */

  function stopDictation() {
    if (recognition) {
      recognition.onend = null;
      recognition.onerror = null;
      try {
        recognition.stop();
      } catch {
        /* déjà arrêtée */
      }
      recognition = null;
    }
    if (els.dict) {
      els.dict.classList.remove('active');
      els.dict.title = 'Dicter le message';
    }
  }

  function toggleDictation() {
    if (recognition) {
      stopDictation();
      return;
    }
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) {
      setStatus('Reconnaissance vocale non prise en charge par ce navigateur.');
      setTimeout(() => setStatus(''), 4000);
      return;
    }

    recognition = new SR();
    recognition.lang = 'fr-FR';
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.onresult = (event) => {
      const text = Array.from(event.results)
        .map((result) => result[0].transcript)
        .join(' ')
        .trim();
      if (!text) return;
      els.input.value = els.input.value ? `${els.input.value} ${text}` : text;
      els.input.focus();
    };
    recognition.onend = () => {
      recognition = null;
      if (els.dict) els.dict.classList.remove('active');
    };
    recognition.onerror = () => {
      recognition = null;
      if (els.dict) els.dict.classList.remove('active');
    };

    try {
      recognition.start();
      els.dict.classList.add('active');
      els.dict.title = 'Arrêter la dictée';
    } catch {
      recognition = null;
    }
  }

  /* ─────────────────────────── Init ─────────────────────────── */

  function init() {
    els.messages = els$('chat-messages');
    els.input = els$('chat-input');
    els.send = els$('chat-send');
    els.form = els$('chat-form');
    els.dict = els$('chat-dict');
    els.status = els$('chat-status');
    els.scroll = els$('chat-scroll');
    els.welcome = els$('chat-welcome');

    if (!els.messages || !els.form) return;

    els.form.addEventListener('submit', onSubmit);
    els$('chat-new').addEventListener('click', startNewConversation);
    els.dict.addEventListener('click', toggleDictation);

    document.querySelectorAll('[data-suggestion]').forEach((button) => {
      button.addEventListener('click', () => {
        if (busy) return;
        const text = button.getAttribute('data-suggestion') || button.textContent.trim();
        els.input.value = '';
        sendMessage(text);
      });
    });

    window.SOC.initShell('chat').then(loadRecentConversation, loadRecentConversation);
  }

  init();
})();

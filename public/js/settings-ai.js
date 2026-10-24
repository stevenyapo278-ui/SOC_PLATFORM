/* Paramètres > Intelligence artificielle — administration des providers (admin only). */
(function () {
  'use strict';
  if (!window.SOC) return;
  const { api, escapeHtml, showAlert, clearAlert } = window.SOC;

  const root = document.getElementById('settings-ai');
  if (!root) return;

  let isAdmin = false;

  const KIND_LABELS = {
    openai_compat: 'OpenAI compatible',
    anthropic: 'Anthropic',
    gemini: 'Gemini',
  };
  const MODEL_TYPES = ['CHAT', 'EMBEDDING', 'RERANK'];

  async function boot() {
    // initShell peut ne pas avoir fini : on attend l'état.
    for (let i = 0; i < 50 && !window.SOC.state.user; i += 1) {
      await new Promise((r) => setTimeout(r, 100));
    }
    const user = window.SOC.state.user;
    isAdmin = user && user.role === 'admin';
    root.hidden = !isAdmin;
    if (!isAdmin) return;
    wire();
    await loadAll();
  }

  function wire() {
    document.getElementById('ai-add-provider').addEventListener('click', () => {
      const form = document.getElementById('ai-form');
      form.hidden = !form.hidden;
      if (!form.hidden) document.getElementById('ai-name').focus();
    });
    document.getElementById('ai-cancel-provider').addEventListener('click', () => {
      document.getElementById('ai-form').hidden = true;
      ['ai-name', 'ai-label', 'ai-baseurl'].forEach((id) => {
        document.getElementById(id).value = '';
      });
    });
    document.getElementById('ai-save-provider').addEventListener('click', createProvider);
    document.getElementById('ai-refresh').addEventListener('click', loadAll);
  }

  async function loadAll() {
    clearAlert('#settings-error');
    const box = document.getElementById('ai-providers');
    try {
      const providers = await api('/api/ai/providers');
      const status = await api('/api/ai/status').catch(() => null);
      const usage = await api('/api/ai/usage?days=1').catch(() => null);
      renderStatus(status, usage);
      renderProviders(providers, box);
    } catch (error) {
      if (error.status === 403 || error.status === 500 || error.code === 'ENOENT') {
        root.hidden = true;
        return;
      }
      showAlert('#settings-error', error.message || 'Chargement IA impossible.');
    }
  }

  function renderStatus(status, usage) {
    const el = document.getElementById('ai-status');
    if (!status) {
      el.innerHTML = '<span class="badge bg-secondary-subtle text-secondary">Base de données non configurée — IA inactive</span>';
      return;
    }
    const breakers = Array.isArray(status.breakers) ? status.breakers : Object.entries(status.breakers || {}).map(([name, b]) => ({ name, ...b }));
    const parts = [];
    breakers.forEach((b) => {
      const cls = b.state === 'OPEN' ? 'bg-danger-subtle text-danger' : b.state === 'HALF_OPEN' ? 'bg-warning-subtle text-warning' : 'bg-success-subtle text-success';
      const label = b.state === 'OPEN' ? 'coupé' : b.state === 'HALF_OPEN' ? 'test' : 'actif';
      parts.push(`<span class="badge ${cls}">${escapeHtml(b.name || 'provider')} : ${label}</span>`);
    });
    const activeProviders = (status.providers || []).map((p) => `<span class="badge bg-primary-subtle text-primary">${escapeHtml(p.label || p.name)}</span>`).join('');
    const tokens = usage && usage.stats ? usage.stats.reduce((sum, s) => sum + Number(s.total_tokens || 0), 0) : 0;
    const calls = usage && usage.stats ? usage.stats.reduce((sum, s) => sum + Number(s.calls || 0), 0) : 0;
    el.innerHTML =
      `<div class="d-flex gap-2 flex-wrap mb-2">${activeProviders || '<span class="badge bg-secondary-subtle text-secondary">Aucun provider actif</span>'}${parts.join('')}</div>` +
      `<div class="fs-12 text-muted">Consommation 24 h : ${escapeHtml(String(calls))} appel(s), ${escapeHtml(String(tokens))} token(s).</div>`;
  }

  function renderProviders(providers, box) {
    if (!providers.length) {
      box.innerHTML = '<div class="text-muted fs-13">Aucun provider configuré. Créez-en un (ex. gemini, openai, mistral) puis ajoutez une clé API et un modèle.</div>';
      return;
    }
    box.innerHTML = '';
    providers.forEach((p) => {
      const card = document.createElement('div');
      card.className = 'border rounded p-3';
      const stateBadge = p.isActive
        ? '<span class="badge bg-success-subtle text-success">Actif</span>'
        : '<span class="badge bg-secondary-subtle text-secondary">Inactif</span>';
      const defaultBadge = p.isDefault ? '<span class="badge bg-primary-subtle text-primary">Défaut</span>' : '';

      card.innerHTML = `
        <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
          <div class="d-flex align-items-center gap-2 flex-wrap">
            <strong class="fs-14">${escapeHtml(p.label || p.name)}</strong>
            <code class="fs-11">${escapeHtml(p.name)}</code>
            <span class="badge bg-info-subtle text-info">${escapeHtml(KIND_LABELS[p.kind] || p.kind)}</span>
            ${stateBadge}${defaultBadge}
            ${p.baseUrl ? `<span class="text-muted fs-12">${escapeHtml(p.baseUrl)}</span>` : ''}
          </div>
          <div class="d-flex gap-2">
            <div class="form-check form-switch m-0 align-self-center">
              <input class="form-check-input" type="checkbox" data-act="toggle-provider" ${p.isActive ? 'checked' : ''} title="Activer ce provider" />
            </div>
            <button class="btn btn-sm btn-outline-danger btn-icon" type="button" data-act="del-provider" title="Supprimer"><i class="ti ti-trash"></i></button>
          </div>
        </div>
        <div class="row g-3">
          <div class="col-md-6">
            <p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Clés API <button class="btn btn-link btn-sm p-0 ms-1" type="button" data-act="add-key">+ ajouter</button></p>
            <div data-keys class="d-flex flex-wrap gap-2"></div>
          </div>
          <div class="col-md-6">
            <p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Modèles <button class="btn btn-link btn-sm p-0 ms-1" type="button" data-act="add-model">+ ajouter</button></p>
            <div data-models class="d-flex flex-wrap gap-2"></div>
          </div>
        </div>`;

      const keysEl = card.querySelector('[data-keys]');
      if (!p.keys.length) keysEl.innerHTML = '<span class="text-muted fs-12">Aucune clé</span>';
      p.keys.forEach((k) => {
        const el = document.createElement('span');
        el.className = 'badge bg-light text-body border';
        el.innerHTML = `<code class="fs-11">${escapeHtml(k.label || 'clé')} ${escapeHtml(k.masked)}</code>${k.isDefault ? ' ★' : ''}
          <button class="btn btn-link btn-sm p-0 ms-1 text-danger" type="button" data-act="del-key" data-id="${k.id}" title="Supprimer la clé">×</button>`;
        keysEl.appendChild(el);
      });

      const modelsEl = card.querySelector('[data-models]');
      if (!p.models.length) modelsEl.innerHTML = '<span class="text-muted fs-12">Aucun modèle</span>';
      p.models.forEach((m) => {
        const el = document.createElement('span');
        el.className = 'badge bg-light text-body border';
        el.innerHTML = `<span class="fs-11">${escapeHtml(m.label || m.name)}</span> <span class="text-muted">${escapeHtml(m.type)}</span>${m.isDefault ? ' ★' : ''}
          <button class="btn btn-link btn-sm p-0 ms-1 text-danger" type="button" data-act="del-model" data-id="${m.id}" title="Supprimer le modèle">×</button>`;
        modelsEl.appendChild(el);
      });

      card.querySelector('[data-act="toggle-provider"]').addEventListener('change', async (e) => {
        await patch(`/api/ai/providers/${p.id}`, { isActive: e.target.checked });
      });
      card.querySelector('[data-act="del-provider"]').addEventListener('click', async () => {
        if (!window.confirm(`Supprimer le provider « ${p.label || p.name} » ?`)) return;
        await del(`/api/ai/providers/${p.id}`);
      });
      card.querySelector('[data-act="add-key"]').addEventListener('click', async () => {
        const key = window.prompt('Clé API (ne sera jamais réaffichée en clair) :');
        if (!key) return;
        const label = window.prompt('Libellé de la clé (ex. prod) :') || 'clé';
        await post(`/api/ai/providers/${p.id}/keys`, { apiKey: key.trim(), label });
      });
      card.querySelectorAll('[data-act="del-key"]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await del(`/api/ai/keys/${btn.dataset.id}`);
        });
      });
      card.querySelector('[data-act="add-model"]').addEventListener('click', async () => {
        const name = window.prompt('Nom du modèle (ex. gemini-2.5-flash) :');
        if (!name) return;
        const label = window.prompt('Libellé affiché :') || name;
        const type = window.prompt('Type : CHAT, EMBEDDING ou RERANK :', 'CHAT');
        const cleanType = MODEL_TYPES.includes((type || '').toUpperCase()) ? type.toUpperCase() : 'CHAT';
        await post(`/api/ai/providers/${p.id}/models`, { name: name.trim(), label, type: cleanType });
      });
      card.querySelectorAll('[data-act="del-model"]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          await del(`/api/ai/models/${btn.dataset.id}`);
        });
      });

      box.appendChild(card);
    });
  }

  async function createProvider() {
    const name = document.getElementById('ai-name').value.trim();
    const label = document.getElementById('ai-label').value.trim();
    const baseUrl = document.getElementById('ai-baseurl').value.trim();
    if (!name) return showAlert('#settings-error', 'Nom du provider requis.');
    try {
      await post('/api/ai/providers', { name, label: label || name, baseUrl });
      document.getElementById('ai-form').hidden = true;
      ['ai-name', 'ai-label', 'ai-baseurl'].forEach((id) => {
        document.getElementById(id).value = '';
      });
      await loadAll();
    } catch (error) {
      showAlert('#settings-error', error.message);
    }
  }

  async function post(path, body) {
    try {
      await api(path, { method: 'POST', body });
      await loadAll();
    } catch (error) {
      showAlert('#settings-error', error.message);
    }
  }

  async function patch(path, body) {
    try {
      await api(path, { method: 'PATCH', body });
      await loadAll();
    } catch (error) {
      showAlert('#settings-error', error.message);
    }
  }

  async function del(path) {
    try {
      await api(path, { method: 'DELETE' });
      await loadAll();
    } catch (error) {
      showAlert('#settings-error', error.message);
    }
  }

  boot();
})();

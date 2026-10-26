(function () {
  'use strict';

  SOC.initShell('incidents');

  const Case = SOC.Case;
  const PAGE_SIZE = 25;

  let query = '';
  let status = '';
  let priority = '';
  let assignee = '';
  let users = [];
  let currentCase = null;
  let pickedThreat = null;

  const tbody = document.getElementById('incidents-table-body');
  const range = document.getElementById('incidents-range');
  const searchForm = document.getElementById('incidents-search');
  const searchInput = document.getElementById('incidents-query');
  const statusSelect = document.getElementById('incidents-status');
  const prioritySelect = document.getElementById('incidents-priority');
  const assigneeSelect = document.getElementById('incidents-assignee');

  const caseModalEl = document.getElementById('case-modal');
  const caseModal = caseModalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal
    ? new bootstrap.Modal(caseModalEl)
    : null;
  const newModalEl = document.getElementById('case-new-modal');
  const newModal = newModalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal
    ? new bootstrap.Modal(newModalEl)
    : null;

  const COLSPAN = 8;

  /* ── filtres ── */

  function fillFilters() {
    statusSelect.innerHTML = '<option value="">Statut : tous</option>' + Case.statusOptions('');
    prioritySelect.innerHTML = '<option value="">Priorité : toutes</option>' + Case.priorityOptions('');

    const options = ['<option value="">Techniciens : tous</option>'];
    options.push('<option value="me">Mes dossiers</option>');
    options.push('<option value="unassigned">Non attribués</option>');
    options.push(...users.map(
      (user) => `<option value="${SOC.escapeHtml(user.username)}">${SOC.escapeHtml(user.displayName || user.username)}</option>`,
    ));
    assigneeSelect.innerHTML = options.join('');
    assigneeSelect.value = assignee;
  }

  /* ── compteurs ── */

  function setKpi(key, value) {
    const el = document.querySelector(`[data-kpi-${key}]`);
    if (el) el.textContent = SOC.formatNumber(value);
  }

  async function loadSummary() {
    try {
      const payload = await SOC.api('/api/cases/summary');
      const data = payload.data || {};
      setKpi('total', data.total || 0);
      setKpi('open', data.open || 0);
      setKpi('mine', data.mine || 0);
      setKpi('critical', data.critical || 0);
    } catch (error) {
      SOC.showAlert('#incidents-error', error.message || 'Impossible de charger les compteurs.');
    }
  }

  /* ── liste ── */

  function loadingRow() {
    tbody.innerHTML = SOC.skeletonRows(COLSPAN, 6);
  }

  function renderRows(data) {
    if (!data.length) {
      const empty = status || priority || assignee || query
        ? 'Aucun dossier ne correspond à ces filtres.'
        : "Aucun dossier d'incident — attribuez une menace depuis la page Menaces ou le bouton « Attribuer une menace ».";
      tbody.innerHTML = `<tr><td colspan="${COLSPAN}">${SOC.emptyState(empty, 'ti-folder-briefcase')}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map((dossier) => {
        const threat = dossier.threat || {};
        const endpoint = threat.agentId
          ? `<a href="/endpoints/${encodeURIComponent(threat.agentId)}" class="text-decoration-none" data-endpoint-link>${SOC.escapeHtml(threat.agentName || '—')}</a>
             <div class="text-muted fs-12">${SOC.escapeHtml(threat.site || '')}</div>`
          : `<span class="text-muted">${SOC.escapeHtml(threat.agentName || '—')}</span>`;

        return `<tr class="soc-case-row" data-case-id="${dossier.id}" style="cursor:pointer">
          <td>
            <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(threat.name || '')}">${SOC.escapeHtml(threat.name || 'Menace inconnue')}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(threat.classification || `Dossier #${dossier.id}`)}</span>
          </td>
          <td>${SOC.severityBadge(threat.severity)}</td>
          <td class="fs-13">${endpoint}</td>
          <td>${Case.priorityBadge(dossier.priority)}</td>
          <td>${Case.statusBadge(dossier.status)}</td>
          <td>
            ${Case.assigneeHtml(dossier)}
            <div class="text-muted fs-12 mt-1">
              <i class="ti ti-message me-1"></i>${SOC.formatNumber(dossier.commentCount)}
              <i class="ti ti-paperclip ms-2 me-1"></i>${SOC.formatNumber(dossier.attachmentCount)}
            </div>
          </td>
          <td class="text-muted fs-13">
            ${SOC.formatDate(dossier.updatedAt)}
            <div class="fs-11">${dossier.updatedAt ? SOC.formatRelative(dossier.updatedAt) : ''}</div>
          </td>
          <td class="text-end">
            <button class="btn btn-sm btn-outline-primary" type="button" data-open-case="${dossier.id}">
              Ouvrir<i class="ti ti-chevron-right ms-1"></i>
            </button>
          </td>
        </tr>`;
      })
      .join('');
  }

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('incidents-prev'),
    next: document.getElementById('incidents-next'),
    label: document.getElementById('incidents-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="${COLSPAN}">${SOC.emptyState('Dossiers indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#incidents-error', error.message || 'Impossible de charger les dossiers.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#incidents-error');
      loadingRow();
      const page = await SOC.api(
        `/api/cases?${SOC.params({ limit: PAGE_SIZE, cursor, query, status, priority, assignee })}`,
      );
      renderRows(page.data || []);
      const total = (page.pagination && page.pagination.totalItems) || 0;
      range.textContent = `${(page.data || []).length} dossier(s) affiché(s) sur ${SOC.formatNumber(total)}`;
      SOC.markUpdated();
      return page;
    },
  });

  /* ── détail du dossier ── */

  function renderJournal(events) {
    const body = document.getElementById('case-journal-body');
    if (!events || !events.length) {
      body.innerHTML = SOC.emptyState('Aucun événement pour ce dossier.', 'ti-history');
      return;
    }
    body.innerHTML = events.map(Case.journalItem).join('');
  }

  function renderAttachments(attachments) {
    const body = document.getElementById('case-attachments-body');
    const count = document.getElementById('case-attachment-count');
    const list = attachments || [];
    if (count) count.textContent = String(list.length);
    if (!list.length) {
      body.innerHTML = SOC.emptyState('Aucun rapport joint pour ce dossier.', 'ti-file-text');
      return;
    }
    body.innerHTML = `<div class="table-responsive">
      <table class="table table-custom table-centered table-nowrap mb-0 soc-table">
        <thead><tr><th>Fichier</th><th>Taille</th><th>Ajouté par</th><th>Le</th><th class="text-end">Actions</th></tr></thead>
        <tbody>
          ${list
            .map(
              (file) => `<tr>
                <td class="fw-semibold fs-13">
                  <i class="ti ti-paperclip me-1"></i>
                  <a href="/api/cases/${currentCase.id}/attachments/${file.id}" class="text-decoration-none">${SOC.escapeHtml(file.filename)}</a>
                </td>
                <td class="text-muted fs-13">${Case.formatSize(file.size)}</td>
                <td class="fs-13">${SOC.escapeHtml(file.uploadedBy || '—')}</td>
                <td class="text-muted fs-13">${SOC.formatDate(file.createdAt)}</td>
                <td class="text-end">
                  <button class="btn btn-sm btn-outline-danger" type="button"
                    data-delete-attachment="${file.id}" title="Supprimer ce rapport">
                    <i class="ti ti-trash"></i>
                  </button>
                </td>
              </tr>`,
            )
            .join('')}
        </tbody>
      </table>
    </div>`;
  }

  function renderCaseHeader(dossier) {
    const threat = dossier.threat || {};
    document.getElementById('case-modal-title').textContent = threat.name || `Dossier #${dossier.id}`;
    document.getElementById('case-modal-subtitle').textContent =
      `Dossier #${dossier.id} · ouvert par ${dossier.createdBy || '—'} le ${SOC.formatDate(dossier.createdAt)}`;

    const badges = [
      SOC.severityBadge(threat.severity),
      Case.priorityBadge(dossier.priority),
      Case.statusBadge(dossier.status),
      threat.agentId
        ? `<a class="badge bg-light text-body border text-decoration-none" href="/endpoints/${encodeURIComponent(threat.agentId)}"><i class="ti ti-device-desktop me-1"></i>${SOC.escapeHtml(threat.agentName || 'Endpoint')}</a>`
        : '',
      threat.storyline
        ? `<span class="badge bg-secondary-subtle text-secondary soc-truncate" style="max-width:220px" title="${SOC.escapeHtml(threat.storyline)}">Storyline</span>`
        : '',
    ].filter(Boolean);
    document.getElementById('case-modal-badges').innerHTML = badges.join(' ');

    document.getElementById('case-modal-meta').innerHTML = threat.createdAt
      ? `<i class="ti ti-clock-hour-4 me-1"></i>Menace détectée le ${SOC.formatDate(threat.createdAt)}`
      : '';

    const controls = document.getElementById('case-controls');
    controls.innerHTML = Case.controlsHtml(dossier, users);
    Case.bindControls(controls, dossier.id, onCaseUpdated);
  }

  async function refreshDetail() {
    if (!currentCase) return;
    const payload = await SOC.api(`/api/cases/${currentCase.id}`);
    currentCase = payload.data.case;
    renderCaseHeader(currentCase);
    renderJournal(payload.data.events);
    renderAttachments(payload.data.attachments);
  }

  function onCaseUpdated(dossier, changed, error) {
    if (error || !dossier) return;
    currentCase = dossier;
    if (changed === false) {
      renderCaseHeader(dossier);
      return;
    }
    refreshDetail()
      .then(() => {
        pager.load();
        loadSummary();
      })
      .catch((refreshError) => {
        SOC.showAlert('#case-error', refreshError.message || 'Rechargement impossible.');
      });
  }

  async function openCase(caseId) {
    if (!caseModal) return;
    currentCase = { id: caseId };
    SOC.clearAlert('#case-error');
    document.getElementById('case-modal-title').textContent = 'Chargement…';
    document.getElementById('case-modal-subtitle').textContent = '—';
    document.getElementById('case-modal-badges').innerHTML = '';
    document.getElementById('case-modal-meta').textContent = '—';
    document.getElementById('case-controls').innerHTML = '';
    document.getElementById('case-journal-body').innerHTML =
      '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    document.getElementById('case-attachments-body').innerHTML =
      '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    caseModal.show();

    try {
      const payload = await SOC.api(`/api/cases/${caseId}`);
      currentCase = payload.data.case;
      renderCaseHeader(currentCase);
      renderJournal(payload.data.events);
      renderAttachments(payload.data.attachments);
    } catch (error) {
      SOC.showAlert('#case-error', error.message || 'Impossible de charger le dossier.');
    }
  }

  tbody.addEventListener('click', (event) => {
    if (event.target.closest('a[data-endpoint-link]')) return;
    const open = event.target.closest('[data-open-case]');
    if (open) {
      openCase(open.getAttribute('data-open-case'));
      return;
    }
    const row = event.target.closest('tr.soc-case-row');
    if (row) openCase(row.getAttribute('data-case-id'));
  });

  /* ── commentaire ── */

  const commentForm = document.getElementById('case-comment-form');
  const commentInput = document.getElementById('case-comment');

  commentForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const message = commentInput.value.trim();
    if (!message || !currentCase) return;
    const button = commentForm.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await SOC.api(`/api/cases/${currentCase.id}/events`, { method: 'POST', body: { message } });
      commentInput.value = '';
      await refreshDetail();
    } catch (error) {
      SOC.showAlert('#case-error', error.message || 'Commentaire impossible.');
    } finally {
      button.disabled = false;
    }
  });

  /* ── rapports ── */

  const uploadForm = document.getElementById('case-upload-form');
  const fileInput = document.getElementById('case-file');

  uploadForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const file = fileInput.files && fileInput.files[0];
    if (!file || !currentCase) return;
    const button = uploadForm.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const form = new FormData();
      form.append('file', file, file.name);
      const response = await fetch(`/api/cases/${currentCase.id}/attachments`, {
        method: 'POST',
        credentials: 'same-origin',
        body: form,
      });
      const payload = await response.json().catch(() => null);
      if (response.status === 401) {
        window.location.replace('/login');
        return;
      }
      if (!response.ok) {
        throw new Error((payload && payload.error) || `Erreur ${response.status}.`);
      }
      SOC.clearAlert('#case-error');
      fileInput.value = '';
      SOC.showAlert('#case-upload-status', `Rapport « ${payload.data.filename} » joint au dossier.`, 'success');
      await refreshDetail();
      pager.load();
    } catch (error) {
      SOC.showAlert('#case-upload-status', error.message || 'Téléversement impossible.');
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById('case-attachments-body').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-delete-attachment]');
    if (!button || !currentCase) return;
    const fileId = button.getAttribute('data-delete-attachment');
    if (!window.confirm('Supprimer définitivement ce rapport du dossier ?')) return;
    button.disabled = true;
    try {
      await SOC.api(`/api/cases/${currentCase.id}/attachments/${fileId}`, { method: 'DELETE' });
      await refreshDetail();
      pager.load();
    } catch (error) {
      button.disabled = false;
      SOC.showAlert('#case-error', error.message || 'Suppression impossible.');
    }
  });

  /* ── attribution d'une nouvelle menace ── */

  const newResults = document.getElementById('case-new-results');
  const newPicked = document.getElementById('case-new-picked');
  const newQuery = document.getElementById('case-new-query');
  const newAssignee = document.getElementById('case-new-assignee');
  const newPriority = document.getElementById('case-new-priority');
  const newComment = document.getElementById('case-new-comment');
  const newSubmit = document.getElementById('case-new-submit');

  function resetNewModal() {
    pickedThreat = null;
    newQuery.value = '';
    newResults.innerHTML = '';
    newComment.value = '';
    newPicked.textContent = 'Aucune menace sélectionnée.';
    newSubmit.disabled = true;
    SOC.clearAlert('#case-new-error');
    newAssignee.innerHTML = Case.userOptions(users, SOC.state.user ? SOC.state.user.username : '');
    newPriority.innerHTML = Case.priorityOptions('moyenne');
  }

  function pickThreat(button) {
    pickedThreat = { id: button.getAttribute('data-threat-id'), name: button.getAttribute('data-threat-name') };
    newResults.querySelectorAll('.list-group-item').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    newPicked.textContent = `Menace retenue : ${pickedThreat.name}`;
    newSubmit.disabled = false;
  }

  async function searchThreats() {
    const value = newQuery.value.trim();
    SOC.clearAlert('#case-new-error');
    newResults.innerHTML = `<div class="list-group-item text-muted">Recherche…</div>`;
    try {
      const page = await SOC.api(`/api/threats?${SOC.params({ query: value, limit: 25 })}`);
      const available = (page.data || []).filter((threat) => !threat.case);
      if (!available.length) {
        newResults.innerHTML = `<div class="list-group-item text-muted">Aucune menace disponible (déjà suivie ou introuvable).</div>`;
        return;
      }
      newResults.innerHTML = available
        .map(
          (threat) => `<button type="button" class="list-group-item list-group-item-action"
            data-threat-id="${SOC.escapeHtml(threat.id)}" data-threat-name="${SOC.escapeHtml(threat.name)}">
            <span class="d-flex justify-content-between gap-2">
              <span class="fw-semibold text-truncate">${SOC.escapeHtml(threat.name)}</span>
              ${SOC.severityBadge(threat.severity)}
            </span>
            <span class="fs-12 text-muted">${SOC.escapeHtml(threat.agentName)}${threat.site ? ` · ${SOC.escapeHtml(threat.site)}` : ''}</span>
          </button>`,
        )
        .join('');
    } catch (error) {
      SOC.showAlert('#case-new-error', error.message || 'Recherche impossible.');
      newResults.innerHTML = '';
    }
  }

  newResults.addEventListener('click', (event) => {
    const button = event.target.closest('[data-threat-id]');
    if (button) pickThreat(button);
  });

  document.getElementById('case-new-search').addEventListener('click', searchThreats);
  newQuery.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      searchThreats();
    }
  });

  newSubmit.addEventListener('click', async () => {
    if (!pickedThreat) return;
    SOC.clearAlert('#case-new-error');
    newSubmit.disabled = true;
    try {
      const dossier = await Case.assign(pickedThreat.id, {
        assignee: newAssignee.value,
        priority: newPriority.value,
        message: newComment.value.trim(),
      });
      if (newModal) newModal.hide();
      await Promise.all([pager.load(), loadSummary()]);
      SOC.showAlert('#incidents-error', `Menace attribuée à ${dossier.assignee} (dossier #${dossier.id}).`, 'success');
      openCase(dossier.id);
    } catch (error) {
      SOC.showAlert('#case-new-error', error.message || 'Attribution impossible.');
      newSubmit.disabled = false;
    }
  });

  const newButton = document.getElementById('incident-new');
  if (newButton) {
    newButton.addEventListener('click', () => {
      resetNewModal();
      if (newModal) newModal.show();
      newQuery.focus();
    });
  }

  /* ── filtres + démarrage ── */

  searchForm.addEventListener('submit', (event) => {
    event.preventDefault();
    query = searchInput.value.trim();
    status = statusSelect.value;
    priority = prioritySelect.value;
    assignee = assigneeSelect.value;
    pager.reset();
  });

  statusSelect.addEventListener('change', () => {
    status = statusSelect.value;
    pager.reset();
  });
  prioritySelect.addEventListener('change', () => {
    priority = prioritySelect.value;
    pager.reset();
  });
  assigneeSelect.addEventListener('change', () => {
    assignee = assigneeSelect.value;
    pager.reset();
  });

  document.getElementById('incidents-reset').addEventListener('click', () => {
    searchInput.value = '';
    statusSelect.value = '';
    prioritySelect.value = '';
    assigneeSelect.value = '';
    query = '';
    status = '';
    priority = '';
    assignee = '';
    pager.reset();
  });

  SOC.onRefresh(async () => {
    await Promise.all([pager.load(), loadSummary()]);
  });

  // Dossier ouvert en profondeur : /incidents?case=12 (lien depuis l'enquête).
  const deepCaseId = new URLSearchParams(window.location.search).get('case');

  async function init() {
    try {
      users = await Case.roster();
    } catch (error) {
      // 503 sans PostgreSQL : message serveur, filtres limités aux valeurs globales.
      SOC.showAlert('#incidents-error', error.message || 'Collaboration indisponible.');
    }
    fillFilters();
    await pager.load();
    loadSummary();
    if (deepCaseId && /^\d+$/.test(deepCaseId)) {
      history.replaceState(null, '', '/incidents');
      openCase(Number(deepCaseId));
    }
  }

  init();
})();

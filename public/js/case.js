/* Dossiers d'incident (suivi collaboratif) — helpers partagés. */
(function () {
  'use strict';

  const STATUS_LABELS = {
    nouveau: 'Nouveau',
    en_cours: 'En cours',
    en_attente: 'En attente',
    resolu: 'Résolu',
    ferme: 'Fermé',
  };
  const STATUS_CLASSES = {
    nouveau: 'bg-info-subtle text-info',
    en_cours: 'bg-primary-subtle text-primary',
    en_attente: 'bg-warning-subtle text-warning',
    resolu: 'bg-success-subtle text-success',
    ferme: 'bg-secondary-subtle text-secondary',
  };
  const PRIORITY_LABELS = {
    basse: 'Basse',
    moyenne: 'Moyenne',
    haute: 'Haute',
    critique: 'Critique',
  };
  const PRIORITY_CLASSES = {
    basse: 'bg-secondary-subtle text-secondary',
    moyenne: 'bg-info-subtle text-info',
    haute: 'bg-warning-subtle text-warning',
    critique: 'bg-danger-subtle text-danger',
  };
  const EVENT_ICONS = {
    created: 'ti-folder-plus',
    assigned: 'ti-user-check',
    status: 'ti-refresh',
    priority: 'ti-flag',
    comment: 'ti-message',
    attachment_added: 'ti-paperclip',
    attachment_removed: 'ti-file-off',
  };
  const EVENT_LABELS = {
    created: 'Dossier créé',
    assigned: 'Attribution',
    status: 'Statut modifié',
    priority: 'Priorité modifiée',
    comment: 'Commentaire',
    attachment_added: 'Rapport ajouté',
    attachment_removed: 'Rapport retiré',
  };

  let rosterCache = null;

  // Roster des techniciens (alimenté à chaque connexion). Mis en cache par
  // onglet : la page peut ouvrir plusieurs dossiers sans re-télécharger la liste.
  async function roster(force) {
    if (rosterCache && !force) return rosterCache;
    const payload = await SOC.api('/api/users');
    rosterCache = (payload && payload.data) || [];
    return rosterCache;
  }

  function statusBadge(status) {
    const key = STATUS_LABELS[status] ? status : 'nouveau';
    return SOC.textBadge(STATUS_LABELS[key], STATUS_CLASSES[key]);
  }

  function priorityBadge(priority) {
    const key = PRIORITY_LABELS[priority] ? priority : 'moyenne';
    return SOC.textBadge(PRIORITY_LABELS[key], PRIORITY_CLASSES[key]);
  }

  function assigneeHtml(dossier) {
    const name = dossier && dossier.assignee ? dossier.assignee : '';
    if (!name) return '<span class="text-muted">Non attribuée</span>';
    return `<span class="d-inline-flex align-items-center gap-1"><i class="ti ti-user"></i>${SOC.escapeHtml(name)}</span>`;
  }

  // Résumé compact pour une colonne de tableau : technicien + statut.
  function summaryHtml(dossier) {
    if (!dossier) return '<span class="text-muted fs-13">Non attribuée</span>';
    return `${assigneeHtml(dossier)}<div class="mt-1">${statusBadge(dossier.status)}</div>`;
  }

  function optionList(entries, selected) {
    return entries
      .map(([value, label]) =>
        `<option value="${SOC.escapeHtml(value)}"${String(value) === String(selected) ? ' selected' : ''}>${SOC.escapeHtml(label)}</option>`,
      )
      .join('');
  }

  function statusOptions(selected) {
    return optionList(Object.entries(STATUS_LABELS), selected);
  }

  function priorityOptions(selected) {
    return optionList(Object.entries(PRIORITY_LABELS), selected);
  }

  function userOptions(users, selected, extra) {
    const options = (extra || []).map(([value, label]) => [value, label]);
    for (const user of users || []) {
      options.push([user.username, `${user.displayName || user.username}`]);
    }
    return optionList(options, selected);
  }

  // Trois sélecteurs (statut / priorité / technicien) dans un conteneur unique.
  function controlsHtml(dossier, users) {
    return `
      <div class="row g-2 align-items-end">
        <div class="col-sm-4 col-md-3">
          <label class="form-label fs-12 text-muted mb-1" for="case-status">Statut</label>
          <select class="form-select form-select-sm" id="case-status" data-case-field="status" ${dossier ? '' : 'disabled'}>
            ${statusOptions(dossier ? dossier.status : 'nouveau')}
          </select>
        </div>
        <div class="col-sm-4 col-md-3">
          <label class="form-label fs-12 text-muted mb-1" for="case-priority">Priorité</label>
          <select class="form-select form-select-sm" id="case-priority" data-case-field="priority" ${dossier ? '' : 'disabled'}>
            ${priorityOptions(dossier ? dossier.priority : 'moyenne')}
          </select>
        </div>
        <div class="col-sm-4 col-md-4">
          <label class="form-label fs-12 text-muted mb-1" for="case-assignee">Technicien</label>
          <select class="form-select form-select-sm" id="case-assignee" data-case-field="assignee" ${dossier ? '' : 'disabled'}>
            ${userOptions(users, dossier ? dossier.assignee : '', [])}
          </select>
        </div>
      </div>`;
  }

  // Écoute les trois sélecteurs du conteneur : chaque changement devient un
  // PATCH (le serveur transforme en événement avant/après) puis `onUpdated`.
  // Le dossier courant est relu sur le conteneur : on n'attache qu'un seul
  // écouteur quand la page ouvre plusieurs dossiers successivement.
  function bindControls(container, dossierId, onUpdated) {
    if (!container) return;
    container.dataset.caseId = String(dossierId || '');
    if (container.dataset.caseBound === '1') return;
    container.dataset.caseBound = '1';
    container.addEventListener('change', async (event) => {
      const select = event.target.closest('[data-case-field]');
      const caseId = container.dataset.caseId;
      if (!select || !caseId) return;
      const field = select.getAttribute('data-case-field');
      const value = select.value;
      select.disabled = true;
      try {
        const payload = await SOC.api(`/api/cases/${caseId}`, {
          method: 'PATCH',
          body: { [field]: value },
        });
        if (onUpdated) onUpdated(payload.data, payload.changed);
      } catch (error) {
        if (onUpdated) onUpdated(null, false, error);
        SOC.showAlert('#case-error', error.message || 'Modification impossible.');
      } finally {
        select.disabled = false;
      }
    });
  }

  function eventTitle(event) {
    const label = EVENT_LABELS[event.type] || event.type;
    const payload = event.payload || {};
    if (event.type === 'assigned') {
      return `${label} : ${payload.from || '—'} → ${payload.to || '—'}`;
    }
    if (event.type === 'status') {
      return `${label} : ${STATUS_LABELS[payload.from] || payload.from || '—'} → ${STATUS_LABELS[payload.to] || payload.to || '—'}`;
    }
    if (event.type === 'priority') {
      return `${label} : ${PRIORITY_LABELS[payload.from] || payload.from || '—'} → ${PRIORITY_LABELS[payload.to] || payload.to || '—'}`;
    }
    if (event.type === 'attachment_added' || event.type === 'attachment_removed') {
      return `${label} : ${payload.filename || '—'} (${formatSize(payload.size)})`;
    }
    return label;
  }

  function journalItem(event) {
    const icon = EVENT_ICONS[event.type] || 'ti-circle';
    const isComment = event.type === 'comment';
    return `<div class="soc-list-item">
      <div class="d-flex justify-content-between gap-3">
        <div class="min-width-0">
          <span class="fw-semibold d-block"><i class="ti ${icon} me-1"></i>${SOC.escapeHtml(eventTitle(event))}</span>
          ${isComment ? `<div class="soc-case-comment fs-13">${SOC.escapeHtml(event.message)}</div>` : ''}
          <span class="text-muted fs-12"><i class="ti ti-user me-1"></i>${SOC.escapeHtml(event.author || '—')}</span>
        </div>
        <span class="text-muted fs-12 text-nowrap">${SOC.formatDate(event.createdAt)}</span>
      </div>
    </div>`;
  }

  function formatSize(size) {
    const bytes = Number(size);
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 o';
    if (bytes < 1024) return `${bytes} o`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
  }

  // Dossier rattaché à une menace (ou null) — une seule requête sans limit.
  async function findByThreat(threatId) {
    if (!threatId) return null;
    const page = await SOC.api(`/api/cases?${SOC.params({ threatId, limit: 1 })}`);
    return (page.data && page.data[0]) || null;
  }

  async function assign(threatId, { assignee, priority, status, message }) {
    const existing = await findByThreat(threatId);
    if (existing) {
      const changes = {};
      if (assignee) changes.assignee = assignee;
      if (priority) changes.priority = priority;
      if (status) changes.status = status;
      let dossier = existing;
      if (Object.keys(changes).length > 0) {
        const patched = await SOC.api(`/api/cases/${existing.id}`, { method: 'PATCH', body: changes });
        dossier = patched.data;
      }
      if (message) {
        await SOC.api(`/api/cases/${existing.id}/events`, { method: 'POST', body: { message } });
      }
      return dossier;
    }
    const created = await SOC.api('/api/cases', {
      method: 'POST',
      body: { threatId, assignee, priority, status },
    });
    if (message) {
      await SOC.api(`/api/cases/${created.data.id}/events`, { method: 'POST', body: { message } });
    }
    return created.data;
  }

  window.SOC.Case = {
    STATUS_LABELS,
    PRIORITY_LABELS,
    roster,
    statusBadge,
    priorityBadge,
    assigneeHtml,
    summaryHtml,
    statusOptions,
    priorityOptions,
    userOptions,
    controlsHtml,
    bindControls,
    eventTitle,
    journalItem,
    formatSize,
    findByThreat,
    assign,
  };
})();

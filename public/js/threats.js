(function () {
  'use strict';

  SOC.initShell('threats');

  const PAGE_SIZE = 25;
  let query = '';
  let verdict = '';
  let mitigation = '';

  const tbody = document.getElementById('threats-table-body');
  const totalBadge = document.querySelector('[data-threats-total]');
  const range = document.getElementById('threats-range');
  const searchForm = document.getElementById('threats-search');
  const searchInput = document.getElementById('threats-query');
  const verdictSelect = document.getElementById('threats-verdict');
  const mitigationSelect = document.getElementById('threats-mitigation');
  const resetButton = document.getElementById('threats-reset');

  const modalEl = document.getElementById('threat-investigate-modal');
  const modal = modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal
    ? new bootstrap.Modal(modalEl)
    : null;

  function loadingRow() {
    tbody.innerHTML = SOC.skeletonRows(7, 6);
  }

  function agentLink(agent) {
    const id = agent.agentId || (agent.endpoint && agent.endpoint.id) || '';
    const name = agent.agentName || (agent.endpoint && agent.endpoint.name) || '—';
    if (!id) return SOC.escapeHtml(name);
    return `<a href="/endpoints/${encodeURIComponent(id)}" class="text-decoration-none" data-endpoint-link>${SOC.escapeHtml(name)}</a>`;
  }

  function renderRows(data) {
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState(
        query ? 'Aucune menace ne correspond à cette recherche.' : 'Aucune menace remontée par SentinelOne.',
        'ti-shield-check',
      )}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map(
        (threat) => `<tr class="soc-threat-row" data-threat-id="${SOC.escapeHtml(threat.id)}" style="cursor:pointer">
          <td>
            <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(threat.name)}">${SOC.escapeHtml(threat.name)}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(threat.confidence)}</span>
          </td>
          <td>${SOC.severityBadge(threat.severity)}</td>
          <td class="fs-13">${agentLink(threat)}<div class="text-muted fs-12">${SOC.escapeHtml(threat.site)}</div></td>
          <td class="fs-13">${SOC.escapeHtml(threat.classification)}</td>
          <td>${SOC.mitigationBadge(threat.mitigationStatus)}</td>
          <td class="fs-13">${SOC.escapeHtml(SOC.humanize(threat.incidentStatus, SOC.INCIDENT_LABELS))}</td>
          <td class="text-muted fs-13">
            ${SOC.formatDate(threat.createdAt)}
            <div class="fs-11">${threat.createdAt ? SOC.formatRelative(threat.createdAt) : ''}</div>
          </td>
        </tr>`,
      )
      .join('');
  }

  function kv(label, value, cls = '') {
    return `<div class="soc-inv-kv"><dt>${SOC.escapeHtml(label)}</dt><dd class="${cls}">${value}</dd></div>`;
  }

  function renderDetail(threat) {
    const body = document.getElementById('threat-detail-body');
    const hashes = [
      threat.sha256 && kv('SHA256', SOC.escapeHtml(threat.sha256), 'soc-inv-hash'),
      threat.sha1 && kv('SHA1', SOC.escapeHtml(threat.sha1), 'soc-inv-hash'),
      threat.md5 && kv('MD5', SOC.escapeHtml(threat.md5), 'soc-inv-hash'),
    ].filter(Boolean).join('');

    body.innerHTML = `
      <div class="soc-inv-grid mb-3">
        ${kv('Classification', SOC.escapeHtml(threat.classification))}
        ${kv('Confiance', SOC.escapeHtml(threat.confidence))}
        ${kv('Statut d’atténuation', SOC.escapeHtml(SOC.humanize(threat.mitigationStatus, SOC.MITIGATION_LABELS)))}
        ${kv('Incident', SOC.escapeHtml(SOC.humanize(threat.incidentStatus, SOC.INCIDENT_LABELS)))}
        ${kv('Verdict analyste', SOC.escapeHtml(SOC.humanize(threat.analystVerdict)))}
        ${kv('Détectée le', SOC.formatDate(threat.createdAt))}
        ${kv('Ticket externe', SOC.escapeHtml(threat.externalTicketId) || '—')}
        ${kv('Éditeur', SOC.escapeHtml(threat.publisherName))}
      </div>
      <div class="soc-inv-grid mb-3">
        ${kv('Fichier', SOC.escapeHtml(threat.filePath))}
        ${kv('Extension', SOC.escapeHtml(threat.fileExtension))}
        ${kv('Taille', threat.fileSize === null ? '—' : SOC.formatNumber(threat.fileSize) + ' o')}
        ${kv('Processus', SOC.escapeHtml(threat.originatorProcess))}
        ${kv('Utilisateur process', SOC.escapeHtml(threat.processUser))}
        ${kv('Utilisateur initiateur', SOC.escapeHtml(threat.initiatingUsername))}
        ${kv('Arguments malveillants', SOC.escapeHtml(threat.maliciousProcessArguments) || '—')}
        ${kv('Storyline', SOC.escapeHtml(threat.storyline) || '—', 'soc-inv-hash')}
      </div>
      <div class="soc-inv-grid mb-3">
        ${kv('Endpoint', SOC.escapeHtml(threat.agentName))}
        ${kv('OS', SOC.escapeHtml(threat.agentOs))}
        ${kv('IP', SOC.escapeHtml(threat.agentIp))}
        ${kv('Version agent', SOC.escapeHtml(threat.agentVersion))}
        ${kv('Site', SOC.escapeHtml(threat.site))}
        ${kv('UUID agent', SOC.escapeHtml(threat.agentUuid) || '—', 'soc-inv-hash')}
      </div>
      ${hashes ? `<p class="text-muted fs-12 text-uppercase fw-semibold mb-1">Empreintes</p><div class="soc-inv-grid">${hashes}</div>` : ''}
    `;
  }

  function renderEndpoint(threat, applications) {
    const body = document.getElementById('threat-endpoint-body');
    const agentCards = `
      <div class="soc-inv-grid mb-3">
        ${kv('Endpoint', SOC.escapeHtml(threat.agentName))}
        ${kv('OS', SOC.escapeHtml(threat.agentOs))}
        ${kv('IP', SOC.escapeHtml(threat.agentIp))}
        ${kv('Version agent', SOC.escapeHtml(threat.agentVersion))}
        ${kv('Réseau', threat.agentNetworkStatus ? SOC.escapeHtml(SOC.humanize(threat.agentNetworkStatus)) : '—')}
        ${kv('Infecté', threat.agentInfected ? '<span class="badge bg-danger-subtle text-danger">Oui</span>' : '<span class="badge bg-success-subtle text-success">Non</span>')}
        ${kv('Site', SOC.escapeHtml(threat.site))}
        ${kv('UUID', SOC.escapeHtml(threat.agentUuid) || '—', 'soc-inv-hash')}
      </div>`;

    let appsHtml;
    if (!applications.length) {
      appsHtml = SOC.emptyState(
        threat.agentId
          ? 'Aucune application remontée par SentinelOne.'
          : 'Identifiant endpoint inconnu — applications indisponibles.',
        'ti-app-window',
      );
    } else {
      appsHtml = `<div class="table-responsive">
        <table class="table table-custom table-centered table-nowrap mb-0 soc-table">
          <thead>
            <tr>
              <th>Application</th>
              <th>Version</th>
              <th>Taille</th>
              <th>Signée</th>
              <th>Installée le</th>
            </tr>
          </thead>
          <tbody>
            ${applications
              .map(
                (app) => `<tr>
                  <td class="fw-semibold">${SOC.escapeHtml(app.name)}</td>
                  <td class="fs-13">${SOC.escapeHtml(app.version)}</td>
                  <td class="fs-13">${app.size === null ? '—' : `${SOC.formatNumber(Math.round(app.size / 1024))} Ko`}</td>
                  <td>${SOC.escapeHtml(app.signed)}</td>
                  <td class="text-muted fs-13">${SOC.formatDate(app.installedAt)}</td>
                </tr>`,
              )
              .join('')}
          </tbody>
        </table>
      </div>`;
    }

    body.innerHTML = `${agentCards}
      <p class="text-muted fs-12 text-uppercase fw-semibold mb-2">
        <i class="ti ti-app-window me-1"></i>Applications installées (${SOC.formatNumber(applications.length)})
      </p>
      ${appsHtml}`;
  }

  function renderActivities(data) {
    const body = document.getElementById('threat-activities-body');
    if (!data.length) {
      body.innerHTML = SOC.emptyState('Aucune activité console liée à cette menace.', 'ti-history');
      return;
    }
    body.innerHTML = data
      .map(
        (activity) => `<div class="soc-list-item">
          <div class="d-flex justify-content-between gap-3">
            <div class="min-width-0">
              <span class="fw-semibold d-block">${SOC.escapeHtml(activity.description)}</span>
              <span class="text-muted fs-12">${SOC.escapeHtml(activity.details)}</span>
              ${activity.user ? `<span class="text-muted fs-12 d-block"><i class="ti ti-user me-1"></i>${SOC.escapeHtml(activity.user)}</span>` : ''}
            </div>
            <span class="text-muted fs-12 text-nowrap">${SOC.formatDate(activity.createdAt)}</span>
          </div>
        </div>`,
      )
      .join('');
  }

  function renderTimeline(data) {
    const body = document.getElementById('threat-timeline-body');
    if (!data.length) {
      body.innerHTML = SOC.emptyState('Aucun événement de timeline pour cette menace.', 'ti-timeline');
      return;
    }
    body.innerHTML = data
      .map(
        (event) => `<div class="soc-list-item">
          <div class="d-flex justify-content-between gap-3">
            <div class="min-width-0">
              <span class="fw-semibold d-block">${SOC.escapeHtml(event.description)}</span>
              <span class="text-muted fs-12">${SOC.escapeHtml(event.details)}</span>
              ${event.user ? `<span class="text-muted fs-12 d-block"><i class="ti ti-user me-1"></i>${SOC.escapeHtml(event.user)}</span>` : ''}
            </div>
            <span class="text-muted fs-12 text-nowrap">${SOC.formatDate(event.createdAt)}</span>
          </div>
        </div>`,
      )
      .join('');
  }

  function renderNotes(data) {
    const body = document.getElementById('threat-notes-body');
    if (!data.length) {
      body.innerHTML = SOC.emptyState('Aucune note d’équipe sur cette menace.', 'ti-note');
      return;
    }
    body.innerHTML = data
      .map(
        (note) => `<div class="soc-inv-note">
          <div class="d-flex justify-content-between gap-3 mb-1">
            <span class="fw-semibold fs-13"><i class="ti ti-user me-1"></i>${SOC.escapeHtml(note.creator)}</span>
            <span class="text-muted fs-12 text-nowrap">${SOC.formatDate(note.createdAt)}${note.edited ? ' (modifiée)' : ''}</span>
          </div>
          <div class="soc-inv-note-text fs-13">${SOC.escapeHtml(note.text)}</div>
        </div>`,
      )
      .join('');
  }

  function renderRelatedAlerts(data) {
    const body = document.getElementById('threat-alerts-body');
    if (!data.length) {
      body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(
        'Aucune alerte STAR corrélée (storyline/hash) trouvée.',
        'ti-bell-off',
      )}</td></tr>`;
      return;
    }
    body.innerHTML = data
      .map(
        (alert) => `<tr>
          <td>
            <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(alert.name)}">${SOC.escapeHtml(alert.name)}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(alert.eventType)}${alert.indicatorName ? ' · ' + SOC.escapeHtml(alert.indicatorName) : ''}</span>
          </td>
          <td>${SOC.severityBadge(alert.severity)}</td>
          <td class="fs-13">${SOC.escapeHtml(alert.processName)}<div class="text-muted fs-12 soc-truncate" title="${SOC.escapeHtml(alert.processPath)}">${SOC.escapeHtml(alert.processPath)}</div></td>
          <td class="fs-13">${SOC.escapeHtml(SOC.humanize(alert.analystVerdict))}</td>
          <td class="text-muted fs-13">${SOC.formatDate(alert.createdAt)}</td>
        </tr>`,
      )
      .join('');
  }

  function renderRelatedThreats(data) {
    const body = document.getElementById('threat-related-body');
    if (!data.length) {
      body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(
        'Aucune autre menace corrélée sur cette storyline.',
        'ti-shield-check',
      )}</td></tr>`;
      return;
    }
    body.innerHTML = data
      .map(
        (threat) => `<tr class="soc-threat-row" data-threat-id="${SOC.escapeHtml(threat.id)}" style="cursor:pointer">
          <td><span class="fw-semibold soc-truncate" title="${SOC.escapeHtml(threat.name)}">${SOC.escapeHtml(threat.name)}</span></td>
          <td>${SOC.severityBadge(threat.severity)}</td>
          <td class="fs-13">${SOC.escapeHtml(threat.agentName)}</td>
          <td>${SOC.mitigationBadge(threat.mitigationStatus)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(threat.createdAt)}</td>
        </tr>`,
      )
      .join('');
  }

  async function openInvestigate(threatId) {
    if (!modal || !threatId) return;

    document.getElementById('threat-investigate-title').textContent = 'Chargement…';
    document.getElementById('threat-investigate-subtitle').textContent = '—';
    document.getElementById('threat-investigate-badges').innerHTML = '';
    document.getElementById('threat-investigate-correlation').textContent = '—';
    SOC.clearAlert('#threat-investigate-error');
    document.getElementById('threat-detail-body').innerHTML = '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    document.getElementById('threat-endpoint-body').innerHTML = '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    document.getElementById('threat-timeline-body').innerHTML = '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    document.getElementById('threat-activities-body').innerHTML = '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    document.getElementById('threat-notes-body').innerHTML = '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</div>';
    document.getElementById('threat-alerts-body').innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Chargement…</td></tr>';
    document.getElementById('threat-related-body').innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Chargement…</td></tr>';

    modal.show();

    try {
      const payload = await SOC.api(`/api/threats/${encodeURIComponent(threatId)}/investigate`);
      const threat = payload.threat;

      document.getElementById('threat-investigate-title').textContent = threat.name;
      document.getElementById('threat-investigate-subtitle').textContent =
        `${threat.agentName} · ${threat.site} · ${SOC.formatDate(threat.createdAt)}`;
      document.getElementById('threat-investigate-badges').innerHTML = [
        SOC.severityBadge(threat.severity),
        SOC.mitigationBadge(threat.mitigationStatus),
        `<span class="badge bg-primary-subtle text-primary">${SOC.escapeHtml(SOC.humanize(threat.analystVerdict))}</span>`,
        `<span class="badge bg-secondary-subtle text-secondary">${SOC.escapeHtml(SOC.humanize(threat.incidentStatus, SOC.INCIDENT_LABELS))}</span>`,
      ].join(' ');

      if (payload.correlation) {
        const key = payload.correlation.key === 'storyline' ? 'Storyline' : 'SHA256';
        document.getElementById('threat-investigate-correlation').innerHTML =
          `<i class="ti ti-link me-1"></i>Corrélation par ${key} : <code>${SOC.escapeHtml(payload.correlation.value)}</code>`;
      }

      if (payload.warnings && payload.warnings.length) {
        SOC.showAlert(
          '#threat-investigate-error',
          `Données partielles : ${payload.warnings.map((w) => w.message).join(' ')}`,
          'warning',
        );
      }

      renderDetail(threat);
      renderEndpoint(threat, payload.applications.data);
      renderTimeline(payload.timeline.data);
      renderActivities(payload.activities.data);
      renderNotes(payload.notes.data);
      renderRelatedAlerts(payload.relatedAlerts.data);
      renderRelatedThreats(payload.relatedThreats.data);
    } catch (error) {
      SOC.showAlert('#threat-investigate-error', error.message || 'Impossible de charger l’enquête.');
      document.getElementById('threat-detail-body').innerHTML = '';
      document.getElementById('threat-endpoint-body').innerHTML = '';
      document.getElementById('threat-timeline-body').innerHTML = '';
      document.getElementById('threat-activities-body').innerHTML = '';
      document.getElementById('threat-notes-body').innerHTML = '';
      document.getElementById('threat-alerts-body').innerHTML = '';
      document.getElementById('threat-related-body').innerHTML = '';
    }
  }

  tbody.addEventListener('click', (event) => {
    if (event.target.closest('a[data-endpoint-link]')) return;
    const row = event.target.closest('tr.soc-threat-row');
    if (row) openInvestigate(row.getAttribute('data-threat-id'));
  });

  const relatedBody = document.getElementById('threat-related-body');
  if (relatedBody) {
    relatedBody.addEventListener('click', (event) => {
      const row = event.target.closest('tr.soc-threat-row');
      if (row) openInvestigate(row.getAttribute('data-threat-id'));
    });
  }

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('threats-prev'),
    next: document.getElementById('threats-next'),
    label: document.getElementById('threats-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState('Données indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#threats-error', error.message || 'Impossible de charger les menaces.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#threats-error');
      loadingRow();
      const page = await SOC.api(
        `/api/threats?${SOC.params({ limit: PAGE_SIZE, cursor, query, analystVerdicts: verdict, mitigationStatuses: mitigation })}`,
      );
      renderRows(page.data);
      const total = page.pagination.totalItems;
      totalBadge.textContent = `${SOC.formatNumber(total)} menace(s)`;
      range.textContent = `${page.data.length} résultat(s) affiché(s) sur ${SOC.formatNumber(total)}`;
      SOC.markUpdated();
      return page;
    },
  });

  searchForm.addEventListener('submit', (event) => {
    event.preventDefault();
    query = searchInput.value.trim();
    verdict = verdictSelect.value;
    mitigation = mitigationSelect.value;
    pager.reset();
  });

  verdictSelect.addEventListener('change', () => {
    verdict = verdictSelect.value;
    pager.reset();
  });

  mitigationSelect.addEventListener('change', () => {
    mitigation = mitigationSelect.value;
    pager.reset();
  });

  resetButton.addEventListener('click', () => {
    searchInput.value = '';
    verdictSelect.value = '';
    mitigationSelect.value = '';
    query = '';
    verdict = '';
    mitigation = '';
    pager.reset();
  });

  SOC.onRefresh(() => pager.reset());

  // Ouverture directe d'une enquête depuis un lien (?investigate=<id>), ex. depuis les alertes corrélées.
  const urlParams = new URLSearchParams(window.location.search);
  const investigateId = urlParams.get('investigate');
  if (investigateId) {
    history.replaceState(null, '', '/threats');
    pager.load().then(() => openInvestigate(investigateId));
  } else {
    pager.load();
  }
})();

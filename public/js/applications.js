(function () {
  'use strict';

  SOC.initShell('applications');

  const PAGE_SIZE = 25;
  const urlParams = new URLSearchParams(window.location.search);

  let query = (urlParams.get('query') || '').trim();
  let agentId = (urlParams.get('agent') || urlParams.get('agentId') || '').trim();
  let agentLabel = (urlParams.get('agentName') || '').trim();
  let forceRefresh = false;

  const tbody = document.getElementById('applications-table-body');
  const totalBadge = document.querySelector('[data-apps-total]');
  const range = document.getElementById('applications-range');
  const searchForm = document.getElementById('applications-search');
  const searchInput = document.getElementById('applications-query');
  const resetButton = document.getElementById('applications-reset');
  const agentFilter = document.getElementById('applications-agent-filter');
  const agentLabelEl = agentFilter ? agentFilter.querySelector('[data-agent-filter-label]') : null;
  const agentClear = document.getElementById('applications-agent-clear');

  const COLSPAN = 8;

  if (query && searchInput) searchInput.value = query;

  function renderAgentFilter() {
    if (!agentFilter) return;
    if (!agentId) {
      agentFilter.classList.add('d-none');
      return;
    }
    if (agentLabelEl) agentLabelEl.textContent = agentLabel || agentId;
    agentFilter.classList.remove('d-none');
  }

  function loadingRow() {
    tbody.innerHTML = SOC.skeletonRows(COLSPAN, 6);
  }

  function renderRows(data) {
    if (!data.length) {
      const empty = agentId
        ? 'Aucune application installée sur cet endpoint.'
        : query
          ? 'Aucune application ne correspond à cette recherche.'
          : "L'inventaire d'applications est vide — lancez une synchronisation avec le bouton Actualiser.";
      tbody.innerHTML = `<tr><td colspan="${COLSPAN}">${SOC.emptyState(empty, 'ti-app-window')}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map((app) => {
        const endpoint = app.endpoint;
        const endpointCell = endpoint
          ? `<a href="/endpoints/${encodeURIComponent(endpoint.id)}" class="fw-semibold text-decoration-none">${SOC.escapeHtml(endpoint.name)}</a>
             <a href="#" class="fs-12 text-decoration-none ms-1" data-agent-filter="${SOC.escapeHtml(endpoint.id)}"
                data-agent-name="${SOC.escapeHtml(endpoint.name)}" title="Filtrer la liste par cet endpoint"><i class="ti ti-filter"></i></a>
             <div class="text-muted fs-12">${SOC.escapeHtml(endpoint.ip || '—')}${endpoint.site ? ` · ${SOC.escapeHtml(endpoint.site)}` : ''}</div>`
          : '<span class="text-muted">—</span>';
        const osCell = endpoint
          ? `${SOC.escapeHtml(endpoint.os || '—')}<div class="text-muted fs-12">${SOC.escapeHtml(endpoint.machineType || '')}</div>`
          : '—';

        return `<tr>
          <td class="fw-semibold">${SOC.escapeHtml(app.name)}</td>
          <td class="fs-13">${SOC.escapeHtml(app.version || '—')}</td>
          <td class="fs-13">${SOC.escapeHtml(app.publisher || '—')}</td>
          <td class="text-muted fs-13">${app.size === null || app.size === undefined ? '—' : `${SOC.formatNumber(Math.round(app.size / 1024))} Ko`}</td>
          <td>${endpointCell}</td>
          <td>${osCell}</td>
          <td>${endpoint ? SOC.agentStatusBadge(endpoint.status) : '<span class="text-muted">—</span>'}</td>
          <td class="text-muted fs-13">${SOC.formatDate(app.installedAt)}</td>
        </tr>`;
      })
      .join('');
  }

  function renderSyncInfo(page) {
    const lastSync = document.querySelector('[data-apps-last-sync]');
    const status = page.status || {};
    if (lastSync) {
      lastSync.textContent = `Inventaire synchronisé : ${status.lastSyncAt ? SOC.formatDate(status.lastSyncAt) : 'jamais'}`;
    }

    if (page.sync && (page.sync.queued || page.sync.running)) {
      SOC.showAlert(
        '#applications-sync',
        "Synchronisation de l'inventaire lancée en arrière-plan — rechargez la page dans une minute.",
        'info',
      );
    } else if (page.sync && page.sync.skipped) {
      SOC.showAlert(
        '#applications-sync',
        "Synchronisation déjà en cours ou récente — patientez avant de la relancer.",
        'warning',
      );
    }
  }

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('applications-prev'),
    next: document.getElementById('applications-next'),
    label: document.getElementById('applications-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="${COLSPAN}">${SOC.emptyState('Données indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#applications-error', error.message || 'Impossible de charger les applications.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#applications-error');
      SOC.clearAlert('#applications-sync');
      loadingRow();
      const page = await SOC.api(
        `/api/applications?${SOC.params({
          limit: PAGE_SIZE,
          cursor,
          query,
          agentId,
          refresh: forceRefresh ? 1 : undefined,
        })}`,
      );
      forceRefresh = false;
      renderRows(page.data || []);
      const total = (page.pagination && page.pagination.totalItems) || 0;
      if (totalBadge) totalBadge.textContent = `${SOC.formatNumber(total)} application(s)`;
      if (range) range.textContent = `${(page.data || []).length} résultat(s) affiché(s) sur ${SOC.formatNumber(total)}`;
      renderSyncInfo(page);
      SOC.markUpdated();
      return page;
    },
  });

  searchForm.addEventListener('submit', (event) => {
    event.preventDefault();
    query = searchInput.value.trim();
    pager.reset();
  });

  resetButton.addEventListener('click', () => {
    searchInput.value = '';
    query = '';
    agentId = '';
    agentLabel = '';
    renderAgentFilter();
    pager.reset();
  });

  tbody.addEventListener('click', (event) => {
    const link = event.target.closest('[data-agent-filter]');
    if (!link) return;
    event.preventDefault();
    agentId = link.getAttribute('data-agent-filter');
    agentLabel = link.getAttribute('data-agent-name') || '';
    renderAgentFilter();
    pager.reset();
  });

  if (agentClear) {
    agentClear.addEventListener('click', () => {
      agentId = '';
      agentLabel = '';
      renderAgentFilter();
      pager.reset();
    });
  }

  renderAgentFilter();
  SOC.onRefresh(async () => {
    forceRefresh = true;
    await pager.reset();
  });
  pager.load();
})();

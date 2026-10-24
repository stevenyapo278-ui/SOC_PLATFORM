(function () {
  'use strict';

  SOC.initShell('agents');

  const PAGE_SIZE = 25;
  let query = '';

  const tbody = document.getElementById('agents-table-body');
  const totalBadge = document.querySelector('[data-agents-total]');
  const range = document.getElementById('agents-range');
  const searchForm = document.getElementById('agents-search');
  const searchInput = document.getElementById('agents-query');
  const resetButton = document.getElementById('agents-reset');

  function loadingRow() {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement des endpoints…</td></tr>`;
  }

  function renderRows(data) {
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="6">${SOC.emptyState(
        query ? 'Aucun endpoint ne correspond à cette recherche.' : 'Aucun endpoint remonté par SentinelOne.',
        'ti-devices-off',
      )}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map(
        (agent) => `<tr class="soc-agent-row" data-agent-id="${SOC.escapeHtml(agent.id)}" data-agent-name="${SOC.escapeHtml(agent.name)}" data-agent-os="${SOC.escapeHtml(agent.os)}" data-agent-site="${SOC.escapeHtml(agent.site)}" data-agent-status="${SOC.escapeHtml(agent.status)}" data-agent-version="${SOC.escapeHtml(agent.version)}" data-agent-ip="${SOC.escapeHtml(agent.ip)}" data-agent-last-active="${SOC.escapeHtml(agent.lastActiveAt || '')}" style="cursor:pointer">
          <td>
            <span class="fw-semibold d-block">${SOC.escapeHtml(agent.name)}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(agent.ip)} · ${SOC.escapeHtml(agent.domain)}</span>
          </td>
          <td>${SOC.escapeHtml(agent.os)}<div class="text-muted fs-12">${SOC.escapeHtml(agent.machineType)}</div></td>
          <td class="fs-13">${SOC.escapeHtml(agent.version)}</td>
          <td class="fs-13">${SOC.escapeHtml(agent.site)}</td>
          <td>${SOC.agentStatusBadge(agent.status)}</td>
          <td class="text-muted fs-13">
            ${SOC.formatDate(agent.lastActiveAt)}
            <div class="fs-11">${agent.lastActiveAt ? SOC.formatRelative(agent.lastActiveAt) : ''}</div>
          </td>
        </tr>`,
      )
      .join('');
  }

  const modalEl = document.getElementById('agent-detail-modal');
  const modal = modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal
    ? new bootstrap.Modal(modalEl)
    : null;

  function loadingRow(colspan) {
    return `<tr><td colspan="${colspan}" class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</td></tr>`;
  }

  async function loadDetailTab(url, body, colspan, render) {
    body.innerHTML = loadingRow(colspan);
    try {
      const page = await SOC.api(url);
      render(page.data || []);
    } catch (error) {
      body.innerHTML = `<tr><td colspan="${colspan}">${SOC.emptyState(
        error.message || 'Données indisponibles.',
        'ti-alert-triangle',
      )}</td></tr>`;
    }
  }

  function renderProcesses(data) {
    const body = document.getElementById('agent-processes-body');
    if (!data.length) {
      body.innerHTML = `<tr><td colspan="6">${SOC.emptyState(
        'Aucun processus : l’API SentinelOne /agents/processes est obsolète et renvoie toujours une liste vide (onglet Applications pour les logiciels installés).',
        'ti-cpu',
      )}</td></tr>`;
      return;
    }
    body.innerHTML = data
      .map(
        (p) => `<tr>
          <td class="fs-13">${SOC.escapeHtml(p.pid) || '—'}</td>
          <td class="fw-semibold">${SOC.escapeHtml(p.name)}</td>
          <td class="text-muted fs-12 soc-truncate" title="${SOC.escapeHtml(p.path)}">${SOC.escapeHtml(p.path)}</td>
          <td>${SOC.formatNumber(p.cpuUsage)}</td>
          <td>${SOC.formatNumber(p.memoryUsage)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(p.startTime)}</td>
        </tr>`,
      )
      .join('');
  }

  function renderApplications(data) {
    const body = document.getElementById('agent-apps-body');
    if (!data.length) {
      body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(
        'Aucune application remontée par SentinelOne.',
        'ti-app-window',
      )}</td></tr>`;
      return;
    }
    body.innerHTML = data
      .map(
        (app) => `<tr>
          <td class="fw-semibold">${SOC.escapeHtml(app.name)}</td>
          <td class="fs-13">${SOC.escapeHtml(app.version)}</td>
          <td class="fs-13">${app.size === null ? '—' : `${SOC.formatNumber(Math.round(app.size / 1024))} Ko`}</td>
          <td>${SOC.escapeHtml(app.signed)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(app.installedAt)}</td>
        </tr>`,
      )
      .join('');
  }

  function openAgentDetail(row) {
    const id = row.getAttribute('data-agent-id');
    if (!id || !modal) return;

    document.getElementById('agent-detail-title').textContent = row.getAttribute('data-agent-name') || 'Endpoint';
    document.getElementById('agent-detail-subtitle').textContent = `${row.getAttribute('data-agent-os') || '—'} · ${row.getAttribute('data-agent-site') || '—'} · ${row.getAttribute('data-agent-ip') || '—'}`;
    document.getElementById('agent-detail-badges').innerHTML = [
      SOC.agentStatusBadge(row.getAttribute('data-agent-status') || 'offline'),
      `<span class="badge bg-primary-subtle text-primary">${SOC.escapeHtml(row.getAttribute('data-agent-version') || '—')}</span>`,
      `<span class="text-muted fs-13 align-self-center">Dernière activité : ${SOC.formatDate(row.getAttribute('data-agent-last-active') || null)}</span>`,
    ].join(' ');
    SOC.clearAlert('#agent-detail-error');

    modal.show();

    loadDetailTab(`/api/agents/${encodeURIComponent(id)}/processes?limit=50`, document.getElementById('agent-processes-body'), 6, renderProcesses);
    loadDetailTab(`/api/agents/${encodeURIComponent(id)}/applications?limit=50`, document.getElementById('agent-apps-body'), 5, renderApplications);
  }

  tbody.addEventListener('click', (event) => {
    const row = event.target.closest('tr.soc-agent-row');
    if (row) openAgentDetail(row);
  });

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('agents-prev'),
    next: document.getElementById('agents-next'),
    label: document.getElementById('agents-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="6">${SOC.emptyState('Données indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#agents-error', error.message || 'Impossible de charger les endpoints.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#agents-error');
      loadingRow();
      const page = await SOC.api(
        `/api/agents?${SOC.params({ limit: PAGE_SIZE, cursor, query })}`,
      );
      renderRows(page.data);
      const total = page.pagination.totalItems;
      totalBadge.textContent = `${SOC.formatNumber(total)} endpoint(s)`;
      range.textContent = `${page.data.length} résultat(s) affiché(s) sur ${SOC.formatNumber(total)}`;
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
    pager.reset();
  });

  SOC.onRefresh(() => pager.reset());
  pager.load();
})();

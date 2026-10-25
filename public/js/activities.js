(function () {
  'use strict';

  SOC.initShell('activities');

  const PAGE_SIZE = 25;

  const tbody = document.getElementById('activities-table-body');
  const totalBadge = document.querySelector('[data-activities-total]');
  const range = document.getElementById('activities-range');

  function loadingRow() {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement du journal…</td></tr>`;
  }

  function renderRows(data) {
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="5">${SOC.emptyState('Aucune activité remontée.', 'ti-history')}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map(
        (activity) => `<tr>
          <td class="soc-activity-description">
            <span class="d-block text-truncate" title="${SOC.escapeHtml(activity.description)}">${SOC.escapeHtml(activity.description)}</span>
            ${activity.details ? `<span class="text-muted fs-12 d-block text-truncate" title="${SOC.escapeHtml(activity.details)}">${SOC.escapeHtml(activity.details)}</span>` : ''}
          </td>
          <td class="fs-13">${
            activity.agentId
              ? `<a href="/endpoints/${encodeURIComponent(activity.agentId)}" class="text-decoration-none">${SOC.escapeHtml(
                  activity.agentName || '—',
                )}</a>`
              : SOC.escapeHtml(activity.agentName || '—')
          }</td>
          <td class="fs-13">${SOC.escapeHtml(activity.user || '—')}</td>
          <td class="text-muted fs-13">${SOC.escapeHtml(activity.site)}</td>
          <td class="text-muted fs-13">
            ${SOC.formatDate(activity.createdAt)}
            <div class="fs-11">${activity.createdAt ? SOC.formatRelative(activity.createdAt) : ''}</div>
          </td>
        </tr>`,
      )
      .join('');
  }

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('activities-prev'),
    next: document.getElementById('activities-next'),
    label: document.getElementById('activities-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="5">${SOC.emptyState('Données indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#activities-error', error.message || 'Impossible de charger le journal d’activités.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#activities-error');
      loadingRow();
      const page = await SOC.api(`/api/activities?${SOC.params({ limit: PAGE_SIZE, cursor })}`);
      renderRows(page.data);
      const total = page.pagination.totalItems;
      totalBadge.textContent = `${SOC.formatNumber(total)} activité(s)`;
      range.textContent = `${page.data.length} résultat(s) affiché(s) sur ${SOC.formatNumber(total)}`;
      SOC.markUpdated();
      return page;
    },
  });

  SOC.onRefresh(() => pager.reset());
  pager.load();
})();

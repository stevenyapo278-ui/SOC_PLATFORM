(function () {
  'use strict';

  SOC.initShell('alerts');

  const PAGE_SIZE = 25;
  let severity = '';
  let verdict = '';
  let period = '';

  const tbody = document.getElementById('alerts-table-body');
  const totalBadge = document.querySelector('[data-alerts-total]');
  const range = document.getElementById('alerts-range');
  const severitySelect = document.getElementById('alerts-severity');
  const verdictSelect = document.getElementById('alerts-verdict');
  const periodSelect = document.getElementById('alerts-period');
  const resetButton = document.getElementById('alerts-reset');

  const modalEl = document.getElementById('alert-detail-modal');
  const modal = modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal
    ? new bootstrap.Modal(modalEl)
    : null;

  function loadingRow() {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement des alertes…</td></tr>`;
  }

  function statusBadge(status) {
    const key = String(status || '').toLowerCase();
    const label = SOC.humanize(status, SOC.ALERT_STATUS_LABELS);
    const cls =
      key === 'open' || key === 'unresolved'
        ? 'bg-danger-subtle text-danger'
        : key === 'in_progress'
          ? 'bg-warning-subtle text-warning'
          : key === 'resolved' || key === 'closed'
            ? 'bg-success-subtle text-success'
            : 'bg-secondary-subtle text-secondary';
    return `<span class="badge ${cls}">${SOC.escapeHtml(label)}</span>`;
  }

  function renderRows(data) {
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState(
        'Aucune alerte ne correspond aux filtres appliqués.',
        'ti-bell-off',
      )}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map(
        (alert) => `<tr class="soc-alert-row"
          data-alert-id="${SOC.escapeHtml(alert.id)}"
          data-alert-name="${SOC.escapeHtml(alert.name)}"
          data-alert-severity="${SOC.escapeHtml(alert.severity)}"
          data-alert-verdict="${SOC.escapeHtml(alert.analystVerdict)}"
          data-alert-status="${SOC.escapeHtml(alert.status)}"
          data-alert-created="${SOC.escapeHtml(alert.createdAt || '')}"
          data-alert-agent="${SOC.escapeHtml(alert.agentName)}"
          data-alert-agent-uuid="${SOC.escapeHtml(alert.agentUuid || '')}"
          data-alert-agent-os="${SOC.escapeHtml(alert.agentOs)}"
          data-alert-site="${SOC.escapeHtml(alert.site)}"
          data-alert-event="${SOC.escapeHtml(alert.eventType)}"
          data-alert-indicator-cat="${SOC.escapeHtml(alert.indicatorCategory)}"
          data-alert-indicator-name="${SOC.escapeHtml(alert.indicatorName)}"
          data-alert-indicator-desc="${SOC.escapeHtml(alert.indicatorDescription)}"
          data-alert-rule-desc="${SOC.escapeHtml(alert.ruleDescription)}"
          data-alert-process="${SOC.escapeHtml(alert.processName)}"
          data-alert-process-path="${SOC.escapeHtml(alert.processPath)}"
          data-alert-process-cmd="${SOC.escapeHtml(alert.processCommandLine)}"
          data-alert-process-user="${SOC.escapeHtml(alert.processUser)}"
          data-alert-sha256="${SOC.escapeHtml(alert.sha256 || '')}"
          data-alert-storyline="${SOC.escapeHtml(alert.storyline || '')}"
          data-alert-dst-ip="${SOC.escapeHtml(alert.dstIp)}"
          data-alert-dst-port="${SOC.escapeHtml(alert.dstPort)}"
          data-alert-dns="${SOC.escapeHtml(alert.dnsRequest)}"
          data-alert-registry="${SOC.escapeHtml(alert.registryKeyPath)}"
          data-alert-login="${SOC.escapeHtml(alert.loginUserName)}"
          style="cursor:pointer">
          <td>
            <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(alert.name)}">${SOC.escapeHtml(alert.name)}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(alert.eventType)}</span>
          </td>
          <td>${SOC.severityBadge(alert.severity)}</td>
          <td class="fs-13">${SOC.escapeHtml(alert.agentName)}<div class="text-muted fs-12">${SOC.escapeHtml(alert.agentOs)}</div></td>
          <td class="fs-13 soc-truncate" title="${SOC.escapeHtml(alert.processPath)}">${SOC.escapeHtml(alert.processName)}</td>
          <td>${statusBadge(alert.status)}</td>
          <td class="fs-13">${SOC.escapeHtml(SOC.humanize(alert.analystVerdict))}</td>
          <td class="text-muted fs-13">
            ${SOC.formatDate(alert.createdAt)}
            <div class="fs-11">${alert.createdAt ? SOC.formatRelative(alert.createdAt) : ''}</div>
          </td>
        </tr>`,
      )
      .join('');
  }

  function kv(label, value, cls = '') {
    return `<div class="soc-inv-kv"><dt>${SOC.escapeHtml(label)}</dt><dd class="${cls}">${value}</dd></div>`;
  }

  function renderAlertDetail(row) {
    const get = (name) => row.getAttribute(`data-alert-${name}`) || '';
    const body = document.getElementById('alert-detail-body');

    const network = [
      get('dst-ip') && kv('IP destination', SOC.escapeHtml(get('dst-ip'))),
      get('dst-port') && kv('Port destination', SOC.escapeHtml(get('dst-port'))),
      get('dns') && kv('Requête DNS', SOC.escapeHtml(get('dns')), 'soc-inv-hash'),
      get('registry') && kv('Clé registre', SOC.escapeHtml(get('registry')), 'soc-inv-hash'),
      get('login') && kv('Compte de connexion', SOC.escapeHtml(get('login'))),
    ].filter(Boolean);

    body.innerHTML = `
      <div class="soc-inv-grid mb-3">
        ${kv('Type d’événement', SOC.escapeHtml(get('event')))}
        ${kv('Indicateur', SOC.escapeHtml(get('indicator-cat')))}
        ${kv('Nom indicateur', SOC.escapeHtml(get('indicator-name')) || '—')}
        ${kv('Description', SOC.escapeHtml(get('indicator-desc')) || '—')}
        ${kv('Règle', SOC.escapeHtml(get('name')))}
        ${kv('Description règle', SOC.escapeHtml(get('rule-desc')) || '—')}
      </div>
      <div class="soc-inv-grid mb-3">
        ${kv('Endpoint', SOC.escapeHtml(get('agent')))}
        ${kv('OS', SOC.escapeHtml(get('agent-os')))}
        ${kv('Site', SOC.escapeHtml(get('site')) || '—')}
        ${kv('UUID agent', SOC.escapeHtml(get('agent-uuid')) || '—', 'soc-inv-hash')}
        ${kv('Détectée le', SOC.formatDate(get('created')))}
        ${kv('Verdict', SOC.escapeHtml(SOC.humanize(get('verdict'))))}
      </div>
      <div class="soc-inv-grid mb-3">
        ${kv('Processus', SOC.escapeHtml(get('process')))}
        ${kv('Chemin', SOC.escapeHtml(get('process-path')))}
        ${kv('Ligne de commande', SOC.escapeHtml(get('process-cmd')) || '—')}
        ${kv('Utilisateur', SOC.escapeHtml(get('process-user')))}
        ${kv('SHA256', SOC.escapeHtml(get('sha256')) || '—', 'soc-inv-hash')}
        ${kv('Storyline', SOC.escapeHtml(get('storyline')) || '—', 'soc-inv-hash')}
      </div>
      ${network.length ? `<p class="text-muted fs-12 text-uppercase fw-semibold mb-1">Réseau / systèmes</p><div class="soc-inv-grid">${network.join('')}</div>` : ''}
    `;
  }

  function renderRelatedThreats(data) {
    const body = document.getElementById('alert-threats-body');
    if (!data.length) {
      body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(
        'Aucune menace SentinelOne corrélée (même storyline/hash).',
        'ti-shield-check',
      )}</td></tr>`;
      return;
    }
    body.innerHTML = data
      .map(
        (threat) => `<tr class="soc-alert-related-threat" data-threat-id="${SOC.escapeHtml(threat.id)}" style="cursor:pointer">
          <td><span class="fw-semibold soc-truncate" title="${SOC.escapeHtml(threat.name)}">${SOC.escapeHtml(threat.name)}</span></td>
          <td>${SOC.severityBadge(threat.severity)}</td>
          <td class="fs-13">${SOC.escapeHtml(threat.agentName)}</td>
          <td>${SOC.mitigationBadge(threat.mitigationStatus)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(threat.createdAt)}</td>
        </tr>`,
      )
      .join('');
  }

  async function loadRelatedThreats(row) {
    const body = document.getElementById('alert-threats-body');
    const storyline = row.getAttribute('data-alert-storyline');
    const sha256 = row.getAttribute('data-alert-sha256');
    const correlation = document.getElementById('alert-detail-correlation');

    body.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement…</td></tr>';

    if (storyline) {
      correlation.innerHTML = `<i class="ti ti-link me-1"></i>Corrélation par Storyline : <code>${SOC.escapeHtml(storyline)}</code>`;
      try {
        const page = await SOC.api(`/api/threats?${SOC.params({ storylines: storyline, limit: 25 })}`);
        renderRelatedThreats(page.data);
        return;
      } catch (error) {
        body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(error.message || 'Corrélation indisponible.', 'ti-alert-triangle')}</td></tr>`;
        return;
      }
    }

    if (sha256) {
      correlation.innerHTML = `<i class="ti ti-hash me-1"></i>Corrélation par SHA256 : <code>${SOC.escapeHtml(sha256)}</code>`;
      try {
        const page = await SOC.api(`/api/threats?${SOC.params({ query: sha256, limit: 25 })}`);
        renderRelatedThreats(page.data);
        return;
      } catch (error) {
        body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(error.message || 'Corrélation indisponible.', 'ti-alert-triangle')}</td></tr>`;
        return;
      }
    }

    correlation.textContent = 'Aucune clé de corrélation (storyline/hash) sur cette alerte.';
    body.innerHTML = `<tr><td colspan="5">${SOC.emptyState(
      'Cette alerte ne porte ni storyline ni hash exploitable.',
      'ti-link-off',
    )}</td></tr>`;
  }

  function openAlertDetail(row) {
    if (!modal || !row) return;

    document.getElementById('alert-detail-title').textContent = row.getAttribute('data-alert-name') || 'Alerte';
    document.getElementById('alert-detail-subtitle').textContent =
      `${row.getAttribute('data-alert-agent') || '—'} · ${SOC.formatDate(row.getAttribute('data-alert-created') || null)}`;
    document.getElementById('alert-detail-badges').innerHTML = [
      SOC.severityBadge(row.getAttribute('data-alert-severity')),
      statusBadge(row.getAttribute('data-alert-status')),
      `<span class="badge bg-primary-subtle text-primary">${SOC.escapeHtml(SOC.humanize(row.getAttribute('data-alert-verdict')))}</span>`,
    ].join(' ');
    SOC.clearAlert('#alert-detail-error');
    document.getElementById('alert-detail-correlation').textContent = '—';

    renderAlertDetail(row);
    modal.show();
    loadRelatedThreats(row);
  }

  tbody.addEventListener('click', (event) => {
    const row = event.target.closest('tr.soc-alert-row');
    if (row) openAlertDetail(row);
  });

  // Clique sur une menace corrélée → ouvre la page Menaces et l’enquête.
  const relatedBody = document.getElementById('alert-threats-body');
  if (relatedBody) {
    relatedBody.addEventListener('click', (event) => {
      const row = event.target.closest('tr.soc-alert-related-threat');
      if (!row) return;
      const threatId = row.getAttribute('data-threat-id');
      window.location.href = `/threats?investigate=${encodeURIComponent(threatId)}`;
    });
  }

  function readPeriodGte() {
    if (!period) return undefined;
    const hours = Number.parseInt(period, 10);
    if (!Number.isFinite(hours)) return undefined;
    return new Date(Date.now() - hours * 3600 * 1000).toISOString();
  }

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('alerts-prev'),
    next: document.getElementById('alerts-next'),
    label: document.getElementById('alerts-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState('Données indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#alerts-error', error.message || 'Impossible de charger les alertes.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#alerts-error');
      loadingRow();
      const page = await SOC.api(`/api/alerts?${SOC.params({
        limit: PAGE_SIZE,
        cursor,
        severity,
        analystVerdict: verdict,
        reportedAtGte: readPeriodGte(),
      })}`);
      renderRows(page.data);
      const total = page.pagination.totalItems;
      totalBadge.textContent = `${SOC.formatNumber(total)} alerte(s)`;
      range.textContent = `${page.data.length} résultat(s) affiché(s) sur ${SOC.formatNumber(total)}`;
      SOC.markUpdated();
      return page;
    },
  });

  severitySelect.addEventListener('change', () => {
    severity = severitySelect.value;
    pager.reset();
  });

  verdictSelect.addEventListener('change', () => {
    verdict = verdictSelect.value;
    pager.reset();
  });

  periodSelect.addEventListener('change', () => {
    period = periodSelect.value;
    pager.reset();
  });

  resetButton.addEventListener('click', () => {
    severitySelect.value = '';
    verdictSelect.value = '';
    periodSelect.value = '';
    severity = '';
    verdict = '';
    period = '';
    pager.reset();
  });

  // Ouverture directe depuis un lien externe (?investigate= géré côté menaces, ici on gère ?alert=).
  const urlParams = new URLSearchParams(window.location.search);
  const openAlertId = urlParams.get('alert');
  if (openAlertId) {
    // L'alerte ciblée est ouverte après le premier rendu de la page.
    pager.load().then(() => {
      const row = tbody.querySelector(`tr[data-alert-id="${CSS.escape(openAlertId)}"]`);
      if (row) openAlertDetail(row);
    });
  } else {
    pager.load();
  }
})();

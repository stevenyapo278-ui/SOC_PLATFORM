(function () {
  'use strict';

  SOC.initShell('agents');

  const PAGE_SIZE = 20;
  const AGENT_ID = decodeURIComponent(window.location.pathname.split('/').filter(Boolean).pop() || '');

  const nameEl = document.querySelector('[data-ep-name]');
  const subtitleEl = document.querySelector('[data-ep-subtitle]');
  const badgesEl = document.querySelector('[data-ep-badges]');
  const seenEl = document.querySelector('[data-ep-seen]');
  const identityEl = document.querySelector('[data-ep-identity]');
  const tagsEl = document.querySelector('[data-ep-tags]');
  const siblingsEl = document.querySelector('[data-ep-siblings]');
  const rangeEl = document.querySelector('[data-ep-range]');

  const EVENT_LABELS = {
    registered: 'Agent enregistré',
    renamed: 'Machine renommée',
    serial_changed: 'Numéro de série modifié',
    mac_changed: 'Adresses MAC modifiées',
    ip_changed: 'Adresses IP modifiées',
    site_changed: 'Site modifié',
    os_changed: 'Système d’exploitation modifié',
    version_changed: 'Version de l’agent modifiée',
    decommissioned: 'Agent décommissionné',
    uninstalled: 'Agent désinstallé',
    infected: 'Machine infectée',
    cured: 'Machine nettoyée',
    duplicate_detected: 'Doublon détecté',
  };

  function fail(message) {
    SOC.showAlert('#endpoint-error', message);
  }

  function clearFail() {
    SOC.clearAlert('#endpoint-error');
  }

  function field(label, value, mono = false) {
    const empty = value === undefined || value === null || value === '' || value === '—';
    return `<div class="col-6 col-xl-4">
      <span class="text-muted fs-12">${SOC.escapeHtml(label)}</span>
      <div class="${mono ? 'font-monospace ' : ''}text-break fs-13">${empty ? '<span class="text-muted">—</span>' : SOC.escapeHtml(String(value))}</div>
    </div>`;
  }

  function renderIdentity(payload) {
    const agent = payload.agent;
    const machine = payload.machine || {};

    nameEl.textContent = agent.name;
    document.title = `${agent.name} | SOC Sentinel`;
    subtitleEl.textContent = [agent.os, agent.site, agent.ip].filter((v) => v && v !== '—').join(' · ') || '—';

    badgesEl.innerHTML = [
      SOC.agentStatusBadge(agent.status),
      agent.infected ? '<span class="badge bg-danger-subtle text-danger">Infectée</span>' : '',
      machine.duplicate ? '<span class="badge bg-warning-subtle text-warning">Doublon d’agents</span>' : '',
      '<span class="badge bg-secondary-subtle text-secondary">Lecture seule</span>',
    ]
      .filter(Boolean)
      .join(' ');

    seenEl.textContent = `Vue du ${agent.firstSeenAt ? SOC.formatDate(agent.firstSeenAt, false) : '—'} · dernière activité ${
      agent.lastActiveAt ? SOC.formatDate(agent.lastActiveAt) : '—'
    }`;

    const macs = Array.isArray(agent.macAddresses) ? agent.macAddresses : [];
    const ips = Array.isArray(agent.ipAddresses) ? agent.ipAddresses : [];
    identityEl.innerHTML = [
      ['Nom', agent.name],
      ['Adresse IP', agent.ip],
      ['Domaine', agent.domain],
      ['Site', agent.site],
      ['Compte', agent.account],
      ['Système', agent.os],
      ['Version agent', agent.version],
      ['Type', agent.machineType],
      ['Numéro de série', agent.serialNumber],
      ['Modèle', agent.model],
      ['MAC', macs.join(', ')],
      ['Adresses IP', ips.join(', ')],
      ['UUID machine', agent.machineUuid],
      ['SID machine', agent.machineSid],
      ['Clé machine', machine.machineKey],
      ['Source de la clé', machine.machineKeySource],
      ['Première vue', agent.firstSeenAt ? SOC.formatDate(agent.firstSeenAt) : ''],
      ['Dernière synchro', agent.lastSeenAt ? SOC.formatDate(agent.lastSeenAt) : ''],
    ]
      .map(([label, value], index) => field(label, value, [8, 10, 11, 12, 13, 14, 15].includes(index)))
      .join('');

    const tags = Array.isArray(machine.tags) ? machine.tags : [];
    tagsEl.innerHTML = tags.length
      ? tags
          .map(
            (tag) =>
              `<span class="badge bg-primary-subtle text-primary">${SOC.escapeHtml(tag.tag)} <span class="text-muted">· ${SOC.escapeHtml(
                tag.createdBy || '—',
              )}</span></span>`,
          )
          .join('')
      : '<span class="text-muted fs-13">Aucun tag sur cette machine.</span>';

    const siblings = Array.isArray(machine.agents) ? machine.agents : [];
    siblingsEl.innerHTML = siblings.length
      ? `<p class="text-warning fs-12 mb-2"><i class="ti ti-alert-triangle me-1"></i>${
          siblings.length
        } autre(s) agent(s) installé(s) sur cette machine physique (réinstallation non décommissionnée).</p>
        <ul class="list-unstyled mb-0">${siblings
          .map(
            (sibling) => `<li class="d-flex justify-content-between align-items-center gap-2 py-1 border-bottom border-dashed">
              <a href="/endpoints/${encodeURIComponent(sibling.id)}" class="text-decoration-none fw-semibold">${SOC.escapeHtml(sibling.name)}</a>
              <span class="text-nowrap">${SOC.agentStatusBadge(sibling.status)}</span>
            </li>`,
          )
          .join('')}</ul>`
      : '<span class="text-muted fs-13">Aucun autre agent — machine unique.</span>';

    const countEl = document.querySelector('[data-ep-count="history"]');
    if (countEl) countEl.textContent = SOC.formatNumber(payload.historyTotal || 0);
    SOC.markUpdated();
  }

  async function loadIdentity() {
    clearFail();
    try {
      const payload = await SOC.api(`/api/agents/${encodeURIComponent(AGENT_ID)}`);
      renderIdentity(payload);
    } catch (error) {
      identityEl.innerHTML = '<div class="col-12 text-muted py-3 text-center">Identité indisponible.</div>';
      fail(error.message || 'Impossible de charger la fiche de cet endpoint.');
    }
  }

  const emptyRow = (colspan, message, icon = 'ti-inbox') =>
    `<tr><td colspan="${colspan}">${SOC.emptyState(message, icon)}</td></tr>`;

  const TABS = {
    applications: {
      empty: 5,
      icon: 'ti-app-window',
      messages: ['Aucune application installée sur cet endpoint.', "Aucune application ne correspond à cette page."],
      url: (cursor) =>
        `/api/applications?${SOC.params({ limit: PAGE_SIZE, cursor, agentId: AGENT_ID })}`,
      render: (data) =>
        data
          .map(
            (app) => `<tr>
              <td class="fw-semibold">${SOC.escapeHtml(app.name)}</td>
              <td class="fs-13">${SOC.escapeHtml(app.version || '—')}</td>
              <td class="fs-13">${SOC.escapeHtml(app.publisher || '—')}</td>
              <td class="text-muted fs-13">${
                app.size === null || app.size === undefined ? '—' : `${SOC.formatNumber(Math.round(app.size / 1024))} Ko`
              }</td>
              <td class="text-muted fs-13">${SOC.formatDate(app.installedAt)}</td>
            </tr>`,
          )
          .join(''),
    },
    threats: {
      empty: 4,
      icon: 'ti-shield-exclamation',
      messages: ['Aucune menace détectée sur cet endpoint.', 'Aucune menace sur cette page.'],
      url: (cursor) => `/api/threats?${SOC.params({ limit: PAGE_SIZE, cursor, agentIds: AGENT_ID })}`,
      render: (data) =>
        data
          .map(
            (threat) => `<tr class="soc-threat-row" data-goto="/threats?investigate=${encodeURIComponent(threat.id)}" style="cursor:pointer">
              <td>
                <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(threat.name)}">${SOC.escapeHtml(threat.name)}</span>
                <span class="text-muted fs-12">${SOC.escapeHtml(threat.classification)}</span>
              </td>
              <td>${SOC.severityBadge(threat.severity)}</td>
              <td class="fs-13">${SOC.mitigationBadge(threat.mitigationStatus)}
                <div class="text-muted fs-12">${SOC.escapeHtml(SOC.humanize(threat.incidentStatus, SOC.INCIDENT_LABELS))}</div></td>
              <td class="text-muted fs-13">${SOC.formatDate(threat.createdAt)}
                <div class="fs-11">${threat.createdAt ? SOC.formatRelative(threat.createdAt) : ''}</div></td>
            </tr>`,
          )
          .join(''),
    },
    alerts: {
      empty: 5,
      icon: 'ti-bell',
      messages: ['Aucune alerte sur cet endpoint.', 'Aucune alerte sur cette page.'],
      url: (cursor) => `/api/alerts?${SOC.params({ limit: PAGE_SIZE, cursor, agentIds: AGENT_ID })}`,
      render: (data) =>
        data
          .map(
            (alert) => `<tr class="soc-alert-row" data-goto="/alerts?alert=${encodeURIComponent(alert.id)}" style="cursor:pointer">
              <td>
                <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(alert.name)}">${SOC.escapeHtml(alert.name)}</span>
                <span class="text-muted fs-12">${SOC.escapeHtml(alert.eventType)}</span>
              </td>
              <td>${SOC.severityBadge(alert.severity)}</td>
              <td class="fs-13 soc-truncate" title="${SOC.escapeHtml(alert.processPath || '')}">${SOC.escapeHtml(alert.processName || '—')}</td>
              <td class="fs-13"><span class="badge bg-secondary-subtle text-secondary">${SOC.escapeHtml(
                SOC.humanize(alert.status, SOC.ALERT_STATUS_LABELS),
              )}</span></td>
              <td class="text-muted fs-13">${SOC.formatDate(alert.createdAt)}
                <div class="fs-11">${alert.createdAt ? SOC.formatRelative(alert.createdAt) : ''}</div></td>
            </tr>`,
          )
          .join(''),
    },
    activities: {
      empty: 4,
      icon: 'ti-history',
      messages: ['Aucune activité enregistrée pour cet endpoint.', 'Aucune activité sur cette page.'],
      url: (cursor) => `/api/activities?${SOC.params({ limit: PAGE_SIZE, cursor, agentIds: AGENT_ID })}`,
      render: (data) =>
        data
          .map(
            (activity) => `<tr>
              <td class="soc-activity-description">
                <span class="d-block text-truncate" title="${SOC.escapeHtml(activity.description)}">${SOC.escapeHtml(activity.description)}</span>
                ${activity.details ? `<span class="text-muted fs-12 d-block text-truncate" title="${SOC.escapeHtml(activity.details)}">${SOC.escapeHtml(activity.details)}</span>` : ''}
              </td>
              <td class="fs-13">${SOC.escapeHtml(activity.user || '—')}</td>
              <td class="text-muted fs-13">${SOC.escapeHtml(activity.site)}</td>
              <td class="text-muted fs-13">${SOC.formatDate(activity.createdAt)}
                <div class="fs-11">${activity.createdAt ? SOC.formatRelative(activity.createdAt) : ''}</div></td>
            </tr>`,
          )
          .join(''),
    },
    history: {
      list: true,
      icon: 'ti-timeline',
      messages: ['Aucun changement d’identité ou de cycle de vie enregistré pour cet endpoint.', 'Aucun événement sur cette page.'],
      url: (cursor) => `/api/agents/${encodeURIComponent(AGENT_ID)}/history?${SOC.params({ limit: PAGE_SIZE, cursor })}`,
      render: (data) =>
        data
          .map(
            (event) => `<div class="soc-list-item">
              <div class="d-flex justify-content-between gap-3">
                <div class="min-width-0">
                  <span class="fw-semibold d-block">${SOC.escapeHtml(EVENT_LABELS[event.event] || event.event)}</span>
                  ${
                    event.oldValue || event.newValue
                      ? `<span class="text-muted fs-12 font-monospace text-break">${SOC.escapeHtml(event.oldValue || '—')} → ${SOC.escapeHtml(
                          event.newValue || '—',
                        )}</span>`
                      : ''
                  }
                </div>
                <span class="text-muted fs-12 text-nowrap">${SOC.formatDate(event.detectedAt)}</span>
              </div>
            </div>`,
          )
          .join(''),
    },
  };

  let activeKey = 'applications';

  function tabBody(key) {
    return document.getElementById(`ep-${key}-body`);
  }

  function renderTab(key, data) {
    const spec = TABS[key];
    const body = tabBody(key);
    if (!body) return;
    if (!data.length) {
      body.innerHTML = spec.list
        ? SOC.emptyState(spec.messages[0], spec.icon)
        : emptyRow(spec.empty, spec.messages[0], spec.icon);
      return;
    }
    body.innerHTML = spec.render(data);
  }

  const loadedTabs = new Set();
  const totals = {};

  function paintRange(key) {
    if (!rangeEl) return;
    const total = totals[key] || 0;
    rangeEl.textContent = `${SOC.formatNumber(total)} élément(s) — onglet ${key}`;
  }

  async function loadTab(key, cursor) {
    const spec = TABS[key];
    clearFail();
    const page = await SOC.api(spec.url(cursor));
    const data = Array.isArray(page.data) ? page.data : [];
    renderTab(key, data);
    const total = (page.pagination && page.pagination.totalItems) || 0;
    totals[key] = total;
    const countEl = document.querySelector(`[data-ep-count="${key}"]`);
    if (countEl) countEl.textContent = SOC.formatNumber(total);
    if (cursor === null) paintRange(key);
    loadedTabs.add(key);
    SOC.markUpdated();
    return page;
  }

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.querySelector('[data-ep-prev]'),
    next: document.querySelector('[data-ep-next]'),
    label: document.querySelector('[data-ep-page-label]'),
    onError: (error) => fail(error.message || 'Impossible de charger cette vue.'),
    onPage: (cursor) => loadTab(activeKey, cursor),
  });

  document.querySelectorAll('[data-endpoint-tab]').forEach((button) => {
    button.addEventListener('shown.bs.tab', () => {
      activeKey = button.getAttribute('data-endpoint-tab');
      if (loadedTabs.has(activeKey)) {
        paintRange(activeKey);
        return;
      }
      pager.reset();
    });
  });

  document.addEventListener('click', (event) => {
    const target = event.target.closest('tr[data-goto]');
    if (!target) return;
    window.location.href = target.getAttribute('data-goto');
  });

  loadIdentity();
  pager.load().catch(() => {});

  SOC.onRefresh(async () => {
    loadedTabs.clear();
    await loadIdentity();
    await pager.reset();
  });
})();

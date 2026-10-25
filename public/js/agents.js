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
  const filterSelect = document.getElementById('agents-filter');
  const viewMachinesButton = document.getElementById('agents-view-machines');
  const viewAgentsButton = document.getElementById('agents-view-agents');

  let view = localStorage.getItem('soc-agents-view') === 'agents' ? 'agents' : 'machines';
  let filter = '';

  function paintViewButtons() {
    const on = (button, active) => {
      button.classList.toggle('btn-primary', active);
      button.classList.toggle('btn-outline-primary', !active);
    };
    on(viewMachinesButton, view === 'machines');
    on(viewAgentsButton, view === 'agents');
  }

  function setKpi(key, value) {
    const el = document.querySelector(`[data-kpi="${key}"]`);
    if (el) el.textContent = SOC.formatNumber(value || 0);
  }

  function updateKpis(summary) {
    if (!summary) return;
    setKpi('machines', summary.machines);
    setKpi('agents', summary.agents);
    setKpi('duplicates', summary.duplicates);
    setKpi('name-collisions', summary.nameCollisions);
  }

  function loadingRow() {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement des endpoints…</td></tr>`;
  }

  // Identité machine conservée en mémoire pour remplir la modale de détail.
  const agentsById = new Map();

  function identityCell(agent) {
    const macs = Array.isArray(agent.macAddresses) ? agent.macAddresses : [];
    const serial = agent.serialNumber
      ? SOC.escapeHtml(agent.serialNumber)
      : '<span class="text-muted">Série absente</span>';
    const mac = macs.length
      ? `${SOC.escapeHtml(macs[0])}${macs.length > 1 ? ` <span class="text-muted">+${macs.length - 1}</span>` : ''}`
      : '<span class="text-muted">—</span>';
    const model = agent.model
      ? `<div class="text-muted fs-11 text-truncate" style="max-width:170px" title="${SOC.escapeHtml(agent.model)}">${SOC.escapeHtml(agent.model)}</div>`
      : '';
    return `<td class="fs-13">
            <span class="font-monospace">${serial}</span>
            <div class="text-muted fs-11 font-monospace">${mac}</div>
            ${model}
          </td>`;
  }

  function renderIdentity(agent) {
    const block = document.getElementById('agent-detail-identity');
    if (!block) return;
    if (!agent) {
      block.innerHTML = '<div class="col-12 text-muted fs-12">Identité machine indisponible.</div>';
      return;
    }
    const macs = Array.isArray(agent.macAddresses) ? agent.macAddresses : [];
    const ips = Array.isArray(agent.ipAddresses) ? agent.ipAddresses : [];
    const items = [
      ['Série', agent.serialNumber || '—'],
      ['Modèle', agent.model || '—'],
      ['MAC', macs.length ? macs.join(', ') : '—'],
      ['IP', ips.length ? ips.join(', ') : agent.ip || '—'],
      ['UUID', agent.machineUuid || '—'],
      ['SID', agent.machineSid || '—'],
    ];
    block.innerHTML = `<div class="col-12 text-muted fs-12">Identité machine</div>${items
      .map(
        ([label, value]) =>
          `<div class="col-6 col-lg-4"><span class="text-muted">${label}</span><div class="font-monospace text-break">${SOC.escapeHtml(value)}</div></div>`,
      )
      .join('')}`;
  }

  function renderRows(data) {
    data.forEach((agent) => agentsById.set(agent.id, agent));

    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState(
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
          ${identityCell(agent)}
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

  // Vue machines : une ligne par machine, les agents additionnels (doublon)
  // apparaissent en sous-lignes dépliables.
  function machineMembers(machine) {
    if (machine.agentCount < 2) return '';
    return machine.agents
      .slice(1)
      .map(
        (agent) => `<tr class="soc-agent-subrow d-none" data-machine="${SOC.escapeHtml(machine.machineKey)}">
          <td class="ps-4"><span class="text-muted">↳</span> ${SOC.escapeHtml(agent.name)}
            <span class="text-muted fs-11">${SOC.escapeHtml(agent.id)}</span></td>
          <td>${SOC.escapeHtml(agent.os)}</td>
          <td class="fs-13 font-monospace">${agent.serialNumber ? SOC.escapeHtml(agent.serialNumber) : '<span class="text-muted">—</span>'}</td>
          <td class="fs-13">${SOC.escapeHtml(agent.version)}</td>
          <td class="fs-13">${SOC.escapeHtml(agent.site)}</td>
          <td>${SOC.agentStatusBadge(agent.status)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(agent.lastActiveAt)}</td>
        </tr>`,
      )
      .join('');
  }

  function machineRow(machine) {
    const primary = machine.agents[0] || {};
    const badges = [];
    if (machine.duplicate) {
      badges.push(
        `<span class="badge bg-warning-subtle text-warning"><i class="ti ti-alert-triangle me-1"></i>${machine.agentCount} agents${
          machine.onlineCount > 1 ? ` · ${machine.onlineCount} en ligne` : ''
        }</span>`,
      );
    }
    if (machine.nameCollision) {
      badges.push('<span class="badge bg-danger-subtle text-danger"><i class="ti ti-alert-triangle me-1"></i>Nom partagé</span>');
    }
    if (machine.infected) {
      badges.push('<span class="badge bg-danger-subtle text-danger">Infecté</span>');
    }

    const expand = machine.agentCount > 1
      ? `<button type="button" class="btn btn-sm btn-link text-decoration-none p-0 me-1" data-machine-toggle="${SOC.escapeHtml(machine.machineKey)}"
            title="Afficher les ${machine.agentCount} agents de cette machine"><i class="ti ti-chevron-right"></i></button>`
      : '';
    const serial = machine.serialNumbers.length
      ? machine.serialNumbers.map(SOC.escapeHtml).join(', ')
      : '<span class="text-muted">Série absente</span>';
    const mac = machine.macAddresses.length
      ? `${SOC.escapeHtml(machine.macAddresses[0])}${machine.macAddresses.length > 1 ? ` <span class="text-muted">+${machine.macAddresses.length - 1}</span>` : ''}`
      : '<span class="text-muted">—</span>';
    const model = machine.model
      ? `<div class="text-muted fs-11 text-truncate" style="max-width:170px" title="${SOC.escapeHtml(machine.model)}">${SOC.escapeHtml(machine.model)}</div>`
      : '';

    const tagChips = (machine.tags || [])
      .map(
        (tag) =>
          `<span class="badge bg-secondary-subtle text-secondary me-1">${SOC.escapeHtml(tag)}</span>`,
      )
      .join('');
    const checked = selectedKeys.has(machine.machineKey) ? 'checked' : '';
    return `<tr class="soc-agent-row" data-agent-id="${SOC.escapeHtml(primary.id || '')}" data-agent-name="${SOC.escapeHtml(primary.name || machine.name)}" data-agent-os="${SOC.escapeHtml(primary.os || '—')}" data-agent-site="${SOC.escapeHtml(primary.site || machine.site)}" data-agent-status="${SOC.escapeHtml(primary.status || machine.status)}" data-agent-version="${SOC.escapeHtml(primary.version || '—')}" data-agent-ip="${SOC.escapeHtml(primary.ip || machine.ip)}" data-agent-last-active="${SOC.escapeHtml(primary.lastActiveAt || '')}" style="cursor:pointer">
      <td>
        <div class="d-flex align-items-start gap-1">
          <input type="checkbox" class="form-check-input mt-1" data-machine-check="${SOC.escapeHtml(machine.machineKey)}" ${checked}
            aria-label="Sélectionner ${SOC.escapeHtml(machine.name)}">
          <div class="flex-grow-1">
            <span class="fw-semibold d-block">${expand}${SOC.escapeHtml(machine.name)}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(machine.ip)} · ${SOC.escapeHtml(primary.domain || '—')}</span>
            ${badges.length || tagChips ? `<div class="mt-1">${badges.join(' ')}${tagChips}</div>` : ''}
          </div>
        </div>
      </td>
      <td>${SOC.escapeHtml(primary.os || '—')}<div class="text-muted fs-12">${SOC.escapeHtml(primary.machineType || primary.osType || '—')}</div></td>
      <td class="fs-13">
        <span class="font-monospace">${serial}</span>
        <div class="text-muted fs-11 font-monospace">${mac}</div>
        ${model}
      </td>
      <td class="fs-13">${SOC.escapeHtml(primary.version || '—')}</td>
      <td class="fs-13">${SOC.escapeHtml(machine.site)}</td>
      <td>${SOC.agentStatusBadge(machine.status)}</td>
      <td class="text-muted fs-13">
        ${SOC.formatDate(machine.lastActiveAt)}
        <div class="fs-11">${machine.lastActiveAt ? SOC.formatRelative(machine.lastActiveAt) : ''}</div>
      </td>
    </tr>`;
  }

  function renderMachines(page) {
    const data = page.data || [];
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState(
        query ? 'Aucune machine ne correspond à cette recherche.' : 'Aucune machine remontée par SentinelOne.',
        'ti-device-desktop-off',
      )}</td></tr>`;
      return;
    }
    tbody.innerHTML = data
      .map((machine) => {
        machine.agents.forEach((agent) => agentsById.set(agent.id, agent));
        return machineRow(machine) + machineMembers(machine);
      })
      .join('');
  }

  /* ──────────────── sélection de machines + tags SOC (locaux) ─────────────── */

  const selectedKeys = new Set();
  const actionsButton = document.getElementById('agents-actions');
  const actionsCount = document.querySelector('[data-actions-count]');
  const selectAll = document.getElementById('agents-select-all');
  const selectAllWrap = document.querySelector('[data-select-all-wrap]');
  const tagModalEl = document.getElementById('machine-tag-modal');
  const tagModal =
    tagModalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal
      ? new bootstrap.Modal(tagModalEl)
      : null;

  function syncSelectionUi() {
    if (!actionsButton) return;
    actionsCount.textContent = String(selectedKeys.size);
    actionsButton.disabled = selectedKeys.size === 0;
    selectAllWrap.classList.toggle('d-none', view !== 'machines');
    const visible = [...tbody.querySelectorAll('[data-machine-check]')].map((box) =>
      box.getAttribute('data-machine-check'),
    );
    selectAll.checked = visible.length > 0 && visible.every((key) => selectedKeys.has(key));
  }

  function renderTagList(tags) {
    const list = document.getElementById('machine-tag-list');
    if (!tags.length) {
      list.innerHTML = '<span class="text-muted fs-13">Aucun tag sur cette sélection.</span>';
      return;
    }
    list.innerHTML = tags
      .map(
        (tag) =>
          `<span class="badge bg-primary-subtle text-primary d-inline-flex align-items-center gap-1">
             ${SOC.escapeHtml(tag)}
             <button type="button" class="btn btn-link p-0 border-0 text-primary" data-tag-remove="${SOC.escapeHtml(tag)}"
               title="Retirer ce tag" aria-label="Retirer le tag ${SOC.escapeHtml(tag)}"><i class="ti ti-x"></i></button>
           </span>`,
      )
      .join('');
  }

  async function loadTagList() {
    const page = await SOC.api(
      `/api/machines?${SOC.params({ limit: 100, keys: [...selectedKeys].join(',') })}`,
    );
    const tags = [...new Set((page.data || []).flatMap((machine) => machine.tags || []))].sort((a, b) =>
      a.localeCompare(b, 'fr'),
    );
    renderTagList(tags);
  }

  async function openTagModal() {
    if (!tagModal || selectedKeys.size === 0) return;
    document.getElementById('machine-tag-selection').textContent = `${selectedKeys.size} machine(s) sélectionnée(s)`;
    document.getElementById('machine-tag-input').value = '';
    SOC.clearAlert('#machine-tag-error');
    renderTagList([]);
    tagModal.show();
    try {
      await loadTagList();
    } catch (error) {
      SOC.showAlert('#machine-tag-error', error.message || 'Tags indisponibles.');
    }
  }

  async function postTag(method, tag) {
    const response = await fetch('/api/machines/tags', {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ machineKeys: [...selectedKeys], tag }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'Opération refusée.');
    await loadTagList();
    pager.load();
  }

  document.getElementById('agents-add-tag').addEventListener('click', openTagModal);

  document.getElementById('machine-tag-add').addEventListener('click', async () => {
    const input = document.getElementById('machine-tag-input');
    const tag = input.value.trim();
    SOC.clearAlert('#machine-tag-error');
    if (!tag) {
      SOC.showAlert('#machine-tag-error', 'Saisissez un tag.');
      return;
    }
    try {
      await postTag('POST', tag);
      input.value = '';
    } catch (error) {
      SOC.showAlert('#machine-tag-error', error.message);
    }
  });

  document.getElementById('machine-tag-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') document.getElementById('machine-tag-add').click();
  });

  document.getElementById('machine-tag-list').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-tag-remove]');
    if (!button) return;
    SOC.clearAlert('#machine-tag-error');
    try {
      await postTag('DELETE', button.getAttribute('data-tag-remove'));
    } catch (error) {
      SOC.showAlert('#machine-tag-error', error.message);
    }
  });

  tbody.addEventListener('change', (event) => {
    const box = event.target.closest('[data-machine-check]');
    if (!box) return;
    const key = box.getAttribute('data-machine-check');
    if (box.checked) selectedKeys.add(key);
    else selectedKeys.delete(key);
    syncSelectionUi();
  });

  if (selectAll) {
    selectAll.addEventListener('change', () => {
      tbody.querySelectorAll('[data-machine-check]').forEach((box) => {
        box.checked = selectAll.checked;
        const key = box.getAttribute('data-machine-check');
        if (selectAll.checked) selectedKeys.add(key);
        else selectedKeys.delete(key);
      });
      syncSelectionUi();
    });
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
    renderIdentity(agentsById.get(id));

    modal.show();

    loadDetailTab(`/api/agents/${encodeURIComponent(id)}/applications?limit=50`, document.getElementById('agent-apps-body'), 5, renderApplications);
  }

  tbody.addEventListener('click', (event) => {
    if (event.target.closest('[data-machine-check]')) return;
    const toggle = event.target.closest('[data-machine-toggle]');
    if (toggle) {
      event.stopPropagation();
      const key = toggle.getAttribute('data-machine-toggle');
      const hidden = [...tbody.querySelectorAll(`tr.soc-agent-subrow[data-machine="${CSS.escape(key)}"]`)]
        .filter((row) => row.classList.contains('d-none'));
      hidden.forEach((row) => row.classList.remove('d-none'));
      const icon = toggle.querySelector('i');
      if (icon) icon.classList.toggle('ti-chevron-down', hidden.length > 0);
      if (icon) icon.classList.toggle('ti-chevron-right', hidden.length === 0);
      return;
    }
    const row = event.target.closest('tr.soc-agent-row');
    if (row) openAgentDetail(row);
  });

  const pager = SOC.createPager({
    limit: PAGE_SIZE,
    prev: document.getElementById('agents-prev'),
    next: document.getElementById('agents-next'),
    label: document.getElementById('agents-page-label'),
    onError: (error) => {
      tbody.innerHTML = `<tr><td colspan="7">${SOC.emptyState('Données indisponibles.', 'ti-alert-triangle')}</td></tr>`;
      SOC.showAlert('#agents-error', error.message || 'Impossible de charger les endpoints.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#agents-error');
      loadingRow();

      if (view === 'machines') {
        const page = await SOC.api(
          `/api/machines?${SOC.params({
            limit: PAGE_SIZE,
            cursor,
            query,
            duplicates: filter === 'duplicates' ? '1' : undefined,
            collisions: filter === 'collisions' ? '1' : undefined,
          })}`,
        );
        renderMachines(page);
        syncSelectionUi();
        updateKpis(page.summary);
        const total = page.pagination.totalItems;
        totalBadge.textContent = `${SOC.formatNumber(page.summary ? page.summary.machines : total)} machine(s)`;
        range.textContent = `${page.data.length} machine(s) affichée(s) sur ${SOC.formatNumber(total)}`;
        SOC.markUpdated();
        return page;
      }

      const page = await SOC.api(
        `/api/agents?${SOC.params({ limit: PAGE_SIZE, cursor, query })}`,
      );
      renderRows(page.data);
      syncSelectionUi();
      const total = page.pagination.totalItems;
      totalBadge.textContent = `${SOC.formatNumber(total)} agent(s)`;
      range.textContent = `${page.data.length} agent(s) affiché(s) sur ${SOC.formatNumber(total)}`;
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

  viewMachinesButton.addEventListener('click', () => {
    if (view === 'machines') return;
    view = 'machines';
    localStorage.setItem('soc-agents-view', view);
    paintViewButtons();
    pager.reset();
  });

  viewAgentsButton.addEventListener('click', () => {
    if (view === 'agents') return;
    view = 'agents';
    localStorage.setItem('soc-agents-view', view);
    paintViewButtons();
    pager.reset();
  });

  filterSelect.addEventListener('change', () => {
    filter = filterSelect.value;
    if (view !== 'machines') {
      view = 'machines';
      localStorage.setItem('soc-agents-view', view);
      paintViewButtons();
    }
    pager.reset();
  });

  paintViewButtons();
  SOC.onRefresh(() => pager.reset());
  pager.load();
})();

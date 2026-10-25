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

  function loadingTable() {
    tbody.innerHTML = `<tr><td colspan="${activeColumns().length}" class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>Chargement des endpoints…</td></tr>`;
  }

  // Identité machine conservée en mémoire pour remplir la modale de détail.
  const agentsById = new Map();

  /* ──────────────── colonnes personnalisables (choix persisté) ───────────── */

  const COLUMNS_STORAGE = 'soc-agents-columns';

  const COLUMNS = [
    { key: 'name', label: 'Endpoint', machineLabel: 'Machine', default: true, cls: '', views: ['agents', 'machines'] },
    { key: 'ip', label: 'Adresse IP', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'os', label: 'Système', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'serial', label: 'N° de série', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'mac', label: 'Adresse MAC', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'model', label: 'Modèle', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'version', label: 'Version agent', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'site', label: 'Site', default: true, cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'status', label: 'Statut', default: true, cls: '', views: ['agents', 'machines'] },
    { key: 'lastActive', label: 'Dernière activité', default: true, cls: 'text-muted fs-13', views: ['agents', 'machines'] },
    { key: 'tags', label: 'Tags', default: true, cls: 'fs-13', views: ['machines'] },
    { key: 'domain', label: 'Domaine', cls: 'fs-13', views: ['agents', 'machines'] },
    { key: 'registeredAt', label: 'Inscrit le', cls: 'text-muted fs-13', views: ['agents', 'machines'] },
    { key: 'machineKey', label: 'Clé machine', cls: 'fs-13', views: ['machines'] },
    { key: 'agentCount', label: 'Nb d\u2019agents', cls: 'fs-13', views: ['machines'] },
    { key: 'onlineCount', label: 'Agents en ligne', cls: 'fs-13', views: ['machines'] },
    { key: 'account', label: 'Compte', cls: 'fs-13', views: ['agents'] },
    { key: 'ipAddresses', label: 'Autres adresses IP', cls: 'fs-13', views: ['agents'] },
    { key: 'machineUuid', label: 'UUID machine', cls: 'fs-13', views: ['agents'] },
    { key: 'machineSid', label: 'SID machine', cls: 'fs-13', views: ['agents'] },
    { key: 'externalId', label: 'External ID', cls: 'fs-13', views: ['agents'] },
    { key: 'osType', label: 'Type OS', cls: 'fs-13', views: ['agents'] },
    { key: 'id', label: 'Identifiant', cls: 'fs-13', views: ['agents'] },
  ];

  function storedSelection() {
    try {
      const parsed = JSON.parse(localStorage.getItem(COLUMNS_STORAGE) || '{}');
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (error) {
      return {};
    }
  }

  function availableColumns(viewKey) {
    return COLUMNS.filter((col) => col.views.includes(viewKey));
  }

  function selectionFor(viewKey) {
    const available = availableColumns(viewKey);
    const stored = storedSelection()[viewKey];
    const valid = Array.isArray(stored) ? stored.filter((key) => available.some((col) => col.key === key)) : [];
    if (!valid.length) return available.filter((col) => col.default).map((col) => col.key);
    return valid;
  }

  function activeColumns() {
    const chosen = new Set(selectionFor(view));
    return COLUMNS.filter((col) => col.views.includes(view) && chosen.has(col.key));
  }

  function columnLabel(col) {
    return view === 'machines' && col.machineLabel ? col.machineLabel : col.label;
  }

  function persistSelection(next) {
    if (!next.length) return false;
    const all = storedSelection();
    all[view] = next;
    localStorage.setItem(COLUMNS_STORAGE, JSON.stringify(all));
    return true;
  }

  function renderHead() {
    const row = document.getElementById('agents-head-row');
    if (!row) return;
    const cols = activeColumns();
    row.innerHTML = cols.map((col) => `<th>${SOC.escapeHtml(columnLabel(col))}</th>`).join('');
    const counter = document.querySelector('[data-columns-count]');
    if (counter) counter.textContent = String(cols.length);
  }

  function renderColumnPicker() {
    const menu = document.getElementById('agents-columns-menu');
    if (!menu) return;
    const available = availableColumns(view);
    const chosen = new Set(selectionFor(view));
    menu.innerHTML =
      `<li><span class="dropdown-item-text text-muted fs-12">${chosen.size} colonne(s) affichée(s) sur ${available.length}</span></li>` +
      available
        .map(
          (col) => `<li><label class="dropdown-item d-flex align-items-center gap-2 mb-0">
            <input class="form-check-input m-0" type="checkbox" data-col-toggle="${col.key}"${
              chosen.has(col.key) ? ' checked' : ''
            }>
            <span>${SOC.escapeHtml(columnLabel(col))}</span>
          </label></li>`,
        )
        .join('') +
      `<li><hr class="dropdown-divider"></li>
       <li><button class="dropdown-item" type="button" data-col-all>Tout afficher</button></li>
       <li><button class="dropdown-item" type="button" data-col-reset>Réinitialiser</button></li>`;
  }

  let lastPage = null;

  function refreshColumns() {
    renderHead();
    renderColumnPicker();
    if (!lastPage) return;
    if (view === 'machines') {
      renderMachines(lastPage);
      syncSelectionUi();
    } else {
      renderRows(lastPage.data || []);
    }
  }

  /* ──────────────── rendu d’une cellule selon la colonne ─────────────────── */

  function cellValue(value) {
    return value ? SOC.escapeHtml(String(value)) : '<span class="text-muted">\u2014</span>';
  }

  function cellMono(value) {
    return value
      ? `<span class="font-monospace">${SOC.escapeHtml(String(value))}</span>`
      : '<span class="text-muted">\u2014</span>';
  }

  function cellList(values) {
    const list = Array.isArray(values) ? values : [];
    return list.length ? SOC.escapeHtml(list.join(', ')) : '<span class="text-muted">\u2014</span>';
  }

  function cellMac(values) {
    const list = Array.isArray(values) ? values : [];
    if (!list.length) return '<span class="text-muted">\u2014</span>';
    const extra = list.length > 1 ? ` <span class="text-muted">+${list.length - 1}</span>` : '';
    return `<span class="font-monospace">${SOC.escapeHtml(list[0])}</span>${extra}`;
  }

  function cellDate(value) {
    if (!value) return '<span class="text-muted">\u2014</span>';
    return `${SOC.formatDate(value)}<div class="fs-11">${SOC.formatRelative(value)}</div>`;
  }

  function cellStatus(status) {
    return status ? SOC.agentStatusBadge(status) : '<span class="text-muted">\u2014</span>';
  }

  function primaryOf(machine) {
    return machine.__agent || machine.agents[0] || {};
  }

  function machineBadges(machine) {
    const badges = [];
    if (machine.duplicate) {
      badges.push(
        `<span class="badge bg-warning-subtle text-warning"><i class="ti ti-alert-triangle me-1"></i>${machine.agentCount} agents${
          machine.onlineCount > 1 ? ` \u00b7 ${machine.onlineCount} en ligne` : ''
        }</span>`,
      );
    }
    if (machine.nameCollision) {
      badges.push('<span class="badge bg-danger-subtle text-danger"><i class="ti ti-alert-triangle me-1"></i>Nom partag\u00e9</span>');
    }
    if (machine.infected) {
      badges.push('<span class="badge bg-danger-subtle text-danger">Infect\u00e9</span>');
    }
    return badges.length ? `<div class="mt-1">${badges.join(' ')}</div>` : '';
  }

  const AGENT_CELLS = {
    name: (agent) =>
      `<a href="/endpoints/${encodeURIComponent(agent.id)}" class="fw-semibold text-decoration-none" data-endpoint-link>${SOC.escapeHtml(
        agent.name,
      )}</a>`,
    ip: (agent) => cellValue(agent.ip),
    os: (agent) =>
      `${cellValue(agent.os)}${agent.machineType ? `<div class="text-muted fs-11">${SOC.escapeHtml(agent.machineType)}</div>` : ''}`,
    serial: (agent) =>
      agent.serialNumber
        ? `<span class="font-monospace">${SOC.escapeHtml(agent.serialNumber)}</span>`
        : '<span class="text-muted">S\u00e9rie absente</span>',
    mac: (agent) => cellMac(agent.macAddresses),
    model: (agent) =>
      agent.model
        ? `<span class="text-truncate d-inline-block" style="max-width:170px" title="${SOC.escapeHtml(agent.model)}">${SOC.escapeHtml(
            agent.model,
          )}</span>`
        : '<span class="text-muted">\u2014</span>',
    version: (agent) => cellValue(agent.version),
    site: (agent) => cellValue(agent.site),
    status: (agent) => cellStatus(agent.status),
    lastActive: (agent) => cellDate(agent.lastActiveAt),
    domain: (agent) => cellValue(agent.domain),
    registeredAt: (agent) => cellDate(agent.registeredAt),
    account: (agent) => cellValue(agent.account),
    ipAddresses: (agent) => cellList(agent.ipAddresses),
    machineUuid: (agent) => cellMono(agent.machineUuid),
    machineSid: (agent) => cellMono(agent.machineSid),
    externalId: (agent) => cellMono(agent.externalId),
    osType: (agent) => cellValue(agent.osType),
    id: (agent) => cellMono(agent.id),
  };

  const MACHINE_CELLS = {
    name: (machine, opts) => {
      const primary = primaryOf(machine);
      if (opts.sub) {
        return `<a href="/endpoints/${encodeURIComponent(primary.id || '')}" class="text-decoration-none">${SOC.escapeHtml(
          machine.name,
        )}</a> <span class="text-muted fs-11 font-monospace">${SOC.escapeHtml(primary.id || '')}</span>`;
      }
      return `<span class="fw-semibold d-block">${SOC.escapeHtml(machine.name)}
        <a href="/endpoints/${encodeURIComponent(primary.id || '')}" class="ms-1 text-decoration-none" data-endpoint-link
           title="Ouvrir la fiche de l\u2019endpoint"><i class="ti ti-external-link fs-12"></i></a></span>
        ${machineBadges(machine)}`;
    },
    ip: (machine) => cellValue(machine.ip),
    os: (machine) => {
      const primary = primaryOf(machine);
      const os = primary.os || '\u2014';
      const kind = primary.machineType || primary.osType || '';
      return `${SOC.escapeHtml(os)}${kind ? `<div class="text-muted fs-11">${SOC.escapeHtml(kind)}</div>` : ''}`;
    },
    serial: (machine) =>
      machine.serialNumbers && machine.serialNumbers.length
        ? SOC.escapeHtml(machine.serialNumbers.join(', '))
        : '<span class="text-muted">S\u00e9rie absente</span>',
    mac: (machine) => cellMac(machine.macAddresses),
    model: (machine) =>
      machine.model
        ? `<span class="text-truncate d-inline-block" style="max-width:170px" title="${SOC.escapeHtml(machine.model)}">${SOC.escapeHtml(
            machine.model,
          )}</span>`
        : '<span class="text-muted">\u2014</span>',
    version: (machine) => cellValue(primaryOf(machine).version),
    site: (machine) => cellValue(machine.site),
    status: (machine) => cellStatus(machine.status),
    lastActive: (machine) => cellDate(machine.lastActiveAt),
    tags: (machine) => {
      const chips = (machine.tags || [])
        .map((tag) => `<span class="badge bg-secondary-subtle text-secondary me-1">${SOC.escapeHtml(tag)}</span>`)
        .join('');
      return chips || '<span class="text-muted">\u2014</span>';
    },
    domain: (machine) => cellValue(primaryOf(machine).domain),
    registeredAt: (machine) => cellDate(machine.registeredAt),
    machineKey: (machine) => cellMono(machine.machineKey),
    agentCount: (machine) => `${machine.agentCount || 0}`,
    onlineCount: (machine) => `${machine.onlineCount || 0} / ${machine.agentCount || 0}`,
  };

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

  function rowCells(cells, render) {
    return cells.map((col) => `<td class="${col.cls}">${render(col)}</td>`).join('');
  }

  function renderRows(data) {
    data.forEach((agent) => agentsById.set(agent.id, agent));
    const cols = activeColumns();

    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="${cols.length}">${SOC.emptyState(
        query ? 'Aucun endpoint ne correspond à cette recherche.' : 'Aucun endpoint remonté par SentinelOne.',
        'ti-devices-off',
      )}</td></tr>`;
      return;
    }

    tbody.innerHTML = data
      .map(
        (agent) => `<tr class="soc-agent-row" data-agent-id="${SOC.escapeHtml(agent.id)}" data-agent-name="${SOC.escapeHtml(
          agent.name,
        )}" data-agent-os="${SOC.escapeHtml(agent.os)}" data-agent-site="${SOC.escapeHtml(
          agent.site,
        )}" data-agent-status="${SOC.escapeHtml(agent.status)}" data-agent-version="${SOC.escapeHtml(
          agent.version,
        )}" data-agent-ip="${SOC.escapeHtml(agent.ip)}" data-agent-last-active="${SOC.escapeHtml(
          agent.lastActiveAt || '',
        )}" style="cursor:pointer">
          ${rowCells(cols, (col) => (AGENT_CELLS[col.key] || (() => '—'))(agent))}
        </tr>`,
      )
      .join('');
  }

  // Vue machines : une ligne par machine, les agents additionnels (doublon)
  // apparaissent en sous-lignes dépliables.
  function twinMachine(machine, agent) {
    return Object.assign({}, machine, {
      name: agent.name,
      ip: agent.ip,
      site: agent.site,
      status: agent.status,
      lastActiveAt: agent.lastActiveAt,
      registeredAt: agent.registeredAt,
      model: agent.model || '',
      serialNumbers: agent.serialNumber ? [agent.serialNumber] : [],
      macAddresses: agent.macAddresses || [],
      tags: [],
      duplicate: false,
      nameCollision: false,
      infected: agent.infected,
      agentCount: 1,
      onlineCount: 0,
      agents: [agent],
      __agent: agent,
    });
  }

  function machineMembers(machine) {
    if (machine.agentCount < 2) return '';
    const cols = activeColumns();
    return machine.agents
      .slice(1)
      .map((agent) => {
        const twin = twinMachine(machine, agent);
        const cells = cols.map((col, index) => {
          const content = (MACHINE_CELLS[col.key] || (() => '—'))(twin, { sub: true });
          return index === 0
            ? `<td class="ps-4 ${col.cls}"><div class="d-flex align-items-start gap-1"><span class="text-muted mt-1">↳</span><div class="flex-grow-1">${content}</div></div></td>`
            : `<td class="${col.cls}">${content}</td>`;
        });
        return `<tr class="soc-agent-subrow d-none" data-machine="${SOC.escapeHtml(machine.machineKey)}">${cells.join('')}</tr>`;
      })
      .join('');
  }

  function machineRow(machine) {
    const primary = machine.agents[0] || {};
    const cols = activeColumns();
    const checked = selectedKeys.has(machine.machineKey) ? 'checked' : '';
    const expand =
      machine.agentCount > 1
        ? `<button type="button" class="btn btn-sm btn-link text-decoration-none p-0" data-machine-toggle="${SOC.escapeHtml(
            machine.machineKey,
          )}" title="Afficher les ${machine.agentCount} agents de cette machine"><i class="ti ti-chevron-right"></i></button>`
        : '';
    const tools = `<input type="checkbox" class="form-check-input mt-1" data-machine-check="${SOC.escapeHtml(
      machine.machineKey,
    )}" ${checked} aria-label="Sélectionner ${SOC.escapeHtml(machine.name)}">${expand}`;

    const cells = cols.map((col, index) => {
      const content = (MACHINE_CELLS[col.key] || (() => '—'))(machine, { sub: false });
      return index === 0
        ? `<td class="${col.cls}"><div class="d-flex align-items-start gap-1">${tools}<div class="flex-grow-1">${content}</div></div></td>`
        : `<td class="${col.cls}">${content}</td>`;
    });

    return `<tr class="soc-agent-row" data-agent-id="${SOC.escapeHtml(primary.id || '')}" data-agent-name="${SOC.escapeHtml(
      primary.name || machine.name,
    )}" data-agent-os="${SOC.escapeHtml(primary.os || '—')}" data-agent-site="${SOC.escapeHtml(
      primary.site || machine.site,
    )}" data-agent-status="${SOC.escapeHtml(primary.status || machine.status)}" data-agent-version="${SOC.escapeHtml(
      primary.version || '—',
    )}" data-agent-ip="${SOC.escapeHtml(primary.ip || machine.ip)}" data-agent-last-active="${SOC.escapeHtml(
      primary.lastActiveAt || '',
    )}" style="cursor:pointer">${cells.join('')}</tr>`;
  }

  function renderMachines(page) {
    const data = page.data || [];
    if (!data.length) {
      tbody.innerHTML = `<tr><td colspan="${activeColumns().length}">${SOC.emptyState(
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

    const openLink = document.getElementById('agent-detail-open');
    if (openLink) openLink.href = `/endpoints/${encodeURIComponent(id)}`;

    modal.show();

    loadDetailTab(`/api/agents/${encodeURIComponent(id)}/applications?limit=50`, document.getElementById('agent-apps-body'), 5, renderApplications);
  }

  tbody.addEventListener('click', (event) => {
    if (event.target.closest('a[data-endpoint-link]')) return;
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
      tbody.innerHTML = `<tr><td colspan="${activeColumns().length}">${SOC.emptyState(
        'Données indisponibles.',
        'ti-alert-triangle',
      )}</td></tr>`;
      SOC.showAlert('#agents-error', error.message || 'Impossible de charger les endpoints.');
    },
    onPage: async (cursor) => {
      SOC.clearAlert('#agents-error');
      loadingTable();

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
        lastPage = page;
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
      lastPage = page;
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
    renderHead();
    renderColumnPicker();
    pager.reset();
  });

  viewAgentsButton.addEventListener('click', () => {
    if (view === 'agents') return;
    view = 'agents';
    localStorage.setItem('soc-agents-view', view);
    paintViewButtons();
    renderHead();
    renderColumnPicker();
    pager.reset();
  });

  filterSelect.addEventListener('change', () => {
    filter = filterSelect.value;
    if (view !== 'machines') {
      view = 'machines';
      localStorage.setItem('soc-agents-view', view);
      paintViewButtons();
      renderHead();
      renderColumnPicker();
    }
    pager.reset();
  });

  /* Choix des colonnes : au moins une colonne reste toujours affichée. */
  const columnsMenu = document.getElementById('agents-columns-menu');

  function toggleColumns(next) {
    if (!persistSelection(next)) return false;
    SOC.clearAlert('#agents-error');
    refreshColumns();
    return true;
  }

  if (columnsMenu) {
    columnsMenu.addEventListener('change', (event) => {
      const input = event.target.closest('[data-col-toggle]');
      if (!input) return;
      const next = availableColumns(view)
        .map((col) => col.key)
        .filter((key) => {
          const box = columnsMenu.querySelector(`[data-col-toggle="${key}"]`);
          return box && box.checked;
        });
      if (!toggleColumns(next)) {
        input.checked = true;
        SOC.showAlert('#agents-error', 'Au moins une colonne doit rester affichée.');
      }
    });

    columnsMenu.addEventListener('click', (event) => {
      const pickAll = event.target.closest('[data-col-all]');
      const pickReset = event.target.closest('[data-col-reset]');
      if (!pickAll && !pickReset) return;
      event.preventDefault();
      const available = availableColumns(view);
      const next = pickAll ? available.map((col) => col.key) : available.filter((col) => col.default).map((col) => col.key);
      if (toggleColumns(next)) {
        columnsMenu.querySelectorAll('[data-col-toggle]').forEach((box) => {
          box.checked = next.includes(box.getAttribute('data-col-toggle'));
        });
      }
    });
  }

  paintViewButtons();
  renderHead();
  renderColumnPicker();
  SOC.onRefresh(() => pager.reset());
  pager.load();
})();

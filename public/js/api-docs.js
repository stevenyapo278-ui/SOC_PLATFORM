/* Vue Documentation API — catalogue généré depuis le Swagger exporté de la console. */
(function () {
  'use strict';

  SOC.initShell('apidocs');

  const DATA_BASE = '/api-docs/data';
  const METHOD_CLASSES = {
    GET: 'bg-success-subtle text-success',
    POST: 'bg-primary-subtle text-primary',
    PUT: 'bg-warning-subtle text-warning',
    DELETE: 'bg-danger-subtle text-danger',
    PATCH: 'bg-info-subtle text-info',
  };

  const els = {
    error: document.getElementById('apidocs-error'),
    cats: document.getElementById('apidocs-cats'),
    catsCount: document.querySelector('[data-apidocs-cats-count]'),
    list: document.getElementById('apidocs-list'),
    listTitle: document.getElementById('apidocs-list-title'),
    listCount: document.querySelector('[data-apidocs-list-count]'),
    count: document.querySelector('[data-apidocs-count]'),
    search: document.getElementById('apidocs-search'),
    query: document.getElementById('apidocs-query'),
    reset: document.getElementById('apidocs-reset'),
  };

  let index = null;
  let activeCatSlug = null;
  const catCache = new Map();

  function normalizePath(url) {
    return String(url || '')
      .replace(/\{[^}]+\}/g, '')
      .replace(/\/+/g, '/')
      .replace(/\/$/, '');
  }

  function buildOverrides(catalog) {
    const map = new Map();
    for (const item of catalog) {
      const key = `${item.method} ${normalizePath(item.path)}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(item);
    }
    return map;
  }

  const OVERRIDES = buildOverrides(window.SOC_API_CATALOG || []);

  function findOverrides(op) {
    return OVERRIDES.get(`${op.method} ${normalizePath(op.url)}`) || [];
  }

  function methodBadge(method) {
    const cls = METHOD_CLASSES[method] || 'bg-secondary-subtle text-secondary';
    return `<span class="badge ${cls} font-monospace">${SOC.escapeHtml(method)}</span>`;
  }

  function mergeOp(op, slug) {
    const overrides = findOverrides(op);
    if (!overrides.length) return { ...op, slug };

    const merged = { ...op, slug };
    for (const ov of overrides) {
      if (ov.title) merged.title = ov.title;
      if (ov.description) merged.description = ov.description;
      if (ov.note) merged.note = ov.note;
      if (ov.deprecated) merged.deprecated = true;
      if (Array.isArray(ov.responseFields) && ov.responseFields.length) merged.overrideResponseFields = ov.responseFields;
      if (Array.isArray(ov.queryParams) && ov.queryParams.length) merged.overrideQueryParams = ov.queryParams;
      if (ov.sample) merged.overrideSample = ov.sample;
      if (Array.isArray(ov.permissions) && ov.permissions.length) merged.permissions = ov.permissions;
      if (Array.isArray(ov.optionalPermissions) && ov.optionalPermissions.length) merged.optionalPermissions = ov.optionalPermissions;
    }
    return merged;
  }

  function opTitle(op) {
    return op.title || op.name;
  }

  async function loadJson(url) {
    const response = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const type = response.headers.get('content-type') || '';
    if (!type.includes('json')) throw new Error('Réponse non JSON');
    return response.json();
  }

  async function loadCategory(slug) {
    if (catCache.has(slug)) return catCache.get(slug);
    const data = await loadJson(`${DATA_BASE}/cat/${slug}.json`);
    catCache.set(slug, data);
    return data;
  }

  function renderCats() {
    if (!index) return;
    const categories = index.categories;
    els.catsCount.textContent = `${categories.length}`;
    els.cats.innerHTML = categories
      .map(
        (cat) => `
      <button type="button" class="list-group list-group-item-action apidocs-cat ${cat.slug === activeCatSlug ? 'active' : ''}"
        data-cat="${SOC.escapeHtml(cat.slug)}">
        <div class="d-flex justify-content-between align-items-center gap-2">
          <span class="soc-truncate">${SOC.escapeHtml(cat.name)}</span>
          <span class="badge ${cat.slug === activeCatSlug ? 'bg-white text-primary' : 'bg-secondary-subtle text-secondary'}">${cat.count}</span>
        </div>
      </button>`,
      )
      .join('');
  }

  function opRow(op, showCat) {
    const perms = (op.permissions || [])
      .slice(0, 3)
      .map((p) => `<span class="badge bg-secondary-subtle text-secondary">${SOC.escapeHtml(p)}</span>`)
      .join(' ');
    const extra = (op.permissions || []).length > 3 ? `<span class="badge bg-secondary-subtle text-secondary">+${op.permissions.length - 3}</span>` : '';
    const deprecated = op.deprecated ? '<span class="badge bg-danger-subtle text-danger">Obsolète</span>' : '';
    const cat = showCat ? `<span class="badge bg-light text-muted border">${SOC.escapeHtml(op.catName || '')}</span>` : '';

    return `
      <div class="border rounded p-2 mb-2 apidocs-op" data-slug="${SOC.escapeHtml(op.slug)}" data-id="${SOC.escapeHtml(op.id)}">
        <button type="button" class="btn btn-link text-start w-100 p-0 apidocs-op-toggle" aria-expanded="false">
          <div class="d-flex align-items-start gap-2 flex-wrap">
            ${methodBadge(op.method)}
            <div class="flex-grow-1 min-width-0">
              <div class="fw-semibold fs-14">${SOC.escapeHtml(opTitle(op))} ${deprecated} ${cat}</div>
              <code class="fs-12 text-muted">${SOC.escapeHtml(op.url)}</code>
            </div>
            <i class="ti ti-chevron-down text-primary apidocs-chevron"></i>
          </div>
          <div class="d-flex flex-wrap gap-1 mt-1">${perms} ${extra}</div>
        </button>
        <div class="apidocs-detail collapse mt-2" id="detail-${SOC.escapeHtml(op.slug)}-${SOC.escapeHtml(op.id)}"></div>
      </div>`;
  }

  function renderList(ops, title, showCat) {
    els.listTitle.textContent = title;
    els.listCount.textContent = `${ops.length}`;
    if (!ops.length) {
      els.list.innerHTML = SOC.emptyState('Aucun endpoint ne correspond.', 'ti-search');
      return;
    }
    els.list.innerHTML = ops.map((op) => opRow(op, showCat)).join('');
  }

  async function renderCategory(slug) {
    const cat = index.categories.find((entry) => entry.slug === slug);
    if (!cat) return;
    activeCatSlug = slug;
    renderCats();
    SOC.setLoading('#apidocs-list', 'Chargement des endpoints…');
    try {
      const data = await loadCategory(slug);
      const ops = data.operations.map((op) => mergeOp(op, slug));
      renderList(ops, cat.name, false);
    } catch (error) {
      SOC.showAlert('#apidocs-error', `Impossible de charger la catégorie : ${error.message}`);
      els.list.innerHTML = SOC.emptyState('Catégorie indisponible.', 'ti-alert-triangle');
    }
  }

  function searchOps(term) {
    const results = [];
    for (const cat of index.categories) {
      for (const summary of cat.operations) {
        const hay = `${summary.name} ${summary.method} ${summary.url} ${cat.name} ${(summary.permissions || []).join(' ')}`.toLowerCase();
        if (hay.includes(term)) results.push({ summary, cat });
        if (results.length >= 300) return results;
      }
    }
    return results;
  }

  async function renderSearch(term) {
    const results = searchOps(term);
    els.listTitle.textContent = `Résultats pour « ${term} »`;
    els.listCount.textContent = results.length >= 300 ? '300+' : `${results.length}`;
    if (!results.length) {
      els.list.innerHTML = SOC.emptyState('Aucun endpoint ne correspond à cette recherche.', 'ti-search');
      return;
    }

    const slugs = [...new Set(results.map((r) => r.cat.slug))];
    await Promise.all(slugs.map((slug) => loadCategory(slug).catch(() => null)));

    const ops = [];
    for (const { summary, cat } of results) {
      const data = catCache.get(cat.slug);
      if (!data) continue;
      const found = data.operations.find((op) => op.id === summary.id);
      if (found) {
        const merged = mergeOp(found, cat.slug);
        merged.catName = cat.name;
        ops.push(merged);
      }
    }
    renderList(ops, `Résultats pour « ${term} »`, true);
  }

  function paramRows(params, overrideParams) {
    if (overrideParams && overrideParams.length) {
      return overrideParams
        .map(
          (p) => `<tr>
            <td><code class="fs-12">${SOC.escapeHtml(p.name)}</code></td>
            <td class="fs-12 text-muted">${SOC.escapeHtml(p.type || '')}</td>
            <td class="fs-13">${SOC.escapeHtml(p.desc || p.description || '')}</td>
          </tr>`,
        )
        .join('');
    }
    return params
      .map(
        (p) => `<tr>
          <td><code class="fs-12">${SOC.escapeHtml(p.name)}</code>${p.required ? ' <span class="text-danger">*</span>' : ''}</td>
          <td class="fs-12 text-muted">${SOC.escapeHtml(p.type || '')}${p.enum && p.enum.length ? `<br><span class="fs-11">${SOC.escapeHtml(p.enum.join(', '))}</span>` : ''}</td>
          <td class="fs-13">${SOC.escapeHtml(p.description || '')}</td>
        </tr>`,
      )
      .join('');
  }

  function paramTables(op) {
    const locations = { query: 'Paramètres de requête', path: 'Paramètres de chemin', formData: 'Données de formulaire' };
    const override = op.overrideQueryParams;
    let html = '';
    if (override) {
      html += `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Paramètres (extrait)</p>
        <div class="table-responsive mb-3">
          <table class="table table-sm table-bordered soc-table mb-0">
            <thead><tr><th>Param</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>${paramRows([], override)}</tbody>
          </table>
        </div>`;
      return html;
    }
    for (const [location, label] of Object.entries(locations)) {
      const params = op.parameters && op.parameters[location];
      if (!params || !params.length) continue;
      html += `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">${label}${params.some((p) => p.required) ? ' — <span class="text-danger">* requis</span>' : ''}</p>
        <div class="table-responsive mb-3">
          <table class="table table-sm table-bordered soc-table mb-0">
            <thead><tr><th>Param</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>${paramRows(params)}</tbody>
          </table>
        </div>`;
    }
    if (op.body && op.body.fields && op.body.fields.length) {
      html += `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Corps de la requête (body)</p>
        <div class="table-responsive mb-3">
          <table class="table table-sm table-bordered soc-table mb-0">
            <thead><tr><th>Champ</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>${paramRows(op.body.fields.map((f) => ({ name: f.path, type: f.type, required: f.required, description: f.description, enum: f.enum })))}</tbody>
          </table>
        </div>`;
    }
    return html;
  }

  function responseFieldsHtml(op) {
    if (op.overrideResponseFields) {
      return `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Réponse</p>
        <div class="table-responsive mb-3">
          <table class="table table-sm table-bordered soc-table mb-0">
            <thead><tr><th>Champ</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>${op.overrideResponseFields
              .map(
                (f) => `<tr>
                  <td><code class="fs-12">${SOC.escapeHtml(f.name)}</code></td>
                  <td class="fs-12 text-muted">${SOC.escapeHtml(f.type || '')}</td>
                  <td class="fs-13">${SOC.escapeHtml(f.desc || '')}</td>
                </tr>`,
              )
              .join('')}</tbody>
          </table>
        </div>`;
    }
    if (!op.response || !op.response.fields || !op.response.fields.length) return '';
    return `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Schéma de réponse</p>
      <div class="table-responsive mb-3">
        <table class="table table-sm table-bordered soc-table mb-0">
          <thead><tr><th>Champ</th><th>Type</th><th>Req.</th><th>Description</th></tr></thead>
          <tbody>${op.response.fields
            .map(
              (f) => `<tr>
                <td><code class="fs-12">${SOC.escapeHtml(f.path)}</code></td>
                <td class="fs-12 text-muted">${SOC.escapeHtml(f.type || '')}</td>
                <td class="fs-12">${f.required ? '<i class="ti ti-check text-success"></i>' : ''}</td>
                <td class="fs-13">${SOC.escapeHtml(f.description || '')}</td>
              </tr>`,
            )
            .join('')}</tbody>
        </table>
      </div>`;
  }

  function responsesHtml(op) {
    if (!op.responses || !op.responses.length) return '';
    return `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Codes de réponse</p>
      <div class="table-responsive mb-3">
        <table class="table table-sm table-bordered soc-table mb-0">
          <thead><tr><th>Code</th><th>Signification</th></tr></thead>
          <tbody>${op.responses
            .map(
              (r) => `<tr>
                <td><span class="badge ${r.code.startsWith('2') ? 'bg-success-subtle text-success' : r.code.startsWith('4') ? 'bg-warning-subtle text-warning' : 'bg-danger-subtle text-danger'}">${SOC.escapeHtml(r.code)}</span></td>
                <td class="fs-13">${SOC.escapeHtml(r.description)}</td>
              </tr>`,
            )
            .join('')}</tbody>
        </table>
      </div>`;
  }

  function sampleHtml(op) {
    const sample = op.overrideSample || (op.response ? op.response.example : null);
    if (sample === undefined || sample === null) return '';
    return `<p class="fs-12 text-uppercase fw-semibold text-muted mb-1">Exemple de réponse</p>
      <pre class="bg-light border rounded p-2 fs-12 mb-0 overflow-auto apidocs-pre"><code>${SOC.escapeHtml(
        JSON.stringify(sample, null, 2),
      )}</code></pre>`;
  }

  function detailHtml(op) {
    const perms = (op.permissions || [])
      .map((p) => `<span class="badge bg-secondary-subtle text-secondary">${SOC.escapeHtml(p)}</span>`)
      .join(' ');
    const optional = (op.optionalPermissions || [])
      .map((p) => `<span class="badge bg-light text-muted border">${SOC.escapeHtml(p)}</span>`)
      .join(' ');
    const note = op.note ? `<div class="badge bg-light text-muted border">${SOC.escapeHtml(op.note)}</div>` : '';
    const deprecated = op.deprecated
      ? `<div class="alert alert-warning py-2 px-3 mb-2 fs-13"><i class="ti ti-alert-triangle me-1"></i>Endpoint obsolète ou déconseillé.</div>`
      : '';

    return `${deprecated}
      <p class="fs-13 mb-2">${SOC.escapeHtml(op.description || '')}</p>
      <div class="d-flex flex-wrap gap-1 mb-3">${perms} ${optional} ${note}</div>
      ${responsesHtml(op)}
      ${paramTables(op)}
      ${responseFieldsHtml(op)}
      ${sampleHtml(op)}`;
  }

  async function toggleDetail(container, op) {
    const box = container.querySelector('.apidocs-detail');
    const button = container.querySelector('.apidocs-op-toggle');
    const icon = container.querySelector('.apidocs-chevron');
    const open = box.classList.contains('show');

    if (open) {
      box.classList.remove('show');
      button.setAttribute('aria-expanded', 'false');
      if (icon) icon.className = 'ti ti-chevron-down text-primary apidocs-chevron';
      return;
    }

    if (!box.dataset.loaded) {
      box.innerHTML = `<div class="text-muted py-2 fs-13"><span class="spinner-border spinner-border-sm me-2"></span>Chargement…</div>`;
      box.classList.add('show');
      try {
        const data = await loadCategory(op.slug);
        const found = data.operations.find((entry) => entry.id === op.id);
        if (!found) throw new Error('Endpoint introuvable');
        box.innerHTML = detailHtml(mergeOp(found, op.slug));
        box.dataset.loaded = '1';
      } catch (error) {
        box.innerHTML = `<div class="text-danger fs-13">Détail indisponible : ${SOC.escapeHtml(error.message)}</div>`;
      }
    } else {
      box.classList.add('show');
    }
    button.setAttribute('aria-expanded', 'true');
    if (icon) icon.className = 'ti ti-chevron-up text-primary apidocs-chevron';
  }

  function currentOps() {
    return [...els.list.querySelectorAll('.apidocs-op')].map((node) => ({
      node,
      slug: node.dataset.slug,
      id: node.dataset.id,
    }));
  }

  els.list.addEventListener('click', async (event) => {
    const row = event.target.closest('.apidocs-op');
    const button = event.target.closest('.apidocs-op-toggle');
    if (!row || !button) return;
    const summary = currentOps().find((entry) => entry.node === row);
    await toggleDetail(row, summary || { slug: row.dataset.slug, id: row.dataset.id });
  });

  els.cats.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-cat]');
    if (!button) return;
    els.query.value = '';
    await renderCategory(button.dataset.cat);
  });

  els.search.addEventListener('submit', async (event) => {
    event.preventDefault();
    const term = els.query.value.trim().toLowerCase();
    if (!index) return;
    if (!term) {
      if (activeCatSlug) await renderCategory(activeCatSlug);
      return;
    }
    SOC.setLoading('#apidocs-list', 'Recherche en cours…');
    try {
      await renderSearch(term);
    } catch (error) {
      SOC.showAlert('#apidocs-error', `Recherche impossible : ${error.message}`);
    }
  });

  els.reset.addEventListener('click', async () => {
    els.query.value = '';
    if (activeCatSlug) await renderCategory(activeCatSlug);
  });

  async function init() {
    SOC.setLoading('#apidocs-cats', 'Chargement…');
    try {
      index = await loadJson(`${DATA_BASE}/index.json`);
    } catch (error) {
      SOC.showAlert('#apidocs-error', `Catalogue API indisponible : ${error.message}`);
      els.cats.innerHTML = '';
      els.list.innerHTML = SOC.emptyState('Catalogue indisponible.', 'ti-alert-triangle');
      return;
    }

    els.count.textContent = `${index.totalOperations} endpoints`;
    const date = new Date(index.generatedAt);
    document.querySelectorAll('[data-soc-updated]').forEach((el) => {
      el.textContent = date.toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
    });

    activeCatSlug = index.categories.length ? index.categories[0].slug : null;
    renderCats();
    if (activeCatSlug) await renderCategory(activeCatSlug);
  }

  init();
})();

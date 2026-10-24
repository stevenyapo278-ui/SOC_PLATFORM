/* Shared client helpers for SOC Sentinel. */
(function () {
  'use strict';

  const REFRESH_HANDLERS = [];
  const SEVERITY_LABELS = {
    critical: 'Critique',
    high: 'Élevée',
    medium: 'Moyenne',
    low: 'Faible',
    info: 'Info',
    unknown: 'Inconnue',
  };
  const SEVERITY_CLASSES = {
    critical: 'bg-danger-subtle text-danger',
    high: 'bg-warning-subtle text-warning',
    medium: 'bg-info-subtle text-info',
    low: 'bg-secondary-subtle text-secondary',
    info: 'bg-light text-muted',
    unknown: 'bg-secondary-subtle text-secondary',
  };

  const state = { user: null, settings: null };

  function escapeHtml(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ Accept: 'application/json' }, options.headers || {});
    const fetchOptions = Object.assign({ credentials: 'same-origin' }, options, { headers });

    if (options.body && typeof options.body !== 'string') {
      fetchOptions.body = JSON.stringify(options.body);
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(path, fetchOptions);
    const text = await response.text();
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { error: text };
      }
    }

    if (response.status === 401 && !options.noRedirect) {
      window.location.replace('/login');
      throw new Error('Session expirée.');
    }

    if (!response.ok) {
      const error = new Error((payload && payload.error) || `Erreur ${response.status}.`);
      error.status = response.status;
      error.code = payload && payload.code;
      throw error;
    }

    return payload;
  }

  function formatNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n.toLocaleString('fr-FR') : '—';
  }

  function formatDate(value, withTime = true) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString('fr-FR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}),
    });
  }

  function formatRelative(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    const diffSeconds = Math.round((date.getTime() - Date.now()) / 1000);
    const abs = Math.abs(diffSeconds);
    const units = [
      ['year', 31536000],
      ['month', 2592000],
      ['day', 86400],
      ['hour', 3600],
      ['minute', 60],
      ['second', 1],
    ];
    for (const [unit, seconds] of units) {
      if (abs >= seconds || unit === 'second') {
        const amount = Math.round(diffSeconds / seconds);
        return new Intl.RelativeTimeFormat('fr-FR', { numeric: 'auto' }).format(amount, unit);
      }
    }
    return '—';
  }

  function formatLongDate(value) {
    if (!value) return '—';
    const date = new Date(`${value}T00:00:00Z`);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleDateString('fr-FR', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      timeZone: 'UTC',
    });
  }

  function severityBadge(severity) {
    const key = SEVERITY_LABELS[severity] ? severity : 'unknown';
    return `<span class="badge ${SEVERITY_CLASSES[key]}">${SEVERITY_LABELS[key]}</span>`;
  }

  function textBadge(label, cls) {
    return `<span class="badge ${cls}">${escapeHtml(label)}</span>`;
  }

  function humanize(value, mapping) {
    if (!value || value === '—') return '—';
    const key = String(value);
    if (mapping && mapping[key.toLowerCase()]) return mapping[key.toLowerCase()];
    return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  const MITIGATION_LABELS = {
    not_mitigated: 'Non atténuée',
    mitigated: 'Atténuée',
    marked_as_benign: 'Bénigne',
    kill: 'Processus arrêté',
    quarantine: 'Mis en quarantaine',
  };
  const INCIDENT_LABELS = {
    unresolved: 'Non résolue',
    in_progress: 'En cours',
    resolved: 'Résolue',
  };
  const ALERT_STATUS_LABELS = {
    open: 'Ouverte',
    unresolved: 'Non résolue',
    in_progress: 'En cours',
    resolved: 'Résolue',
    closed: 'Fermée',
    dismissed: 'Ignorée',
  };
  const AGENT_STATUS = {
    online: { label: 'En ligne', cls: 'bg-success-subtle text-success' },
    offline: { label: 'Hors ligne', cls: 'bg-secondary-subtle text-secondary' },
    infected: { label: 'Infecté', cls: 'bg-danger-subtle text-danger' },
    decommissioned: { label: 'Désactivé', cls: 'bg-light text-muted' },
  };

  function agentStatusBadge(status) {
    const info = AGENT_STATUS[status] || { label: status, cls: 'bg-secondary-subtle text-secondary' };
    return textBadge(info.label, info.cls);
  }

  function mitigationBadge(value) {
    const label = humanize(value, MITIGATION_LABELS);
    const mitigated = ['mitigated', 'marked_as_benign'].includes(String(value).toLowerCase());
    return textBadge(label, mitigated ? 'bg-success-subtle text-success' : 'bg-warning-subtle text-warning');
  }

  function showAlert(selector, message, type = 'danger') {
    const container = document.querySelector(selector);
    if (!container) return;
    container.innerHTML = `<div class="alert alert-${type} d-flex align-items-start gap-2 mb-0" role="alert">
      <i class="ti ti-alert-triangle fs-18"></i><div>${escapeHtml(message)}</div></div>`;
  }

  function clearAlert(selector) {
    const container = document.querySelector(selector);
    if (container) container.innerHTML = '';
  }

  function setLoading(selector, message = 'Chargement des données SentinelOne…') {
    const container = document.querySelector(selector);
    if (!container) return;
    container.innerHTML = `<div class="text-center text-muted py-4">
      <span class="spinner-border spinner-border-sm text-primary me-2"></span>${escapeHtml(message)}</div>`;
  }

  function emptyState(message, icon = 'ti-inbox') {
    return `<div class="text-center text-muted py-4"><i class="ti ${icon} fs-28 d-block mb-2"></i>${escapeHtml(message)}</div>`;
  }

  function markUpdated() {
    const time = new Date().toLocaleTimeString('fr-FR');
    document.querySelectorAll('[data-soc-updated]').forEach((el) => {
      el.textContent = time;
    });
  }

  function onRefresh(handler) {
    REFRESH_HANDLERS.push(handler);
  }

  function buildSidebar(active) {
    const items = [
      { href: '/', key: 'dashboard', icon: 'ti-dashboard', label: 'Dashboard' },
      { href: '/agents', key: 'agents', icon: 'ti-devices', label: 'Endpoints' },
      { href: '/threats', key: 'threats', icon: 'ti-shield-exclamation', label: 'Menaces' },
      { href: '/alerts', key: 'alerts', icon: 'ti-bell', label: 'Alertes' },
      { href: '/activities', key: 'activities', icon: 'ti-history', label: 'Activités' },
      { href: '/chat', key: 'chat', icon: 'ti-message-chatbot', label: 'Assistant IA' },
      { href: '/settings', key: 'settings', icon: 'ti-settings', label: 'Paramètres' },
      { href: '/api-docs', key: 'apidocs', icon: 'ti-api', label: 'Documentation API' },
    ];

    return `
      <a href="/" class="logo">
        <span class="logo-lg d-flex align-items-center gap-2">
          <span class="avatar-title bg-primary text-white rounded fs-20" style="width:34px;height:34px"><i class="ti ti-shield-lock"></i></span>
          <span class="fw-bold fs-18 text-body">SOC<span class="text-primary">Sentinel</span></span>
        </span>
        <span class="logo-sm text-center">
          <span class="avatar-title bg-primary text-white rounded"><i class="ti ti-shield-lock"></i></span>
        </span>
      </a>

      <button class="button-sm-hover" type="button" aria-label="Réduire le menu">
        <i class="ti ti-circle align-middle"></i>
      </button>
      <button class="button-close-fullsidebar" type="button" aria-label="Fermer le menu">
        <i class="ti ti-x align-middle"></i>
      </button>

      <div data-simplebar>
        <ul class="side-nav">
          <li class="side-nav-title mt-2">Supervision</li>
          ${items
            .map(
              (item) => `
            <li class="side-nav-item">
              <a href="${item.href}" class="side-nav-link ${active === item.key ? 'active' : ''}">
                <span class="menu-icon"><i class="ti ${item.icon}"></i></span>
                <span class="menu-text">${item.label}</span>
              </a>
            </li>`,
            )
            .join('')}
        </ul>
        <div class="clearfix"></div>
      </div>

      <div class="p-3 mt-auto">
        <div class="border border-dashed rounded p-3">
          <p class="text-muted fs-12 mb-1 text-uppercase fw-semibold">Source de données</p>
          <div class="d-flex align-items-center gap-2">
            <span class="badge bg-success-subtle text-success">API</span>
            <span class="fs-13 fw-semibold">SentinelOne</span>
          </div>
        </div>
      </div>`;
  }

  function buildTopbar() {
    return `
      <div class="page-container topbar-menu">
        <div class="d-flex align-items-center gap-2">
          <button class="sidenav-toggle-button btn btn-secondary btn-icon" type="button" aria-label="Menu">
            <i class="ti ti-menu-deep fs-24"></i>
          </button>
          <div class="d-none d-md-flex align-items-center gap-2 ms-2">
            <span class="text-muted fs-13">Console SentinelOne</span>
            <span class="badge bg-primary-subtle text-primary">Supervision</span>
          </div>
        </div>

        <div class="d-flex align-items-center gap-2 ms-auto">
          <button class="btn btn-outline-primary btn-icon" id="soc-refresh" type="button" title="Rafraîchir les données" aria-label="Rafraîchir">
            <i class="ti ti-refresh fs-20"></i>
          </button>
          <button class="btn btn-outline-primary btn-icon" id="light-dark-mode" type="button" title="Thème" aria-label="Changer de thème">
            <i class="ti ti-moon fs-20"></i>
          </button>
          <div class="topbar-item dropdown">
            <button class="topbar-link btn btn-outline-primary dropdown-toggle drop-arrow-none" data-bs-toggle="dropdown" data-bs-offset="0,22" type="button" aria-haspopup="false" aria-expanded="false">
              <span class="avatar-title bg-primary text-white rounded-circle fs-14" style="width:26px;height:26px" data-soc-initials>?</span>
              <span class="d-lg-flex flex-column gap-1 d-none ms-lg-2 text-start">
                <span class="fs-13 fw-semibold" data-soc-user>Utilisateur</span>
                <span class="fs-11 text-muted" data-soc-role>—</span>
              </span>
              <i class="ti ti-chevron-down d-none d-lg-block align-middle ms-2"></i>
            </button>
            <div class="dropdown-menu dropdown-menu-end">
              <div class="dropdown-header noti-title">
                <h6 class="text-overflow m-0">Connecté</h6>
                <span class="fs-12 text-muted" data-soc-email>—</span>
              </div>
              <div class="dropdown-divider"></div>
              <button class="dropdown-item active fw-semibold text-danger" id="soc-logout" type="button">
                <i class="ti ti-logout me-1 fs-17 align-middle"></i>
                <span class="align-middle">Se déconnecter</span>
              </button>
            </div>
          </div>
        </div>
      </div>`;
  }

  function applyUser(user) {
    state.user = user;
    const initials = String(user.displayName || user.username || '?')
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0].toUpperCase())
      .join('');
    document.querySelectorAll('[data-soc-user]').forEach((el) => {
      el.textContent = user.displayName || user.username;
    });
    document.querySelectorAll('[data-soc-initials]').forEach((el) => {
      el.textContent = initials || '?';
    });
    document.querySelectorAll('[data-soc-role]').forEach((el) => {
      el.textContent = user.role === 'admin' ? 'Administrateur' : 'Analyste';
    });
    document.querySelectorAll('[data-soc-email]').forEach((el) => {
      el.textContent = user.email || 'Active Directory';
    });
  }

  const MIGRATION_DISMISS_KEY = 'soc_migration_banner_dismissed_v1';

  function migrationDismissed() {
    try {
      return window.localStorage.getItem(MIGRATION_DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  }

  function dismissMigrationBanner() {
    try {
      window.localStorage.setItem(MIGRATION_DISMISS_KEY, '1');
    } catch {
      // stockage indisponible — masquage pour la session seule
    }
  }

  function renderMigrationBanner(migration) {
    if (!migration || !migration.enabled || migrationDismissed()) return;
    const pageContent = document.querySelector('.page-content');
    if (!pageContent || document.getElementById('soc-migration-banner')) return;

    const learnMore = migration.docUrl
      ? `<a href="${escapeHtml(migration.docUrl)}" target="_blank" rel="noopener noreferrer" class="alert-link ms-1">En savoir plus</a>`
      : '';

    const alert = document.createElement('div');
    alert.id = 'soc-migration-banner';
    alert.className = 'alert alert-info d-flex align-items-start gap-2 mt-3 mb-0';
    alert.setAttribute('role', 'status');
    alert.innerHTML = `
      <i class="ti ti-info-circle fs-20 mt-1"></i>
      <div class="flex-grow-1">
        <strong>Singularity™ Operations Center</strong> deviendra l’expérience par défaut le
        <strong>${escapeHtml(formatLongDate(migration.defaultDate))}</strong>, avant le retrait de la
        console historique le <strong>${escapeHtml(formatLongDate(migration.retirementDate))}</strong>.
        Les API utilisées par cette plateforme restent inchangées.${learnMore}
      </div>
      <button type="button" class="btn-close" aria-label="Masquer cette information"></button>`;

    alert.querySelector('.btn-close').addEventListener('click', () => {
      dismissMigrationBanner();
      alert.remove();
    });

    const firstChild = pageContent.firstElementChild;
    pageContent.insertBefore(alert, firstChild);
  }

  async function initShell(active) {
    const sidebar = document.getElementById('soc-sidebar');
    const topbar = document.getElementById('soc-topbar');
    if (sidebar) sidebar.innerHTML = buildSidebar(active);
    if (topbar) topbar.innerHTML = buildTopbar();

    document.querySelectorAll('[data-soc-year]').forEach((el) => {
      el.textContent = String(new Date().getFullYear());
    });

    const logout = document.getElementById('soc-logout');
    if (logout) {
      logout.addEventListener('click', async () => {
        try {
          await api('/api/auth/logout', { method: 'POST' });
        } finally {
          window.location.replace('/login');
        }
      });
    }

    const refresh = document.getElementById('soc-refresh');
    if (refresh) {
      refresh.addEventListener('click', async () => {
        if (refresh.disabled) return;
        refresh.disabled = true;
        const icon = refresh.querySelector('i');
        if (icon) icon.classList.add('soc-spin');
        try {
          await Promise.all(REFRESH_HANDLERS.map((handler) => handler()));
        } catch (error) {
          console.error('Refresh failed', error);
        } finally {
          refresh.disabled = false;
          if (icon) icon.classList.remove('soc-spin');
        }
      });
    }

    try {
      const payload = await api('/api/auth/me');
      applyUser(payload.user);
    } catch (error) {
      if (error.status !== 401) {
        console.error('Unable to load session', error);
      }
    }

    try {
      const settings = await api('/api/settings');
      state.settings = settings;
      renderMigrationBanner(settings.migration);
    } catch (error) {
      if (error.status !== 401) {
        console.error('Unable to load settings', error);
      }
    }
  }

  function createPager({ limit, prev, next, label, onPage, onError }) {
    const cursors = [null];
    let index = 0;
    let nextCursor = null;
    let busy = false;

    function render() {
      if (label) label.textContent = `Page ${index + 1}`;
      if (prev) prev.disabled = index === 0 || busy;
      if (next) next.disabled = !nextCursor || busy;
    }

    async function load() {
      if (busy) return;
      busy = true;
      render();
      try {
        const page = await onPage(cursors[index]);
        nextCursor = page && page.pagination ? page.pagination.nextCursor : null;
      } catch (error) {
        nextCursor = null;
        if (typeof onError === 'function') onError(error);
      } finally {
        busy = false;
        render();
      }
    }

    if (next) {
      next.addEventListener('click', () => {
        if (!nextCursor) return;
        cursors[index + 1] = nextCursor;
        index += 1;
        load();
      });
    }
    if (prev) {
      prev.addEventListener('click', () => {
        if (index === 0) return;
        index -= 1;
        cursors.length = index + 1;
        load();
      });
    }

    return {
      load,
      reset() {
        cursors.length = 1;
        cursors[0] = null;
        index = 0;
        nextCursor = null;
        return load();
      },
      get pageIndex() {
        return index;
      },
    };
  }

  function params(extra = {}) {
    const search = new URLSearchParams();
    Object.entries(extra).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
    });
    return search.toString();
  }

  window.SOC = {
    state,
    api,
    escapeHtml,
    formatNumber,
    formatDate,
    formatRelative,
    formatLongDate,
    severityBadge,
    agentStatusBadge,
    mitigationBadge,
    humanize,
    MITIGATION_LABELS,
    INCIDENT_LABELS,
    ALERT_STATUS_LABELS,
    showAlert,
    clearAlert,
    setLoading,
    emptyState,
    markUpdated,
    onRefresh,
    initShell,
    createPager,
    params,
  };
})();

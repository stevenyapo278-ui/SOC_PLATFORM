(function () {
  'use strict';

  SOC.initShell('settings');

  const els = {
    consoleUrl: document.querySelector('[data-settings-console-url]'),
    consoleLink: document.querySelector('[data-settings-console-link]'),
    token: document.querySelector('[data-settings-token]'),
    state: document.querySelector('[data-settings-state]'),
    testButton: document.getElementById('settings-test-s1'),
    testResult: document.getElementById('settings-test-result'),
    migrationStatus: document.querySelector('[data-settings-migration-status]'),
    migrationDefault: document.querySelector('[data-settings-migration-default]'),
    migrationRetirement: document.querySelector('[data-settings-migration-retirement]'),
    migrationBanner: document.querySelector('[data-settings-migration-banner]'),
    migrationDoc: document.querySelector('[data-settings-migration-doc]'),
    apiPath: document.querySelector('[data-settings-api-path]'),
    sampleLimit: document.querySelector('[data-settings-sample-limit]'),
    pageSize: document.querySelector('[data-settings-page-size]'),
    cacheTtl: document.querySelector('[data-settings-cache-ttl]'),
    tls: document.querySelector('[data-settings-tls]'),
  };

  function render(settings) {
    const consoleUrl = settings.consoleUrl || '';
    els.consoleUrl.textContent = consoleUrl || 'Non configurée (S1_URL)';
    if (consoleUrl) {
      els.consoleLink.href = consoleUrl;
      els.consoleLink.classList.remove('d-none');
    } else {
      els.consoleLink.classList.add('d-none');
    }

    els.token.textContent = settings.apiTokenMasked || 'Non configuré (S1_API_TOKEN)';
    els.state.innerHTML = settings.sentineloneConfigured
      ? '<span class="badge bg-success-subtle text-success"><i class="ti ti-circle-check me-1"></i>Configuré</span>'
      : '<span class="badge bg-warning-subtle text-warning"><i class="ti ti-alert-triangle me-1"></i>Non configuré</span>';

    const migration = settings.migration || {};
    const enabled = Boolean(migration.enabled);
    els.migrationStatus.innerHTML = enabled
      ? '<span class="badge bg-warning-subtle text-warning">Bannière active</span>'
      : '<span class="badge bg-secondary-subtle text-secondary">Bannière masquée</span>';
    els.migrationDefault.textContent = SOC.formatLongDate(migration.defaultDate);
    els.migrationRetirement.textContent = SOC.formatLongDate(migration.retirementDate);
    els.migrationBanner.textContent = enabled ? 'Affichée sur toutes les pages' : 'Désactivée (S1_MIGRATION_BANNER=false)';

    if (migration.docUrl) {
      els.migrationDoc.href = migration.docUrl;
      els.migrationDoc.classList.remove('d-none');
    } else {
      els.migrationDoc.classList.add('d-none');
    }

    els.apiPath.textContent = settings.apiBasePath || '—';
    els.sampleLimit.textContent = `${SOC.formatNumber(settings.sampleLimit)} menaces/endpoints lus max.`;
    els.pageSize.textContent = `${SOC.formatNumber(settings.defaultPageSize)} éléments`;
    els.cacheTtl.textContent = `${SOC.formatNumber(Math.round((settings.cacheTtlMs || 0) / 1000))} s`;
    els.tls.textContent = settings.tlsInsecure ? 'Vérification désactivée (S1_TLS_INSECURE)' : 'Vérification stricte';
    SOC.markUpdated();
  }

  async function load() {
    SOC.clearAlert('#settings-error');
    try {
      const settings = await SOC.api('/api/settings');
      render(settings);
    } catch (error) {
      SOC.showAlert('#settings-error', error.message || 'Impossible de charger les paramètres.');
    }
  }

  // Test réel de l'API SentinelOne (lecture seule, force le bypass du cache).
  async function testConnection() {
    if (!els.testButton) return;
    els.testButton.disabled = true;
    els.testResult.innerHTML = '<span class="spinner-border spinner-border-sm text-primary me-1"></span>Test de la connexion…';
    try {
      const response = await fetch('/api/health', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) {
        throw new Error(payload.message || `Erreur ${response.status}.`);
      }
      els.testResult.innerHTML = `<span class="text-success"><i class="ti ti-circle-check me-1"></i>${SOC.escapeHtml(payload.message || 'API SentinelOne joignable.')}</span>`;
    } catch (error) {
      els.testResult.innerHTML = `<span class="text-danger"><i class="ti ti-alert-triangle me-1"></i>${SOC.escapeHtml(error.message)}</span>`;
    } finally {
      els.testButton.disabled = false;
    }
  }

  if (els.testButton) els.testButton.addEventListener('click', testConnection);

  SOC.onRefresh(load);
  load();
})();

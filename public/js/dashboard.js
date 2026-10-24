(function () {
  'use strict';

  SOC.initShell('dashboard');

  const SEVERITY_COLORS = {
    critical: '#ed6060',
    high: '#ebb751',
    medium: '#60addf',
    low: '#669776',
    info: '#adb5bd',
    unknown: '#ced4da',
  };

  let lastData = null;
  let trendChart = null;
  let severityChart = null;

  function setText(selector, value) {
    const el = document.querySelector(selector);
    if (el) el.textContent = value;
  }

  function renderKpis(data) {
    const k = data.kpis;
    const approx = data.sampled.agents ? '≈ ' : '';

    setText('[data-kpi="agentsTotal"]', SOC.formatNumber(k.agentsTotal));
    setText(
      '[data-kpi-sub="agents"]',
      `${approx}${SOC.formatNumber(k.agentsOnline)} en ligne${data.sampled.agents ? ' (échantillon)' : ''}`,
    );

    setText('[data-kpi="threatsTotal"]', SOC.formatNumber(k.threatsTotal));
    setText(
      '[data-kpi-sub="threats"]',
      `${SOC.formatNumber(k.threatsActiveSample)} non traitées · ${SOC.formatNumber(k.threatsHighCriticalSample)} hautes`,
    );

    setText('[data-kpi="alertsTotal"]', SOC.formatNumber(k.alertsTotal));
    setText('[data-kpi-sub="alerts"]', `${SOC.formatNumber(k.alertsOpenSample)} ouverte(s) sur l’échantillon`);

    setText('[data-kpi="agentsInfected"]', SOC.formatNumber(k.agentsInfectedSample));
    setText('[data-kpi-sub="infected"]', `sur ${SOC.formatNumber(k.agentsTotal)} endpoints`);
  }

  function themeColors() {
    const dark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    return {
      dark,
      text: dark ? '#9aa0a6' : '#6c757d',
      grid: dark ? '#2b2f38' : '#e9ecef',
      tooltip: dark ? 'dark' : 'light',
    };
  }

  function destroyCharts() {
    if (trendChart) {
      trendChart.destroy();
      trendChart = null;
    }
    if (severityChart) {
      severityChart.destroy();
      severityChart = null;
    }
  }

  function renderCharts(data) {
    if (typeof ApexCharts === 'undefined') return;

    destroyCharts();
    const colors = themeColors();

    const trendEl = document.getElementById('threat-trend-chart');
    const severityEl = document.getElementById('severity-chart');
    if (!trendEl || !severityEl) return;

    trendEl.innerHTML = '';
    trendChart = new ApexCharts(trendEl, {
      chart: {
        type: 'area',
        height: 280,
        fontFamily: 'inherit',
        toolbar: { show: false },
        animations: { enabled: false },
        background: 'transparent',
      },
      series: [{ name: 'Menaces', data: data.threatTrend.map((point) => point.count) }],
      colors: ['#ed6060'],
      stroke: { curve: 'smooth', width: 2 },
      fill: {
        type: 'gradient',
        gradient: { shadeIntensity: 1, opacityFrom: 0.35, opacityTo: 0.03, stops: [0, 90, 100] },
      },
      dataLabels: { enabled: false },
      grid: { borderColor: colors.grid, strokeDashArray: 4, padding: { left: 8, right: 8 } },
      xaxis: {
        categories: data.threatTrend.map((point) => {
          const date = new Date(`${point.date}T00:00:00Z`);
          return date.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' });
        }),
        axisBorder: { show: false },
        axisTicks: { show: false },
        labels: { style: { colors: colors.text, fontSize: '11px' } },
      },
      yaxis: {
        minInterval: 1,
        labels: { style: { colors: colors.text, fontSize: '11px' } },
      },
      tooltip: {
        theme: colors.tooltip,
        y: { formatter: (value) => `${value} menace(s)` },
      },
    });
    trendChart.render();

    const entries = data.severityOrder
      .map((key) => [key, data.severity[key] || 0])
      .filter(([, count]) => count > 0);

    severityEl.innerHTML = '';
    if (entries.length === 0) {
      severityEl.innerHTML = SOC.emptyState('Aucune menace dans l’échantillon', 'ti-shield-check');
      return;
    }

    severityChart = new ApexCharts(severityEl, {
      chart: {
        type: 'donut',
        height: 280,
        fontFamily: 'inherit',
        animations: { enabled: false },
        background: 'transparent',
      },
      series: entries.map(([, count]) => count),
      labels: entries.map(([key]) => {
        const labels = {
          critical: 'Critique',
          high: 'Élevée',
          medium: 'Moyenne',
          low: 'Faible',
          info: 'Info',
          unknown: 'Inconnue',
        };
        return labels[key] || key;
      }),
      colors: entries.map(([key]) => SEVERITY_COLORS[key] || SEVERITY_COLORS.unknown),
      legend: {
        position: 'bottom',
        labels: { colors: colors.text },
        fontSize: '12px',
        markers: { size: 6 },
      },
      dataLabels: { enabled: true, style: { fontSize: '11px' } },
      stroke: { width: 0 },
      plotOptions: {
        pie: { donut: { size: '68%', labels: { show: true, total: { show: true, label: 'Menaces' } } } },
      },
      tooltip: { theme: colors.tooltip },
    });
    severityChart.render();
  }

  function renderRecentThreats(threats) {
    const body = document.getElementById('recent-threats-body');
    if (!body) return;
    if (!threats.length) {
      body.innerHTML = `<tr><td colspan="4">${SOC.emptyState('Aucune menace récente', 'ti-shield-check')}</td></tr>`;
      return;
    }
    body.innerHTML = threats
      .map(
        (threat) => `<tr>
          <td>
            <span class="fw-semibold d-block soc-truncate" title="${SOC.escapeHtml(threat.name)}">${SOC.escapeHtml(threat.name)}</span>
            <span class="text-muted fs-12">${SOC.escapeHtml(threat.classification)}</span>
          </td>
          <td>${SOC.severityBadge(threat.severity)}</td>
          <td>${SOC.escapeHtml(threat.agentName)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(threat.createdAt)}</td>
        </tr>`,
      )
      .join('');
  }

  function renderRecentAlerts(alerts) {
    const list = document.getElementById('recent-alerts-list');
    if (!list) return;
    if (!alerts.length) {
      list.innerHTML = SOC.emptyState('Aucune alerte récente', 'ti-bell-off');
      return;
    }
    list.innerHTML = alerts
      .map(
        (alert) => `<div class="list-group-item soc-list-item border-0 px-3 py-3">
          <div class="d-flex align-items-start justify-content-between gap-2">
            <div class="min-w-0">
              <div class="fw-semibold fs-14 text-truncate" title="${SOC.escapeHtml(alert.name)}">${SOC.escapeHtml(alert.name)}</div>
              <div class="text-muted fs-12 mt-1">
                <i class="ti ti-devices me-1"></i>${SOC.escapeHtml(alert.agentName)}
              </div>
            </div>
            <div class="text-end flex-shrink-0">
              ${SOC.severityBadge(alert.severity)}
              <div class="text-muted fs-11 mt-1">${SOC.formatRelative(alert.detectedAt)}</div>
            </div>
          </div>
        </div>`,
      )
      .join('');
  }

  function renderRecentActivities(activities) {
    const body = document.getElementById('recent-activities-body');
    if (!body) return;
    if (!activities.length) {
      body.innerHTML = `<tr><td colspan="4">${SOC.emptyState('Aucune activité récente', 'ti-history')}</td></tr>`;
      return;
    }
    body.innerHTML = activities
      .map(
        (activity) => `<tr>
          <td class="soc-activity-description">
            <span class="d-block text-truncate" title="${SOC.escapeHtml(activity.description)}">${SOC.escapeHtml(activity.description)}</span>
            ${activity.details ? `<span class="text-muted fs-12 d-block text-truncate">${SOC.escapeHtml(activity.details)}</span>` : ''}
          </td>
          <td>${SOC.escapeHtml(activity.agentName || '—')}</td>
          <td class="text-muted">${SOC.escapeHtml(activity.site)}</td>
          <td class="text-muted fs-13">${SOC.formatDate(activity.createdAt)}</td>
        </tr>`,
      )
      .join('');
  }

  function renderWarnings(warnings) {
    const container = document.getElementById('dashboard-warning');
    if (!container) return;
    if (!warnings || warnings.length === 0) {
      container.innerHTML = '';
      return;
    }
    const labels = { agents: 'endpoints', threats: 'menaces', alerts: 'alertes', activities: 'activités' };
    const message = warnings
      .map((warning) => `${labels[warning.source] || warning.source} : ${warning.message}`)
      .join(' ');
    SOC.showAlert('#dashboard-warning', `Données partielles — ${message}`, 'warning');
  }

  async function load(force = false) {
    SOC.clearAlert('#dashboard-error');
    try {
      const data = await SOC.api(`/api/overview${force ? '?refresh=1' : ''}`);
      lastData = data;
      renderKpis(data);
      renderCharts(data);
      renderRecentThreats(data.recentThreats);
      renderRecentAlerts(data.recentAlerts);
      renderRecentActivities(data.recentActivities);
      renderWarnings(data.warnings);
      SOC.markUpdated();
    } catch (error) {
      SOC.showAlert('#dashboard-error', error.message || 'Impossible de charger les données SentinelOne.');
    }
  }

  SOC.onRefresh(() => load(true));
  load();

  const observer = new MutationObserver(() => {
    if (lastData) renderCharts(lastData);
  });
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });
})();

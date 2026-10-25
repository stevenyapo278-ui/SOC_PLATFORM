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

  // Heatmap + radar (Lot 2) : état de rendu conservé pour re-peindre au
  // changement de thème sans re-toucher l'API.
  let lastHeatmap = null;
  let lastRadar = null;
  let heatmapChart = null;
  let radarChart = null;
  const heatmapState = { entity: 'threats', range: '7d' };

  // Intensité de la heatmap (densité de détections, pas gravité).
  const HEATMAP_LEGEND = [
    { label: 'Aucune', color: '#e9ecef', darkColor: '#2b2f38' },
    { label: 'Faible', color: '#fdd0a2' },
    { label: 'Modéré', color: '#fdae6b' },
    { label: 'Élevé', color: '#fd8d3c' },
    { label: 'Très élevé', color: '#d94801' },
  ];

  // Libellés courts pour les axes autour du radar (les libellés complets sont
  // dans la liste en dessous, avec le détail chiffré).
  const RADAR_SHORT = {
    online: 'En ligne',
    clean: 'Sans menace',
    aligned: 'Version',
    mitigated: 'Atténuées',
    closed: 'Clôturées',
    inventoried: 'Inventaire',
  };

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

  function heatmapRanges(max, dark) {
    const neutral = dark ? '#2b2f38' : '#e9ecef';
    if (!max) return [{ from: 0, to: 0, color: neutral, name: 'Aucune' }];
    const step = max / 4;
    return [
      { from: 0, to: 0, color: neutral, name: 'Aucune' },
      { from: 0.0001, to: step, color: '#fdd0a2', name: 'Faible' },
      { from: step, to: step * 2, color: '#fdae6b', name: 'Modéré' },
      { from: step * 2, to: step * 3, color: '#fd8d3c', name: 'Élevé' },
      { from: step * 3, to: max, color: '#d94801', name: 'Très élevé' },
    ];
  }

  function dayLabel(day) {
    const date = new Date(`${day}T00:00:00Z`);
    if (Number.isNaN(date.getTime())) return day;
    return date.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' });
  }

  function renderHeatmapLegend(dark) {
    const legend = document.getElementById('heatmap-legend');
    if (!legend) return;
    legend.innerHTML = HEATMAP_LEGEND.map(
      (item, index) =>
        `<span class="d-inline-flex align-items-center gap-1">
           <span class="soc-legend-swatch" style="background:${index === 0 && dark ? item.darkColor : item.color}"></span>
           ${item.label}
         </span>`,
    ).join('');
  }

  function scoreClass(score) {
    if (score === null || score === undefined) return 'text-muted';
    if (score >= 70) return 'text-success';
    if (score >= 40) return 'text-warning';
    return 'text-danger';
  }

  function renderHeatmap(data) {
    const el = document.getElementById('heatmap-chart');
    const caption = document.getElementById('heatmap-caption');
    if (!el) return;

    if (heatmapChart) {
      heatmapChart.destroy();
      heatmapChart = null;
    }
    el.innerHTML = '';

    const suffix = `${SOC.formatNumber(data.total)} ${data.entityLabel} sur ${data.days.length} jours`;
    if (caption) {
      caption.textContent = data.sampled ? `≈ échantillon SentinelOne — ${suffix}` : `${suffix} — base PostgreSQL`;
    }
    renderHeatmapLegend(themeColors().dark);

    if (typeof ApexCharts === 'undefined') return;

    if (!data.cells.length) {
      el.innerHTML = SOC.emptyState(
        `Aucune ${data.entityLabel} sur les ${data.days.length} derniers jours`,
        'ti-calendar-off',
      );
      return;
    }

    const colors = themeColors();
    const values = new Map(data.cells.map((cell) => [`${cell.day}:${cell.hour}`, cell.count]));
    const singular = data.entityLabel.replace(/s$/, '');
    const series = data.days.map((day) => ({
      name: dayLabel(day),
      data: data.hours.map((hour) => values.get(`${day}:${hour}`) || 0),
    }));

    heatmapChart = new ApexCharts(el, {
      chart: {
        type: 'heatmap',
        height: data.days.length > 7 ? 560 : 460,
        fontFamily: 'inherit',
        toolbar: { show: false },
        animations: { enabled: false },
        background: 'transparent',
      },
      series,
      colors: ['#fd8d3c'],
      dataLabels: { enabled: false },
      plotOptions: {
        heatmap: {
          radius: 2,
          enableShades: false,
          colorScale: { ranges: heatmapRanges(data.max, colors.dark) },
        },
      },
      legend: { show: false },
      xaxis: {
        categories: data.hours.map((hour) => (hour % 3 === 0 ? String(hour).padStart(2, '0') : '')),
        axisBorder: { show: false },
        axisTicks: { show: false },
        labels: { style: { colors: colors.text, fontSize: '10px' } },
      },
      yaxis: { labels: { style: { colors: colors.text, fontSize: '10px' } } },
      grid: { show: false },
      tooltip: {
        theme: colors.tooltip,
        x: { show: false },
        y: {
          formatter: (value, opts) => {
            const hour = String(opts.dataPointIndex).padStart(2, '0');
            return value
              ? `${value} ${singular} à ${hour}h`
              : `Aucun(e) ${singular} à ${hour}h`;
          },
        },
      },
    });
    heatmapChart.render();
  }

  function renderRadar(data) {
    const el = document.getElementById('radar-chart');
    const caption = document.getElementById('radar-caption');
    const scoreEl = document.getElementById('radar-score');
    const list = document.getElementById('radar-axes');
    if (!el) return;

    if (radarChart) {
      radarChart.destroy();
      radarChart = null;
    }
    el.innerHTML = '';

    const available = data.axes.filter((axis) => axis.available).length;
    if (caption) {
      const source = data.sampled ? '≈ échantillon SentinelOne' : 'Base PostgreSQL';
      caption.textContent = `${source} — ${available}/${data.axes.length} axes`;
    }
    if (scoreEl) {
      scoreEl.textContent = data.score === null || data.score === undefined ? '—' : String(data.score);
      scoreEl.className = `fs-28 fw-bold lh-1 ${scoreClass(data.score)}`;
    }
    if (list) {
      list.innerHTML = data.axes
        .map(
          (axis) => `<li class="soc-radar-axis py-1">
            <div class="d-flex justify-content-between gap-2">
              <span class="fs-12 text-truncate" title="${SOC.escapeHtml(axis.detail)}">${SOC.escapeHtml(axis.label)}</span>
              <span class="fs-12 fw-semibold flex-shrink-0">${axis.available ? `${axis.value} %` : '—'}</span>
            </div>
            <div class="fs-11 text-muted text-truncate" title="${SOC.escapeHtml(axis.detail)}">${SOC.escapeHtml(axis.detail)}</div>
          </li>`,
        )
        .join('');
    }

    if (typeof ApexCharts === 'undefined' || !data.axes.length) return;

    const colors = themeColors();
    radarChart = new ApexCharts(el, {
      chart: {
        type: 'radar',
        height: 300,
        fontFamily: 'inherit',
        toolbar: { show: false },
        animations: { enabled: false },
        background: 'transparent',
      },
      series: [{ name: 'Posture', data: data.axes.map((axis) => (axis.available ? axis.value : 0)) }],
      labels: data.axes.map((axis) => RADAR_SHORT[axis.key] || axis.label),
      colors: ['#39afd1'],
      markers: { size: 3, colors: ['#39afd1'], strokeColors: colors.dark ? '#0b0e14' : '#ffffff', hover: { size: 4 } },
      stroke: { width: 2 },
      fill: { opacity: 0.18 },
      dataLabels: { enabled: false },
      legend: { show: false },
      plotOptions: {
        radar: {
          polygons: {
            strokeColors: colors.grid,
            connectorColors: colors.grid,
            fill: { colors: ['transparent'] },
          },
        },
      },
      yaxis: {
        min: 0,
        max: 100,
        tickAmount: 4,
        labels: { formatter: (value) => `${value}%`, style: { colors: colors.text, fontSize: '9px' } },
      },
      tooltip: { theme: colors.tooltip, y: { formatter: (value) => `${value} %` } },
    });
    radarChart.render();
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

  async function loadHeatmap(force = false) {
    SOC.clearAlert('#heatmap-error');
    try {
      const params = new URLSearchParams({ entity: heatmapState.entity, range: heatmapState.range });
      if (force) params.set('refresh', '1');
      const data = await SOC.api(`/api/stats/heatmap?${params.toString()}`);
      lastHeatmap = data;
      renderHeatmap(data);
    } catch (error) {
      SOC.showAlert('#heatmap-error', error.message || 'Impossible de charger la heatmap des détections.');
    }
  }

  async function loadRadar(force = false) {
    SOC.clearAlert('#radar-error');
    try {
      const data = await SOC.api(`/api/stats/radar${force ? '?refresh=1' : ''}`);
      lastRadar = data;
      renderRadar(data);
    } catch (error) {
      SOC.showAlert('#radar-error', error.message || 'Impossible de charger le radar de posture.');
    }
  }

  async function load(force = false) {
    SOC.clearAlert('#dashboard-error');
    // Stats agrégées en parallèle : elles ont leurs propres emplacements
    // d'erreur et ne doivent pas retarder les KPI.
    loadHeatmap(force);
    loadRadar(force);
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

  const entitySelect = document.getElementById('heatmap-entity');
  if (entitySelect) {
    entitySelect.addEventListener('change', () => {
      heatmapState.entity = entitySelect.value;
      loadHeatmap(false);
    });
  }
  document.querySelectorAll('input[name="heatmap-range"]').forEach((input) => {
    input.addEventListener('change', () => {
      if (!input.checked) return;
      heatmapState.range = input.value;
      loadHeatmap(false);
    });
  });

  SOC.onRefresh(() => load(true));
  load();

  const observer = new MutationObserver(() => {
    if (lastData) renderCharts(lastData);
    if (lastHeatmap) renderHeatmap(lastHeatmap);
    if (lastRadar) renderRadar(lastRadar);
  });
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });
})();

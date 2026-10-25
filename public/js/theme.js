(function () {
  'use strict';

  var STORAGE_KEY = 'soc-theme';
  var html = document.documentElement;

  function read(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (error) {
      return null;
    }
  }

  function sessionTheme() {
    try {
      var raw = window.sessionStorage.getItem('__BORON_CONFIG__');
      var theme = raw ? JSON.parse(raw).theme : null;
      return theme === 'dark' || theme === 'light' ? theme : null;
    } catch (error) {
      return null;
    }
  }

  function apply(theme) {
    if (theme !== 'dark' && theme !== 'light') return;
    html.setAttribute('data-bs-theme', theme);
    if (window.config && typeof window.config === 'object') window.config.theme = theme;
  }

  // Appliqué avant le rendu : aucun flash du thème clair.
  var stored = read(STORAGE_KEY);
  apply(stored || sessionTheme());

  window.SOC_THEME = {
    key: STORAGE_KEY,
    get: function () {
      return html.getAttribute('data-bs-theme') === 'dark' ? 'dark' : 'light';
    },
    set: function (theme) {
      apply(theme);
      try {
        window.localStorage.setItem(STORAGE_KEY, theme);
      } catch (error) {
        /* stockage indisponible */
      }
    },
  };
})();

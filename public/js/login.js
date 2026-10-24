(function () {
  'use strict';

  const form = document.getElementById('login-form');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const errorBox = document.getElementById('login-error');
  const submit = document.getElementById('login-submit');
  const submitLabel = document.getElementById('login-submit-label');
  const spinner = document.getElementById('login-spinner');
  const toggle = document.getElementById('toggle-password');

  document.querySelectorAll('[data-soc-year]').forEach((el) => {
    el.textContent = String(new Date().getFullYear());
  });

  function showError(message) {
    errorBox.innerHTML = '';
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger d-flex align-items-start gap-2';
    alert.setAttribute('role', 'alert');
    const icon = document.createElement('i');
    icon.className = 'ti ti-alert-triangle fs-18';
    const text = document.createElement('div');
    text.textContent = message;
    alert.append(icon, text);
    errorBox.append(alert);
  }

  function clearError() {
    errorBox.innerHTML = '';
  }

  function setBusy(busy) {
    submit.disabled = busy;
    usernameInput.disabled = busy;
    passwordInput.disabled = busy;
    submitLabel.textContent = busy ? 'Connexion…' : 'Se connecter';
    spinner.classList.toggle('d-none', !busy);
  }

  function safeNext() {
    const next = new URLSearchParams(window.location.search).get('next');
    if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/login')) return '/';
    return next;
  }

  if (toggle) {
    toggle.addEventListener('click', () => {
      const visible = passwordInput.type === 'text';
      passwordInput.type = visible ? 'password' : 'text';
      toggle.querySelector('i').className = visible ? 'ti ti-eye fs-17' : 'ti ti-eye-off fs-17';
      toggle.setAttribute('aria-label', visible ? 'Afficher le mot de passe' : 'Masquer le mot de passe');
    });
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearError();

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      showError('Renseignez votre identifiant AD et votre mot de passe.');
      return;
    }

    setBusy(true);
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (!response.ok) {
        const message =
          response.status === 429
            ? 'Trop de tentatives. Patientez quelques minutes avant de réessayer.'
            : (payload && payload.error) || `Connexion impossible (HTTP ${response.status}).`;
        showError(message);
        passwordInput.value = '';
        passwordInput.focus();
        return;
      }

      window.location.replace(safeNext());
    } catch (error) {
      showError('Serveur injoignable. Vérifiez votre connexion réseau puis réessayez.');
      console.error(error);
    } finally {
      setBusy(false);
    }
  });

  usernameInput.focus();
})();

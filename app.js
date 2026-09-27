fetch('/api/me', { credentials: 'same-origin' })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    const status = document.getElementById('status');
    status.textContent = user
      ? `Sessão de ${user.email ?? user.displayName ?? user.name ?? 'usuário'}.`
      : 'Nenhuma sessão neste navegador.';
  });

const form = document.getElementById('logout-form');
if (form) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const status = document.getElementById('status');

    try {
      const response = await fetch('/oauth/logout', {
        method: 'POST',
        credentials: 'same-origin',
      });

      if (response.ok) {
        status.textContent = 'Sessão encerrada.';
      } else {
        status.textContent = 'Falha ao encerrar a sessão.';
      }
    } catch (error) {
      status.textContent = 'Não foi possível encerrar a sessão.';
    }
  });
}

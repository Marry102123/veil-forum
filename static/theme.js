/* veil-forum theme */
(() => {
  const KEY = 'veil-theme';
  const apply = (theme) => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(KEY, theme); } catch {}
    try { document.cookie = `theme=${theme}; Path=/; Max-Age=31536000; SameSite=Lax`; } catch {}
    const button = document.getElementById('theme-toggle');
    if (button) button.textContent = theme === 'light' ? '☾' : '☼';
  };
  const saved = (() => {
    try {
      const value = localStorage.getItem(KEY);
      if (value === 'light' || value === 'dark') return value;
    } catch {}
    return null;
  })();
  apply(saved || (window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  const button = document.getElementById('theme-toggle');
  button?.addEventListener('click', () => {
    apply(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
  });
})();

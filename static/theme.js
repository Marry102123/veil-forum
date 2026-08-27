/* veil-forum theme — 高密度极简，FOUC-free */
(() => {
  const KEY = 'veil-theme';
  const LEGACY = 'sf-theme';
  const apply = (t) => {
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem(KEY, t); } catch {}
    try { document.cookie = `theme=${t}; Path=/; Max-Age=31536000; SameSite=Lax`; } catch {}
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = t === 'light' ? '☾' : '☼';
  };
  const getSaved = () => {
    try {
      let v = localStorage.getItem(KEY);
      if (v === 'light' || v === 'dark') return v;
      v = localStorage.getItem(LEGACY);
      if (v === 'light' || v === 'dark') { try{localStorage.setItem(KEY,v)}catch{}; return v; }
      const m = document.cookie.match(/(?:^|;\s*)theme=(light|dark)/);
      if (m) return m[1];
    } catch {}
    return null;
  };
  // early apply if not yet set (inline script already did, but double-check)
  const ensure = () => {
    if (document.documentElement.dataset.theme) return;
    const saved = getSaved();
    if (saved) { apply(saved); return; }
    const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    apply(prefersLight ? 'light' : 'dark');
  };
  ensure();

  const wire = () => {
    const cur = document.documentElement.dataset.theme || getSaved() || 'dark';
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.textContent = cur === 'light' ? '☾' : '☼';
      btn.addEventListener('click', () => {
        const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
        apply(next);
      });
    }
    // 系统跟随：仅当用户未手动选择时
    try {
      if (!localStorage.getItem(KEY) && !localStorage.getItem(LEGACY) && window.matchMedia) {
        const mq = window.matchMedia('(prefers-color-scheme: light)');
        const onChange = (e) => {
          try { if (localStorage.getItem(KEY) || localStorage.getItem(LEGACY)) return; } catch {}
          apply(e.matches ? 'light' : 'dark');
        };
        if (mq.addEventListener) mq.addEventListener('change', onChange);
        else if (mq.addListener) mq.addListener(onChange);
      }
    } catch {}
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();

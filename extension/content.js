/*
  content.js — Injected into every webpage
  =========================================
  Adds a live password-strength badge next to every <input type="password">
  it finds. The badge calls the Flask /api/strength/check endpoint and
  updates in real time as the user types — no login required for this feature.
*/

(function () {
  if (window.__pmInjected) return;
  window.__pmInjected = true;

  const SERVER   = 'http://127.0.0.1:5000';
  const COLORS   = ['#dc3545','#fd7e14','#ffc107','#28a745','#20c997'];
  const LABELS   = ['Very Weak','Weak','Fair','Strong','Very Strong'];

  function injectBadge(input) {
    if (input.dataset.pmBadge) return;
    input.dataset.pmBadge = '1';

    // Ensure parent is relatively positioned so we can overlay the badge
    const parent = input.parentElement;
    if (getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }

    const badge = document.createElement('span');
    badge.style.cssText = `
      position:absolute; right:8px; top:50%; transform:translateY(-50%);
      font-size:11px; font-weight:700; padding:2px 6px; border-radius:4px;
      pointer-events:none; z-index:2147483647;
      background:#1e2d4d; color:#fff; white-space:nowrap; display:none;
    `;
    parent.appendChild(badge);

    let debounce;
    input.addEventListener('input', () => {
      clearTimeout(debounce);
      const pw = input.value;
      if (!pw) { badge.style.display = 'none'; return; }

      debounce = setTimeout(async () => {
        try {
          const res  = await fetch(SERVER + '/api/strength/check', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ password: pw }),
          });
          const data = await res.json();
          if (data.score !== undefined) {
            badge.textContent      = LABELS[data.score];
            badge.style.background = COLORS[data.score];
            badge.style.display    = 'inline';
          }
        } catch (_) { /* Flask not running — silently skip */ }
      }, 300);  // 300 ms debounce
    });
  }

  // Scan existing inputs and watch for new ones added dynamically (SPAs)
  function scanAll() {
    document.querySelectorAll('input[type="password"]').forEach(injectBadge);
  }

  scanAll();
  new MutationObserver(scanAll).observe(document.body, { childList: true, subtree: true });
})();

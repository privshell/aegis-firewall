'use strict';
/* Support card, added under About in the Settings tab. */
(function () {
  const DONATE_URL = 'https://github.com/privshell/privshell/blob/main/DONATE.md';
  function openDonate() {
    if (window.ksu && typeof window.ksu.exec === 'function') {
      const cb = `__support_cb_${Date.now()}`;
      window[cb] = () => { delete window[cb]; };
      try { window.ksu.exec(`am start -a android.intent.action.VIEW -d '${DONATE_URL}' >/dev/null 2>&1`, '{}', cb); } catch (e) { delete window[cb]; }
    } else {
      window.open(DONATE_URL, '_blank', 'noopener');
    }
  }
  function inject(box) {
    const last = box.lastElementChild;
    if (!last || box.querySelector('[data-support]')) return;
    const card = document.createElement('div');
    card.className = last.className;
    card.setAttribute('data-support', '');
    card.innerHTML = '<h3>Support</h3>' +
      '<p class="hint">Free and open source, built in spare time. If it saved you time, a small crypto donation keeps it going. A star or a clear bug report helps just as much.</p>' +
      '<button class="ghost" style="width:100%">Donate</button>';
    card.querySelector('button').addEventListener('click', openDonate);
    box.appendChild(card);
  }
  const box = document.getElementById('settingsBox');
  if (!box) return;
  new MutationObserver(() => inject(box)).observe(box, { childList: true });
  inject(box);
})();

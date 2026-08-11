(() => {
  'use strict';

  const screen = document.querySelector('[data-role="launch-screen"]');
  const status = document.querySelector('[data-role="launch-status"]');
  if (!screen) return;

  let dismissed = false;
  const shownAt = window.performance.now();
  const minimumVisibleMilliseconds = 820;
  const dismiss = (message) => {
    if (dismissed) return;
    dismissed = true;
    if (message && status) status.textContent = message;
    const elapsed = window.performance.now() - shownAt;
    const remaining = Math.max(0, minimumVisibleMilliseconds - elapsed);
    window.setTimeout(() => {
      screen.classList.add('launch-screen--leaving');
      window.setTimeout(() => screen.remove(), 460);
    }, remaining);
  };

  const finishStartup = () => dismiss('Hazır');
  if (document.readyState === 'complete') {
    finishStartup();
  } else {
    window.addEventListener('load', finishStartup, { once: true });
  }

  window.setTimeout(() => {
    if (!dismissed && status) status.textContent = 'Güvenlik arayüzü hazırlanıyor';
  }, 1200);
})();

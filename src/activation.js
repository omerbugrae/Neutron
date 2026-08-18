'use strict';

// Renderer for the standalone activation window. Deliberately tiny and
// independent of renderer.js: this window has to work when the main UI is
// blocked or was never opened, so it shares no state with it.

const api = window.neutron;
const deviceOutput = document.querySelector('[data-role="device"]');
const keyInput = document.querySelector('[data-role="key"]');
const activateButton = document.querySelector('[data-role="activate"]');
const closeButton = document.querySelector('[data-role="close"]');
const statusOutput = document.querySelector('[data-role="status"]');
const banner = document.querySelector('[data-role="banner"]');

function setStatus(message, tone = '') {
  statusOutput.textContent = message || '';
  statusOutput.className = `status ${tone}`.trim();
}

// Why this window opened. The main process passes it as a query string
// because the window may be created long before any IPC listener is ready.
const REASONS = {
  expired: 'Neutron lisansınızın süresi doldu. Tüm korumalar durduruldu ve bu bilgisayar şu anda Neutron tarafından korunmuyor.',
  missing: 'Bu bilgisayarda geçerli bir Neutron lisansı bulunamadı. Korumalar başlatılmadı.',
  invalid: 'Neutron lisansı doğrulanamadı. Tüm korumalar durduruldu ve bu bilgisayar şu anda Neutron tarafından korunmuyor.',
  reminder: 'Neutron hâlâ etkinleştirilmedi. Korumalar kapalı kalmaya devam ediyor.',
};

const reason = new URLSearchParams(window.location.search).get('reason');
if (reason && REASONS[reason]) {
  banner.textContent = REASONS[reason];
  banner.hidden = false;
}

function refreshButtonState() {
  activateButton.disabled = !keyInput.value.trim();
}

keyInput.addEventListener('input', refreshButtonState);

// Pasted keys routinely arrive wrapped across lines from e-mail or chat.
// Rejecting those as malformed would be a self-inflicted support burden.
keyInput.addEventListener('paste', () => {
  setTimeout(() => {
    keyInput.value = keyInput.value.replace(/\s+/g, '');
    refreshButtonState();
  }, 0);
});

async function loadDeviceHash() {
  try {
    const status = await api?.getLicenseStatus?.();
    deviceOutput.textContent = status?.deviceHash || 'Cihaz kimliği okunamadı';
  } catch {
    deviceOutput.textContent = 'Cihaz kimliği okunamadı';
  }
}

activateButton.addEventListener('click', async () => {
  const key = keyInput.value.replace(/\s+/g, '');
  if (!key) return;
  activateButton.disabled = true;
  setStatus('Lisans doğrulanıyor ve kaydediliyor…');
  try {
    const result = await api?.activateLicense?.(key);
    if (result?.ok) {
      setStatus('Lisans etkinleştirildi. Korumalar başlatılıyor…', 'ok');
      // The main process closes this window once it has restarted the
      // watchers; leaving it to do that keeps "activated" and "protecting"
      // from being reported separately when only one of them happened.
      return;
    }
    setStatus(result?.message || 'Lisans etkinleştirilemedi.', 'error');
  } catch (error) {
    setStatus(error?.message || 'Lisans etkinleştirilemedi.', 'error');
  }
  activateButton.disabled = false;
});

closeButton.addEventListener('click', () => api?.closeWindow?.());

keyInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) activateButton.click();
});

loadDeviceHash();
refreshButtonState();

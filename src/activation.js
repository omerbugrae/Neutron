'use strict';

// Renderer for the standalone activation window. Deliberately tiny and
// independent of renderer.js: this window has to work when the main UI is
// blocked or was never opened, so it shares no state with it.

const api = window.neutron;

const banner = document.querySelector('[data-role="banner"]');
const contentScroller = document.querySelector('.content');
const statusOutput = document.querySelector('[data-role="status"]');
const submitButton = document.querySelector('[data-role="submit"]');
const closeButton = document.querySelector('[data-role="close"]');
const signOutButton = document.querySelector('[data-role="sign-out"]');
const retryButton = document.querySelector('[data-role="retry"]');

const panels = {
  auth: document.querySelector('[data-panel="auth"]'),
  waiting: document.querySelector('[data-panel="waiting"]'),
  offline: document.querySelector('[data-panel="offline"]'),
};

const tabs = [...document.querySelectorAll('.tab')];
const forms = { signin: document.querySelector('[data-form="signin"]'), signup: document.querySelector('[data-form="signup"]') };
let activeTab = 'signin';
let currentStatus = null;

function setStatus(message, tone = '') {
  statusOutput.textContent = message || '';
  statusOutput.className = `status ${tone}`.trim();
}

function showBanner(message, tone = '') {
  if (!message) { banner.hidden = true; return; }
  banner.textContent = message;
  banner.className = `banner ${tone}`.trim();
  banner.hidden = false;
}

// Why this window opened. Passed as a query string because the window may be
// created long before any IPC listener is ready.
const REASON_BANNERS = {
  expired: ['Erişim süren sona erdi. Neutron çalışma alanı kilitlendi.', 'error'],
  none: ['Devam etmek için Neutron hesabınla giriş yap.', 'info'],
  offline: ['Hesabın şu anda doğrulanamıyor. Bağlantını kontrol et.', 'error'],
  pending: ['Hesabın henüz onaylanmadı.', 'info'],
  revoked: ['Bu hesabın Neutron erişimi durduruldu.', 'error'],
  rejected: ['Hesap talebi onaylanmadı.', 'error'],
  'no-request': ['Bu hesap için etkin bir erişim kaydı bulunamadı.', 'error'],
  reminder: ['Neutron çalışma alanı hesabın doğrulanana kadar kilitli kalır.', 'info'],
};

function applyReasonBanner() {
  const reason = new URLSearchParams(window.location.search).get('reason');
  const entry = reason && REASON_BANNERS[reason];
  if (entry) showBanner(entry[0], entry[1]);
}

function hideAllPanels() {
  Object.values(panels).forEach((panel) => { panel.hidden = true; });
}

function switchTab(name) {
  activeTab = name;
  tabs.forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
    tab.tabIndex = active ? 0 : -1;
  });
  forms.signin.hidden = name !== 'signin';
  forms.signup.hidden = name !== 'signup';
  submitButton.textContent = name === 'signin' ? 'Giriş yap' : 'Hesap oluştur';
  if (contentScroller) contentScroller.scrollTop = 0;
  setStatus('');
}

tabs.forEach((tab) => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

function render(status) {
  currentStatus = status;
  hideAllPanels();
  signOutButton.hidden = true;
  retryButton.hidden = true;
  submitButton.hidden = true;

  const hasSession = Boolean(status?.license?.email);

  if (status?.status === 'offline' && hasSession) {
    panels.offline.hidden = false;
    document.querySelector('[data-role="offline-text"]').textContent =
      status.message || 'İnternet bağlantınızı kontrol edip yeniden deneyin.';
    retryButton.hidden = false;
    signOutButton.hidden = false;
    return;
  }

  if (['pending', 'no-request', 'rejected', 'revoked', 'expired'].includes(status?.status)) {
    panels.waiting.hidden = false;
    const icon = document.querySelector('[data-role="waiting-icon"]');
    const title = document.querySelector('[data-role="waiting-title"]');
    const text = document.querySelector('[data-role="waiting-text"]');
    const emailLine = document.querySelector('[data-role="waiting-email"]');
    const copy = {
      pending: ['Hesabın onay bekliyor', 'Talebin alındı. Onaylandıktan sonra Neutron çalışma alanı açılır ve korumalar başlar.'],
      'no-request': ['Erişim kaydı bulunamadı', 'Bu hesap için etkin bir Neutron erişim kaydı yok. Destek ekibiyle iletişime geçebilirsin.'],
      rejected: ['Hesap talebi onaylanmadı', 'Farklı bir hesap kullanabilir veya destek ekibiyle iletişime geçebilirsin.'],
      revoked: ['Hesap erişimi durduruldu', 'Bu hesabın Neutron çalışma alanına erişimi kapatıldı.'],
      expired: ['Erişim süresi sona erdi', 'Devam etmek için hesabının erişim süresini yenilemen gerekiyor.'],
    }[status.status];
    icon.dataset.state = status.status;
    [title.textContent, text.textContent] = copy;
    emailLine.textContent = hasSession ? status.license.email : '';
    retryButton.hidden = false;
    signOutButton.hidden = false;
    return;
  }

  // 'none' -- no session, or the previous one was cleared (expired refresh
  // token). Show the sign-in/sign-up forms.
  panels.auth.hidden = false;
  submitButton.hidden = false;
}

async function loadStatus() {
  try {
    render(await api?.getStatus?.());
  } catch {
    render(null);
  }
}

async function submitAuth() {
  submitButton.disabled = true;
  setStatus(activeTab === 'signin' ? 'Giriş yapılıyor…' : 'Hesap oluşturuluyor…');
  try {
    const result = activeTab === 'signin'
      ? await api.signIn(
          document.getElementById('si-email').value.trim(),
          document.getElementById('si-password').value,
        )
      : await api.signUp(
          document.getElementById('su-email').value.trim(),
          document.getElementById('su-password').value,
          document.getElementById('su-name').value.trim(),
        );
    if (!result?.ok) {
      setStatus(result?.message || 'İşlem tamamlanamadı.', 'error');
      submitButton.disabled = false;
      return;
    }
    if (result.needsEmailConfirmation) {
      setStatus(result.message, 'ok');
      submitButton.disabled = false;
      return;
    }
    setStatus('Doğrulanıyor…', 'ok');
    await loadStatus();
  } catch (error) {
    setStatus(error?.message || 'İşlem tamamlanamadı.', 'error');
  }
  submitButton.disabled = false;
}

submitButton.addEventListener('click', submitAuth);
[forms.signin, forms.signup].forEach((form) => {
  form.addEventListener('submit', (event) => { event.preventDefault(); submitAuth(); });
  form.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') { event.preventDefault(); submitAuth(); }
  });
});

closeButton.addEventListener('click', () => api?.closeWindow?.());

signOutButton.addEventListener('click', async () => {
  signOutButton.disabled = true;
  try {
    await api.signOut();
    await loadStatus();
  } finally {
    signOutButton.disabled = false;
  }
});

retryButton.addEventListener('click', async () => {
  retryButton.disabled = true;
  setStatus('Yeniden deneniyor…');
  try {
    render(await api.refresh());
    setStatus('');
  } catch (error) {
    setStatus(error?.message || 'Yeniden denenemedi.', 'error');
  }
  retryButton.disabled = false;
});

applyReasonBanner();
switchTab('signin');
loadStatus();

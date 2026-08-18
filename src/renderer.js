(() => {
  'use strict';

  const engine = window.neutronEngine;
  const licenseAccountCard = document.querySelector('[data-role="license-account-card"]');
  const dashboard = document.querySelector('.dashboard');
  const pages = [...document.querySelectorAll('.app-page[data-page]')];
  const pageTargets = [...document.querySelectorAll('[data-page-target]')];
  const quickScanButtons = [...document.querySelectorAll('[data-action="quick-scan"]')];
  const heroPrimaryAction = document.querySelector('.hero-actions [data-action="quick-scan"]');
  const folderScanButtons = [...document.querySelectorAll('[data-action="choose-folder-scan"]')];
  const cancelScanButton = document.querySelector('[data-action="cancel-scan"]');
  const scanModeTabs = [...document.querySelectorAll('[data-scan-mode]')];
  const scanModeOptions = document.querySelector('[data-role="scan-mode-options"]');
  const protectionToggle = document.querySelector('[data-action="toggle-protection"]');
  const behaviorProtectionToggle = document.querySelector('[data-action="toggle-behavior-protection"]');
  const webProtectionToggle = document.querySelector('[data-action="toggle-web-protection"]');
  const amsiProtectionToggle = document.querySelector('[data-action="toggle-amsi-protection"]');
  const watchdogProtectionToggle = document.querySelector('[data-action="toggle-watchdog-protection"]');
  const wscProtectionToggle = document.querySelector('[data-action="toggle-wsc-protection"]');
  const serviceProtectionToggle = document.querySelector('[data-action="toggle-service-protection"]');
  const signatureUpdateButton = document.querySelector('[data-action="update-signatures"]');
  const signatureRollbackButton = document.querySelector('[data-action="rollback-signatures"]');
  const featureUpdateButton = document.querySelector('[data-action="update-features"]');
  const clearAnalysisCacheButton = document.querySelector('[data-action="clear-analysis-cache"]');
  const settingToggles = [...document.querySelectorAll('[data-setting-toggle]')];
  const scanLimitSelect = document.querySelector('[data-setting-select="scan_max_files"]');
  const addWatchFolderButton = document.querySelector('[data-action="add-watch-folder"]');
  const addExclusionFolderButton = document.querySelector('[data-action="add-exclusion-folder"]');
  const chooseFirewallAppButton = document.querySelector('[data-action="choose-firewall-app"]');
  const scanVulnerableSoftwareButton = document.querySelector('[data-action="scan-vulnerable-software"]');
  const exclusionExtensionForm = document.querySelector('[data-role="exclusion-extension-form"]');
  const exclusionExtensionInput = document.querySelector('[data-role="exclusion-extension-input"]');
  const vtApiKeyForm = document.querySelector('[data-role="vt-api-key-form"]');
  const vtApiKeyInput = document.querySelector('[data-role="vt-api-key-input"]');
  const mbApiKeyForm = document.querySelector('[data-role="mb-api-key-form"]');
  const mbApiKeyInput = document.querySelector('[data-role="mb-api-key-input"]');
  const webCheckForm = document.querySelector('[data-role="web-check-form"]');
  const webCheckInput = document.querySelector('[data-role="web-check-input"]');
  const textTargets = (role) => [...document.querySelectorAll(`[data-role="${role}"]`)];
  let scanning = false;
  let protectionEnabled = null;
  let behaviorEnabled = null;
  let behaviorReady = null;
  let webEnabled = null;
  let webReady = null;
  let amsiEnabled = null;
  let amsiReady = null;
  let watchdogEnabled = null;
  let wscEnabled = null;
  let serviceEnabled = null;
  let signatureLabel = 'Proton hazırlanıyor';
  let currentSettings = null;
  let pendingProtectionEventId = null;
  let selectedScanMode = 'quick';
  let selectedFullScanDrive = null;
  let activeThreatDetected = false;

  // Activation itself now lives in its own window, opened by the main process
  // (see openActivationWindow in main.cjs). This is only a read: the main UI
  // still needs to know whether it is licensed so it can say so, but it no
  // longer owns the activation flow.
  const initializeLicense = async () => {
    const status = await engine?.getLicenseStatus?.();
    return Boolean(status?.active);
  };

  const maskLicenseKey = (key) => {
    const chunks = String(key || '').split('-');
    if (chunks.length < 3) return 'NTR1-•••••-•••••';
    return `${chunks[0]}-${chunks[1]}-•••••-•••••-${chunks.at(-1)}`;
  };

  const renderLicenseAccount = async () => {
    if (!engine?.getLicenseStatus) return;
    const result = await engine.getLicenseStatus();
    const settingsSummary = document.querySelector('[data-role="license-settings-summary"]');
    if (!result?.active || !result.license) { if (licenseAccountCard) licenseAccountCard.hidden = true; if (settingsSummary) settingsSummary.hidden = true; return; }
    if (licenseAccountCard) licenseAccountCard.hidden = false;
    const license = result.license;
    setText('license-customer-name', license.customerName || license.licenseId || 'Lisanslı kullanıcı');
    setText('license-edition', `Neutron ${license.edition || 'Standard'} · Çevrimdışı hesap`);
    setText('license-settings-name', license.customerName || license.licenseId || 'Lisanslı kullanıcı');
    setText('license-settings-edition', `Neutron ${license.edition || 'Standard'} · Çevrimdışı hesap`);
    const reveal = await engine.revealLicense?.();
    const key = reveal?.ok ? reveal.key : '';
    setText('license-masked-key', maskLicenseKey(key));
    const expiry = license.expiresAt ? new Date(license.expiresAt) : null;
    const issued = license.issuedAt ? new Date(license.issuedAt) : null;
    if (!expiry || Number.isNaN(expiry.getTime())) {
      setText('license-duration', 'Süresiz lisans'); setText('license-duration-detail', 'Çevrimdışı lisans etkin');
      setText('license-settings-duration', 'Süresiz lisans'); setText('license-settings-detail', 'Çevrimdışı lisans etkin');
      textTargets('license-duration-bar').forEach((bar) => { bar.style.width = '100%'; });
      return;
    }
    const total = issued && !Number.isNaN(issued.getTime()) ? Math.max(1, expiry - issued) : 1;
    const remaining = Math.max(0, expiry - Date.now());
    const percent = Math.max(8, Math.min(100, (remaining / total) * 100));
    const days = Math.max(0, Math.ceil(remaining / 86_400_000));
    setText('license-duration', `${days} gün kaldı`);
    setText('license-duration-detail', `Bitiş: ${new Intl.DateTimeFormat('tr-TR', { dateStyle: 'long' }).format(expiry)}`);
    setText('license-settings-duration', `${days} gün kaldı`);
    setText('license-settings-detail', `Bitiş: ${new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium' }).format(expiry)}`);
    textTargets('license-duration-bar').forEach((bar) => { bar.style.width = `${percent}%`; });
  };

  document.addEventListener('click', async (event) => {
    const target = event.target.closest('[data-action="show-license"]');
    if (!target) return;
    const output = document.querySelector('[data-role="license-full-key"]');
    if (!output) return;
    if (!output.hidden) { output.hidden = true; target.textContent = 'Lisansı göster'; return; }
    const result = await engine?.revealLicense?.();
    if (!result?.ok) return;
    output.textContent = result.key; output.hidden = false; target.textContent = 'Lisansı gizle';
  });

  const setText = (role, value) => textTargets(role).forEach((element) => {
    element.textContent = value;
  });

  const formatDuration = (milliseconds) => {
    const value = Number(milliseconds) || 0;
    return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} sn`;
  };

  // Goes up to TB: the performance page reports temp-directory totals, which
  // pass a gigabyte on machines that have not been cleaned in a while.
  const formatBytes = (bytes) => {
    const value = Math.max(0, Number(bytes) || 0);
    if (value < 1024) return `${value} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let size = value / 1024;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[index]}`;
  };

  const formatScanDate = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Bilinmiyor';
    return new Intl.DateTimeFormat('tr-TR', {
      dateStyle: 'short',
      timeStyle: 'short',
    }).format(date);
  };

  const setButtons = (label, disabled) => {
    quickScanButtons.forEach((button) => {
      const labelElement = button.querySelector('[data-action-label]');
      if (labelElement) labelElement.textContent = label;
      button.disabled = disabled;
      button.setAttribute('aria-busy', disabled ? 'true' : 'false');
    });
    folderScanButtons.forEach((button) => { button.disabled = disabled; });
    if (cancelScanButton) {
      cancelScanButton.hidden = !disabled;
      cancelScanButton.disabled = false;
    }
  };

  const renderScanMode = async (mode) => {
    selectedScanMode = mode;
    scanModeTabs.forEach((tab) => {
      const active = tab.dataset.scanMode === mode;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    if (!scanModeOptions) return;
    scanModeOptions.replaceChildren();
    scanModeOptions.classList.remove('is-entering');
    void scanModeOptions.offsetWidth;
    scanModeOptions.classList.add('is-entering');
    const primaryLabel = quickScanButtons.find((button) => button !== heroPrimaryAction)?.querySelector('[data-action-label]');
    if (mode === 'quick') {
      setText('scan-page-label', 'HIZLI TARAMA');
      setText('scan-page-heading', 'Kritik alanlar');
      setText('scan-page-summary', 'Zararlıların sık kullandığı önemli kullanıcı alanları hızlıca incelenir.');
      if (primaryLabel) primaryLabel.textContent = 'Hızlı tarama başlat';
      return;
    }
    if (mode === 'custom') {
      setText('scan-page-label', 'ÖZEL TARAMA');
      setText('scan-page-heading', 'Dosya veya klasör seçin');
      setText('scan-page-summary', 'Tek bir dosyayı ya da seçtiğiniz klasörün içeriğini ayrıntılı tarayın.');
      if (primaryLabel) primaryLabel.textContent = 'Dosya veya klasör seç';
      return;
    }
    setText('scan-page-label', 'TAM TARAMA');
    setText('scan-page-heading', 'Taranacak sürücüyü seçin');
    setText('scan-page-summary', 'Seçilen sürücü erişilebilen tüm klasörleriyle taranır; işlem uzun sürebilir.');
    if (primaryLabel) primaryLabel.textContent = 'Tam taramayı başlat';
    const result = await engine?.getScanDrives?.();
    for (const drive of result?.drives || []) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'scan-drive-card';
      button.classList.toggle('is-selected', selectedFullScanDrive === drive.path);
      button.innerHTML = '<span class="scan-drive-icon"><svg aria-hidden="true"><use href="#icon-drive"></use></svg></span><span><strong></strong><small></small></span><i></i>';
      button.querySelector('strong').textContent = drive.label;
      button.querySelector('small').textContent = drive.path;
      button.addEventListener('click', () => {
        selectedFullScanDrive = drive.path;
        renderScanMode('full');
      });
      scanModeOptions.append(button);
    }
    if (!selectedFullScanDrive && result?.drives?.[0]) {
      selectedFullScanDrive = result.drives[0].path;
      renderScanMode('full');
    }
  };

  const syncHeroPrimaryAction = () => {
    if (!heroPrimaryAction || scanning) return;
    const label = heroPrimaryAction.querySelector('[data-action-label]');
    if (protectionEnabled === null) {
      if (label) label.textContent = 'Koruma denetleniyor';
      heroPrimaryAction.disabled = true;
      heroPrimaryAction.title = 'Gerçek zamanlı koruma durumu denetleniyor';
      return;
    }
    const shouldEnableProtection = protectionEnabled === false;
    if (label) label.textContent = shouldEnableProtection ? 'Korumayı aç' : 'Hızlı tarama başlat';
    heroPrimaryAction.disabled = false;
    heroPrimaryAction.title = shouldEnableProtection
      ? 'Gerçek zamanlı dosya korumasını etkinleştir'
      : 'Kritik kullanıcı alanları için salt-okunur hızlı tarama';
  };

  const pageNameFromHash = () => window.location.hash.slice(1);

  let systemAuditLoaded = false;

  const showPage = (requestedPage, options = {}) => {
    const pageName = pages.some((page) => page.dataset.page === requestedPage)
      ? requestedPage
      : 'overview';

    pages.forEach((page) => {
      const active = page.dataset.page === pageName;
      page.hidden = !active;
      page.classList.toggle('is-active', active);
    });

    pageTargets.forEach((target) => {
      const active = target.dataset.pageTarget === pageName;
      target.classList.toggle('is-active', active);
      if (target.classList.contains('nav-item')) {
        target.setAttribute('aria-current', active ? 'page' : 'false');
      }
    });

    if (dashboard) dashboard.scrollTop = 0;
    if (options.updateHash !== false && window.location.hash !== `#${pageName}`) {
      window.history.replaceState(null, '', `#${pageName}`);
    }
    if (pageName === 'activity') {
      applyHistory();
      applyProtectionHistory();
    }
    if (pageName === 'quarantine') applyQuarantine();
    if (pageName === 'firewall') {
      applyFirewall();
      applyFirewallRecentApps();
    }
    if (pageName === 'startup-software') {
      applyStartupItems();
      applyVulnerableSoftware();
    }
    // Run once on first visit so the page is never an empty prompt, but not
    // on every navigation -- the reader may be working through the findings.
    if (pageName === 'system-audit' && !systemAuditLoaded) {
      systemAuditLoaded = true;
      applySystemAudit();
    }
    if (pageName === 'settings') {
      applySettings();
      applyExclusions();
      applyAnalysisCacheStatus();
    }
  };

  // 0 means "sınırsız" (unlimited) -- `|| 1500` would treat that falsy 0
  // as "not set" and silently fall back to 1500, so it needs an explicit
  // check rather than the usual default-via-|| shorthand.
  const scanLimitText = (rawValue) => {
    const value = Number(rawValue);
    if (value === 0) return 'sınırsız sayıda';
    return `en fazla ${(Number.isFinite(value) && value > 0 ? value : 1500).toLocaleString('tr-TR')}`;
  };

  const setReadyState = () => {
    const protectionKnown = typeof protectionEnabled === 'boolean';
    setText('engine-state', !protectionKnown
      ? 'Koruma durumu denetleniyor'
      : protectionEnabled ? 'Gerçek zamanlı koruma etkin' : 'Koruma kapalı');
    setText('database-state', signatureLabel);
    setText('protection-label', !protectionKnown
      ? 'KORUMA DENETLENİYOR'
      : protectionEnabled ? 'KORUMA ETKİN' : 'KORUMA KAPALI');
    setText('scan-heading', !protectionKnown
      ? 'Neutron hazırlanıyor.'
      : protectionEnabled ? 'Neutron seni koruyor.' : 'Korumayı açın.');
    setText('scan-summary', !protectionKnown
      ? 'Koruma motorunun durumu kontrol ediliyor.'
      : protectionEnabled
      ? 'Kullanıcı profilinizdeki ve geçici klasörlerdeki yeni ve değişen dosyalar izleniyor.'
      : 'Gerçek zamanlı dosya izleme kapalı. Koruma sayfasından yeniden açabilirsiniz.');
    setText('scan-page-heading', 'Kritik alanlar');
    setText('scan-page-summary', `${scanLimitText(currentSettings?.scan_max_files)} dosya incelenir. Dosyalar silinmez, taşınmaz veya karantinaya alınmaz.`);
    setButtons('Hızlı tarama başlat', false);
    syncHeroPrimaryAction();
    if (activeThreatDetected) applyThreatAlertState();
  };

  const applyThreatAlertState = () => {
    document.body.classList.add('threat-alert');
    setText('engine-state', 'Tehdit bulundu ve engellendi');
    setText('protection-label', 'TEHDİT ENGELLENDİ');
    setText('dashboard-state-heading', 'Tehdit bulundu ve engellendi.');
    setText('dashboard-state-detail', 'Neutron tehdidi güvenli karantinaya aldı. Ayrıntıları Etkinlik ve Karantina sayfalarında görebilirsin.');
    setText('scan-heading', 'Tehdit bulundu ve engellendi.');
    setText('scan-summary', 'Son tespit karantinaya taşındı. Karantina sayfasından inceleyebilir veya geri yükleyebilirsin.');
    setText('overview-file-protection-state', 'Tehdit engellendi');
    setText('sidebar-protection-state', 'Tehdit engellendi');
    setText('sidebar-protection-detail', 'Dosya güvenli karantinaya alındı');
  };

  const refreshProtectionVisualState = () => {
    const protectionKnown = typeof protectionEnabled === 'boolean';
    const behaviorKnown = typeof behaviorEnabled === 'boolean';
    const partiallyProtected = protectionEnabled === true && (behaviorEnabled === false || webEnabled === false);

    document.body.classList.toggle('protection-warning', partiallyProtected);
    document.body.classList.toggle('behavior-protection-off', behaviorKnown && behaviorEnabled === false);
    document.body.classList.toggle('web-protection-off', typeof webEnabled === 'boolean' && webEnabled === false);

    if (activeThreatDetected) {
      applyThreatAlertState();
      return;
    }

    if (!protectionKnown || !behaviorKnown || protectionEnabled === false) return;
    if (partiallyProtected) {
      setText('protection-label', 'KORUMA KISMEN ETKİN');
      setText('scan-heading', 'Koruma dikkat gerektiriyor.');
      setText('scan-summary', 'Dosya koruması etkin; davranış izleme kapalı. Koruma sayfasından yeniden açabilirsiniz.');
      setText('sidebar-protection-state', 'Koruma kısmen etkin');
      setText('sidebar-protection-detail', 'Davranış izleme kapalı');
    }
  };

  const setProtectionState = (enabled, heading, detail) => {
    protectionEnabled = enabled;
    document.body.classList.remove('protection-pending');
    document.body.classList.toggle('protection-off', !enabled);
    document.body.classList.toggle('protection-on', enabled);
    setText('realtime-protection-state', heading);
    setText('realtime-protection-detail', detail);
    setText('file-protection-state', heading);
    setText('file-protection-detail', detail);
    setText('sidebar-protection-state', enabled ? 'Koruma etkin' : 'Koruma kapalı');
    setText('sidebar-protection-detail', enabled ? 'Dosyalar gerçek zamanlı izleniyor' : 'Korumayı yeniden açın');
    setText('dashboard-state-heading', activeThreatDetected ? 'Tehdit bulundu ve engellendi.' : (enabled ? 'Bilgisayarınız izleniyor.' : 'Koruma kapalı.'));
    setText('dashboard-state-detail', activeThreatDetected
      ? 'Neutron tehdidi güvenli karantinaya aldı. Ayrıntıları Etkinlik ve Karantina sayfalarında görebilirsin.'
      : (enabled ? 'Yeni ve değişen dosyalar Neutron tarafından yerel olarak denetleniyor.' : 'Yeni ve değişen dosyalar izlenmiyor. Koruma sayfasından korumayı açın.'));
    setText('overview-file-protection-state', enabled ? 'Koruma etkin' : 'Koruma kapalı');
    setText('protection-label', enabled ? 'KORUMA ETKİN' : 'KORUMA KAPALI');
    setText('scan-heading', activeThreatDetected ? 'Tehdit bulundu ve engellendi.' : (enabled ? 'Neutron seni koruyor.' : 'Korumayı açın.'));
    setText('scan-summary', activeThreatDetected
      ? 'Son tespit karantinaya taşındı. Karantina sayfasından inceleyebilir veya geri yükleyebilirsin.'
      : (enabled ? 'Kullanıcı profilinizdeki ve geçici klasörlerdeki yeni ve değişen dosyalar izleniyor.' : 'Gerçek zamanlı dosya izleme kapalı. Koruma sayfasından yeniden açabilirsiniz.'));
    setText('protection-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (protectionToggle) {
      protectionToggle.classList.toggle('is-active', enabled);
      protectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      protectionToggle.disabled = false;
    }
    refreshProtectionVisualState();
    syncHeroPrimaryAction();
  };

  const setBehaviorProtectionState = (enabled, ready, heading, detail) => {
    behaviorEnabled = enabled;
    behaviorReady = ready;
    setText('overview-behavior-state', enabled ? (ready ? 'Etkin' : 'Başlatılıyor') : 'Kapalı');
    setText('behavior-protection-state', heading);
    setText('behavior-protection-detail', detail);
    setText('behavior-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (behaviorProtectionToggle) {
      behaviorProtectionToggle.classList.toggle('is-active', enabled);
      behaviorProtectionToggle.closest('.detail-module')?.classList.toggle('is-behavior-active', enabled);
      document.querySelector('[data-role="overview-behavior-state"]')
        ?.closest('.protection-module')
        ?.classList.toggle('is-behavior-active', enabled);
      behaviorProtectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      behaviorProtectionToggle.disabled = false;
    }
    refreshProtectionVisualState();
  };

  const setWebProtectionState = (enabled, ready, heading, detail) => {
    webEnabled = enabled; webReady = ready;
    setText('overview-web-state', enabled ? (ready ? 'Etkin' : 'Başlatılıyor') : 'Kapalı');
    setText('overview-web-detail', detail);
    setText('web-protection-state', heading);
    setText('web-protection-detail', detail);
    setText('web-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (webProtectionToggle) {
      webProtectionToggle.classList.toggle('is-active', enabled);
      webProtectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      webProtectionToggle.disabled = false;
    }
    refreshProtectionVisualState();
  };

  const setAmsiProtectionState = (enabled, ready, heading, detail) => {
    amsiEnabled = enabled; amsiReady = ready;
    setText('amsi-protection-state', heading);
    setText('amsi-protection-detail', detail);
    setText('amsi-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (amsiProtectionToggle) {
      amsiProtectionToggle.classList.toggle('is-active', enabled);
      amsiProtectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      amsiProtectionToggle.disabled = false;
    }
  };

  const setWatchdogProtectionState = (enabled, heading, detail) => {
    watchdogEnabled = enabled;
    setText('watchdog-protection-state', heading);
    setText('watchdog-protection-detail', detail);
    setText('watchdog-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (watchdogProtectionToggle) {
      watchdogProtectionToggle.classList.toggle('is-active', enabled);
      watchdogProtectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      watchdogProtectionToggle.disabled = false;
    }
  };

  const setWscProtectionState = (enabled, heading, detail, available = true) => {
    wscEnabled = enabled;
    setText('wsc-protection-state', heading);
    setText('wsc-protection-detail', detail);
    setText('wsc-toggle-label', available ? (enabled ? 'Kapat' : 'Aç') : 'Windows yönetiyor');
    if (wscProtectionToggle) {
      wscProtectionToggle.classList.toggle('is-active', enabled);
      wscProtectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      wscProtectionToggle.disabled = !available;
    }
  };

  const setServiceProtectionState = (enabled, heading, detail) => {
    serviceEnabled = enabled;
    setText('service-protection-state', heading);
    setText('service-protection-detail', detail);
    setText('service-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (serviceProtectionToggle) {
      serviceProtectionToggle.classList.toggle('is-active', enabled);
      serviceProtectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      serviceProtectionToggle.disabled = false;
    }
  };

  const applyAppVersion = async () => {
    try {
      const result = await engine?.getAppVersion?.();
      if (!result?.ok) throw new Error();
      setText('update-heading', `Neutron ${result.version}`);
      setText('update-detail', result.packaged
        ? 'Güncellemeler otomatik denetlenir. Elle de kontrol edebilirsiniz.'
        : 'Geliştirme modu — güncelleme denetimi yalnızca kurulu sürümde çalışır.');
    } catch {
      setText('update-heading', 'Neutron');
      setText('update-detail', 'Sürüm bilgisi alınamadı.');
    }
  };

  const applyEngineStatus = async () => {
    const overviewStatus = document.querySelector('[data-role="overview-engine-status"]');
    const overviewCard = overviewStatus?.closest('.protection-module');
    const detailCard = document.querySelector('[data-glass-id="detail-engine"]');
    try {
      const result = await engine?.getEngineStatus?.();
      if (!result?.ok || !result.version) throw new Error('Motor durumu okunamadı');
      const yaraReady = Boolean(result.yara?.ok && result.yara?.available);
      const ruleFiles = Number(result.yara?.rule_files) || 0;
      const protonVersion = result.proton?.version || 'bilinmiyor';
      const activeModules = [
        result.protection?.enabled,
        result.protection?.behaviorConfigured,
        result.protection?.webConfigured,
      ].filter(Boolean).length;
      const healthy = yaraReady && ruleFiles > 0;

      setText('overview-engine-state', healthy ? 'Çalışıyor' : 'Sınırlı');
      setText('overview-engine-detail', healthy
        ? `Motor ${result.version} · YARA ${ruleFiles} kural dosyasıyla etkin.`
        : `Motor ${result.version} çalışıyor; YARA kuralları kullanılamıyor.`);
      setText('engine-card-heading', `Neutron Engine ${result.version}`);
      setText('engine-card-detail', healthy
        ? `Proton ${protonVersion} · ${ruleFiles} YARA dosyası · ${activeModules}/3 canlı koruma modülü etkin.`
        : `Proton ${protonVersion} yüklü; YARA motoru veya kural dosyaları kullanılamıyor.`);
      overviewStatus?.classList.toggle('module-status--pending', !healthy);
      overviewCard?.classList.remove('protection-module--pending', 'engine-unavailable');
      overviewCard?.classList.toggle('engine-limited', !healthy);
      detailCard?.classList.remove('engine-unavailable');
      detailCard?.classList.toggle('engine-limited', !healthy);
    } catch {
      setText('overview-engine-state', 'Kullanılamıyor');
      setText('overview-engine-detail', 'Yerel tarama motoruna bağlanılamadı.');
      setText('engine-card-heading', 'Motor kullanılamıyor');
      setText('engine-card-detail', 'Neutron Engine durum bilgisi alınamadı. Uygulamayı yeniden başlatın.');
      overviewCard?.classList.add('engine-unavailable');
      detailCard?.classList.add('engine-unavailable');
    }
  };

  const applyProtectionStatus = async () => {
    try {
      const status = await engine?.getProtectionStatus?.();
      if (!status?.ok) throw new Error('Koruma durumu okunamadı');
      if (status.enabled) {
        setProtectionState(true, status.ready ? 'Koruma etkin' : 'Koruma başlatılıyor', status.ready
          ? 'Kullanıcı profiliniz ve geçici klasörler izleniyor.'
          : 'İzlenecek klasörlerin ilk görüntüsü hazırlanıyor.');
      } else {
        setProtectionState(false, 'Koruma kapalı', 'Yeni ve değişen dosyalar şu anda izlenmiyor.');
      }
      // The persisted setting is the source of truth while the watcher is starting.
      // A just-enabled watcher may not have spawned by the first status read yet.
      const behaviorConfigured = typeof status.behaviorConfigured === 'boolean'
        ? status.behaviorConfigured
        : Boolean(status.behaviorEnabled);
      if (behaviorConfigured) {
        setBehaviorProtectionState(
          true,
          Boolean(status.behaviorReady),
          status.behaviorReady ? 'Etkin' : 'Başlatılıyor',
          status.behaviorReady
            ? 'Yeni süreçler ve Windows otomatik başlangıç noktaları izleniyor.'
            : 'Süreç ve kalıcılık başlangıç görüntüsü hazırlanıyor.',
        );
      } else {
        setBehaviorProtectionState(false, false, 'Kapalı', 'Süreçler ve kalıcılık noktaları şu anda izlenmiyor.');
      }
      const webConfigured = typeof status.webConfigured === 'boolean' ? status.webConfigured : Boolean(status.webEnabled);
      setWebProtectionState(
        webConfigured,
        Boolean(status.webReady),
        webConfigured ? (status.webReady ? 'Etkin' : 'Başlatılıyor') : 'Kapalı',
        webConfigured
          ? (status.webReady ? 'İndirilen dosyalar ve kaynak adresleri yerel olarak denetleniyor.' : 'Web koruması başlatılıyor.')
          : 'İndirme ve bağlantı itibarı denetimi kapalı.',
      );
      const amsiConfigured = typeof status.amsiConfigured === 'boolean' ? status.amsiConfigured : Boolean(status.amsiEnabled);
      setAmsiProtectionState(
        amsiConfigured,
        Boolean(status.amsiReady),
        amsiConfigured ? (status.amsiReady ? 'Etkin' : 'Başlatılıyor') : 'Kapalı',
        amsiConfigured
          ? (status.amsiReady ? 'Betikler çalışmadan önce yerel olarak denetleniyor.' : 'Çalıştırma öncesi koruma başlatılıyor.')
          : 'Betik çalıştırma koruması kapalı. Etkinleştirmek yönetici izni gerektirir.',
      );
      const watchdogConfigured = typeof status.watchdogConfigured === 'boolean' ? status.watchdogConfigured : false;
      setWatchdogProtectionState(
        watchdogConfigured,
        watchdogConfigured ? 'Etkin' : 'Kapalı',
        watchdogConfigured
          ? 'Neutron kapatılırsa 2 dakika içinde otomatik olarak yeniden başlatılır.'
          : 'Otomatik yeniden başlatma kapalı. Etkinleştirmek yönetici izni gerektirir.',
      );
      const wscConfigured = typeof status.wscConfigured === 'boolean' ? status.wscConfigured : false;
      const wscAvailable = status.wscAvailable !== false;
      setWscProtectionState(
        wscAvailable && wscConfigured,
        !wscAvailable ? 'Windows tarafından yönetiliyor' : (wscConfigured ? 'Kayıtlı' : 'Kapalı'),
        !wscAvailable
          ? (status.wscMessage || 'Windows Güvenlik Merkezi kaydı bu derlemede desteklenmiyor.')
          : wscConfigured
          ? 'Neutron, Windows Güvenlik Merkezi\'ne bildirildi. Defender\'ın pasif moda geçip geçmediği cihaza bağlıdır.'
          : 'Windows Güvenlik Merkezi kaydı kapalı. Etkinleştirmek yönetici izni gerektirir.',
        wscAvailable,
      );
      const serviceConfigured = typeof status.serviceConfigured === 'boolean' ? status.serviceConfigured : false;
      const serviceConnected = typeof status.serviceConnected === 'boolean' ? status.serviceConnected : false;
      setServiceProtectionState(
        serviceConfigured,
        serviceConfigured ? (serviceConnected ? 'Etkin' : 'Bağlanıyor') : 'Kapalı',
        serviceConfigured
          ? (serviceConnected
            ? 'Koruma motoru Windows servisi olarak çalışıyor.'
            : 'Servise bağlanılıyor…')
          : 'Sistem servisi modu kapalı. Etkinleştirmek yönetici izni gerektirir.',
      );
      await applyEngineStatus();
    } catch {
      setProtectionState(false, 'Koruma kullanılamıyor', 'Python motoruna bağlanılamadı.');
      setBehaviorProtectionState(false, false, 'Kullanılamıyor', 'Davranış izleme motoruna bağlanılamadı.');
    }
  };

  const renderHistory = (scans) => {
    const list = document.querySelector('[data-role="history-list"]');
    if (!list) return;
    list.replaceChildren();

    if (!scans.length) {
      const empty = document.createElement('p');
      empty.className = 'history-empty';
      empty.textContent = 'Henüz kaydedilmiş bir tarama yok.';
      list.append(empty);
      return;
    }

    scans.forEach((scan) => {
      const confirmed = Number(scan.confirmed_count) || 0;
      const review = Number(scan.review_count) || 0;
      const row = document.createElement('article');
      row.className = 'history-row surface-card';

      const stamp = document.createElement('p');
      stamp.className = 'history-row__stamp';
      stamp.textContent = formatScanDate(scan.completed_at);
      const title = document.createElement('h3');
      title.textContent = 'Hızlı tarama';
      const detail = document.createElement('p');
      detail.textContent = `${scan.scanned} dosya · ${formatDuration(scan.elapsed_ms)}`;
      const result = document.createElement('p');
      result.className = confirmed > 0 || review > 0 ? 'history-result history-result--review' : 'history-result';
      result.textContent = confirmed > 0
        ? `${confirmed} imza eşleşmesi`
        : review > 0 ? `${review} inceleme işareti` : 'Bulgu yok';

      row.append(stamp, title, detail, result);
      list.append(row);
    });
  };

  const applyHistory = async () => {
    if (!engine?.getScanHistory) return;
    try {
      const result = await engine.getScanHistory();
      const scans = Array.isArray(result?.scans) ? result.scans : [];
      renderHistory(scans);
      const latest = scans[0];
      if (!latest || scanning) return;

      const confirmed = Number(latest.confirmed_count) || 0;
      const review = Number(latest.review_count) || 0;
      setText('last-scan', formatScanDate(latest.completed_at));
      setText('threat-count', String(confirmed));
      setText('database-state', signatureLabel);
      setText('activity-title', confirmed > 0 ? `${confirmed} imza eşleşmesi bulundu` : 'Son tarama tamamlandı');
      setText('activity-detail', `${latest.scanned} dosya ${formatDuration(latest.elapsed_ms)} içinde incelendi.${review > 0 ? ` ${review} dosya inceleme için işaretlendi.` : ''}`);
    } catch {
      renderHistory([]);
    }
  };

  const renderProtectionHistory = (events) => {
    const list = document.querySelector('[data-role="protection-event-list"]');
    const count = document.querySelector('[data-role="protection-event-count"]');
    if (!list || !count) return;
    list.replaceChildren();
    const pendingEvents = events.filter((event) => (event.disposition || 'pending') === 'pending');
    const isHighConfidenceEvent = (event) => (
      ['test-signature', 'signature', 'cloud-reputation'].includes(event.finding_kind)
      || Number(event.risk_score) >= 60
      || ['high', 'critical'].includes(event.severity)
    );
    const pendingThreats = pendingEvents.filter(isHighConfidenceEvent);
    const pendingReviews = pendingEvents.filter((event) => !isHighConfidenceEvent(event));
    const criticalPending = pendingThreats.length > 0;
    const latestQuarantined = events.find((event) => event.disposition === 'quarantined');
    if (latestQuarantined) activeThreatDetected = true;
    document.body.classList.toggle('threat-alert', criticalPending || activeThreatDetected);
    if (criticalPending) {
      setText('engine-state', 'Tehdit müdahalesi gerekiyor');
      setText('protection-label', 'TEHDİT BULUNDU');
      setText('file-protection-detail', `${pendingThreats.length} yüksek güvenli koruma olayı işlem bekliyor.`);
    } else if (activeThreatDetected) {
      applyThreatAlertState();
    }
    count.textContent = pendingEvents.length
      ? `${pendingThreats.length} müdahale · ${pendingReviews.length} inceleme · ${events.length} olay`
      : `${events.length} olay`;

    if (!events.length) {
      const empty = document.createElement('p');
      empty.className = 'history-empty';
      empty.textContent = 'Henüz işaretlenmiş bir dosya yok.';
      list.append(empty);
      return;
    }

    events.forEach((event) => {
      const row = document.createElement('article');
      row.className = 'protection-event-row';
      row.dataset.protectionEventId = String(event.id);
      const disposition = event.disposition || 'pending';
      const reviewOnly = disposition === 'pending' && !isHighConfidenceEvent(event);
      row.classList.toggle('is-resolved', disposition !== 'pending');
      row.classList.toggle('is-critical', disposition === 'pending' && ['high', 'critical'].includes(event.severity));
      const content = document.createElement('div');
      content.className = 'protection-event-row__content';
      const title = document.createElement('h3');
      title.textContent = event.file_path || 'Bilinmeyen dosya';
      const detail = document.createElement('p');
      detail.textContent = event.reason || 'Dosya inceleme için işaretlendi.';
      content.append(title, detail);
      const meta = document.createElement('div');
      meta.className = 'protection-event-row__meta';
      const badge = document.createElement('span');
      badge.textContent = event.finding_kind === 'test-signature'
        ? 'EICAR TEST'
        : event.finding_kind === 'signature' ? 'İMZA'
            : event.finding_kind === 'yara' ? 'YARA'
              : event.finding_kind === 'pe-analysis' ? 'PE İNCELEMESİ'
            : event.finding_kind === 'behavior' ? 'DAVRANIŞ'
              : event.finding_kind === 'persistence' ? 'KALICILIK'
                : event.finding_kind === 'service-tamper' ? 'SERVİS KURCALAMA' : 'İNCELEME';
      const stamp = document.createElement('time');
      stamp.textContent = formatScanDate(event.occurred_at);
      const dispositionLabel = document.createElement('strong');
      dispositionLabel.className = `protection-disposition protection-disposition--${disposition}`;
      dispositionLabel.textContent = reviewOnly ? 'İNCELEME ÖNERİLİR' : ({
        pending: 'MÜDAHALE BEKLİYOR',
        quarantined: 'KARANTİNADA',
        remediated: 'MÜDAHALE EDİLDİ',
        restored: 'GERİ YÜKLENDİ',
        'rollback-partial': 'KISMEN GERİ ALINDI',
        trusted: 'GÜVENİLİR',
        'trusted-publisher': 'YAYINCI GÜVENİLİR',
        ignored: 'YOK SAYILDI',
      }[disposition] || disposition.toLocaleUpperCase('tr-TR'));
      meta.append(badge, dispositionLabel, stamp);
      const actions = document.createElement('div');
      actions.className = 'protection-event-row__actions';
      if (disposition === 'pending') {
        const actionDefinitions = [
          ['remediate', 'Müdahale et'],
          ['quarantine', 'Karantinaya al'],
          ['trust', 'Güvenilir say'],
          ['trust-publisher', 'Yayıncıyı güvenilir say'],
          ['ignore', 'Yoksay'],
        ];
        actionDefinitions.forEach(([actionName, label]) => {
          if (reviewOnly && actionName === 'remediate') return;
          // Both of these describe an event rather than a file Neutron holds:
          // a registry autostart entry, and a process that was already refused
          // at the pipe. There is nothing to quarantine or restore, so the
          // only honest action is to dismiss the notice.
          if (['persistence', 'service-tamper'].includes(event.finding_kind) && actionName !== 'ignore') return;
          if (actionName === 'remediate' && (!event.file_path || event.file_path.startsWith('registry://') || event.file_path.startsWith('startup://'))) return;
          if (actionName === 'trust' && !/^[a-f0-9]{64}$/i.test(event.sha256 || '')) return;
          if (actionName === 'trust-publisher' && !/^[a-f0-9]{40,64}$/i.test(event.publisher_thumbprint || '')) return;
          const button = document.createElement('button');
          button.type = 'button';
          button.dataset.protectionAction = actionName;
          button.textContent = label;
          button.addEventListener('click', async () => {
            const confirmations = {
              remediate: `“${event.file_path}” için çalışan süreç ağacı durdurulsun, dosya karantinaya alınsın ve eşleşen kullanıcı başlangıç girdileri geri alınabilir biçimde kapatılsın mı?`,
              quarantine: `“${event.file_path}” karantinaya taşınsın mı? Dosya silinmez.`,
              trust: `Bu dosyanın mevcut SHA-256 özeti güvenilir sayılsın mı? Dosya değişirse yeniden taranır.`,
              'trust-publisher': `“${event.publisher_subject || 'Bu yayıncı'}” sertifikası güvenilir sayılsın mı? Aynı sertifikayla imzalanmış ve Windows tarafından doğrulanan dosyalar sezgisel uyarı üretmez.`,
              ignore: `“${event.file_path}” için bu uyarı yoksayılsın mı? Dosyada değişiklik yapılmaz.`,
            };
            if (!window.confirm(confirmations[actionName])) return;
            actions.querySelectorAll('button').forEach((item) => { item.disabled = true; });
            button.textContent = 'İşleniyor…';
            const result = await engine?.applyProtectionAction?.(Number(event.id), actionName);
            if (!result?.ok) {
              actions.querySelectorAll('button').forEach((item) => { item.disabled = false; });
              button.textContent = result?.message || 'Tekrar dene';
              return;
            }
            if (actionName === 'quarantine') applyQuarantine();
            if (actionName === 'remediate') applyQuarantine();
            if (actionName === 'trust') applyExclusions();
            applyProtectionHistory();
          });
          actions.append(button);
        });
      } else if (disposition === 'remediated' && Number.isInteger(event.incident_id)) {
        const rollback = document.createElement('button');
        rollback.type = 'button';
        rollback.textContent = 'Müdahaleyi geri al';
        rollback.addEventListener('click', async () => {
          if (!window.confirm('Karantinadaki dosya ve geri alınabilir başlangıç değişiklikleri eski hâline getirilsin mi? Durdurulan süreçler yeniden başlatılmaz.')) return;
          rollback.disabled = true;
          const result = await engine?.rollbackIncident?.(Number(event.incident_id));
          if (!result?.ok) {
            rollback.disabled = false;
            rollback.textContent = result?.message || 'Tekrar dene';
            return;
          }
          applyQuarantine();
          applyProtectionHistory();
        });
        actions.append(rollback);
      }
      row.append(content, actions, meta);
      list.append(row);
    });

    if (pendingProtectionEventId) {
      const target = list.querySelector(`[data-protection-event-id="${pendingProtectionEventId}"]`);
      if (target) {
        target.classList.add('is-focused');
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        window.setTimeout(() => target.classList.remove('is-focused'), 2400);
        pendingProtectionEventId = null;
      }
    }
  };

  const applyProtectionHistory = async () => {
    if (!engine?.getProtectionHistory) return;
    try {
      const result = await engine.getProtectionHistory();
      renderProtectionHistory(Array.isArray(result?.events) ? result.events : []);
    } catch {
      renderProtectionHistory([]);
    }
  };

  const applySignatureStatus = async () => {
    if (!engine?.getSignatureStatus) return;
    try {
      const result = await engine.getSignatureStatus();
      if (!result?.ok) throw new Error('signature status unavailable');
      const count = Number(result.signature_count) || 0;
      const databaseName = result.database_name || 'Proton';
      signatureLabel = `${databaseName} ${result.version || '1.00.001'}`;
      setText('database-state', signatureLabel);
      setText('signature-version', `${databaseName} ${result.version || '1.00.001'}`);
      const rollbackVersions = Array.isArray(result.rollback_versions) ? result.rollback_versions : [];
      if (signatureRollbackButton) {
        signatureRollbackButton.hidden = rollbackVersions.length === 0;
        signatureRollbackButton.dataset.version = rollbackVersions[0] || '';
      }
      setText('signature-detail', `${count} etkin tehdit tanımı · Proton kullanıma hazır.${rollbackVersions.length ? ` Geri dönüş: ${rollbackVersions[0]}.` : ''}`);
    } catch {
      signatureLabel = 'İmza veritabanı kullanılamıyor';
      setText('database-state', signatureLabel);
      setText('signature-version', 'Durum okunamadı');
      setText('signature-detail', 'Yerel imza veritabanına bağlanılamadı.');
    }
  };

  const applyFeatureUpdateStatus = async () => {
    if (!engine?.getFeatureUpdateStatus) return;
    try {
      const result = await engine.getFeatureUpdateStatus();
      if (!result?.ok) throw new Error('Feature Update status unavailable');
      if (result.ready) {
        setText('feature-update-version', `Machine Learning Models ${result.version}`);
        setText('feature-update-detail', `${Number(result.model_count) || 0} verified models are installed and ready.`);
        if (featureUpdateButton) featureUpdateButton.textContent = 'Check for Feature Update';
      } else {
        setText('feature-update-version', 'Machine Learning Feature Update');
        setText('feature-update-detail', 'The optional machine learning models are not installed yet.');
        if (featureUpdateButton) featureUpdateButton.textContent = 'Download Feature Update';
      }
    } catch {
      setText('feature-update-detail', 'Feature Update status could not be read.');
    }
  };

  const applyYaraStatus = async () => {
    if (!engine?.getYaraStatus) return;
    try {
      const result = await engine.getYaraStatus();
      if (!result?.ok) throw new Error(result?.message || 'YARA kullanılamıyor');
      setText('yara-status', `v${result.version} · ${result.rule_files} kural dosyası`);
    } catch {
      setText('yara-status', 'Kullanılamıyor');
    }
  };

  const renderWatchPaths = (paths) => {
    const list = document.querySelector('[data-role="watch-path-list"]');
    if (!list) return;
    list.replaceChildren();
    if (!paths.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Varsayılan olarak kullanıcı profilinizin tamamı ve geçici klasörler izlenir.';
      list.append(empty);
      return;
    }
    paths.forEach((watchedPath) => {
      const row = document.createElement('div');
      row.className = 'watch-path-row';
      const label = document.createElement('span');
      label.textContent = watchedPath;
      label.title = watchedPath;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.textContent = 'Kaldır';
      remove.addEventListener('click', async () => {
        remove.disabled = true;
        await saveSetting('watch_paths', (currentSettings?.watch_paths || []).filter((item) => item !== watchedPath));
      });
      row.append(label, remove);
      list.append(row);
    });
  };

  const renderSettings = (settings) => {
    currentSettings = settings;
    settingToggles.forEach((button) => {
      const key = button.dataset.settingToggle;
      const enabled = Boolean(settings[key]);
      button.classList.toggle('is-active', enabled);
      button.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      // The protection-page switches put the visual track in the first span,
      // so a bare querySelector('span') would overwrite the switch itself
      // with text. Those mark their text span with data-toggle-label.
      const label = button.querySelector('[data-toggle-label]') || button.querySelector('span');
      if (label) label.textContent = enabled ? 'Açık' : 'Kapalı';
      button.disabled = false;
    });
    setText('ransomware-protection-state', settings.ransomware_protection_enabled ? 'Etkin' : 'Kapalı');
    if (scanLimitSelect) {
      const limit = Number(settings.scan_max_files);
      scanLimitSelect.value = String(Number.isFinite(limit) ? limit : 1500);
      scanLimitSelect.disabled = false;
    }
    renderWatchPaths(Array.isArray(settings.watch_paths) ? settings.watch_paths : []);
    if (vtApiKeyInput && document.activeElement !== vtApiKeyInput) {
      vtApiKeyInput.value = typeof settings.virustotal_api_key === 'string' ? settings.virustotal_api_key : '';
    }
    if (mbApiKeyInput && document.activeElement !== mbApiKeyInput) {
      mbApiKeyInput.value = typeof settings.malwarebazaar_api_key === 'string' ? settings.malwarebazaar_api_key : '';
    }
    setText('settings-save-state', 'Tüm ayarlar bu bilgisayarda saklanıyor');
    const updateHours = Number(settings.signature_update_interval_hours) || 6;
    const lastSuccess = Number(settings.signature_update_last_success_at) || 0;
    const autoUpdateText = settings.signature_auto_update_enabled
      ? `${updateHours} saatte bir${lastSuccess ? ` · Son başarılı: ${formatScanDate(new Date(lastSuccess).toISOString())}` : ''}`
      : 'Kapalı';
    setText('signature-auto-status', autoUpdateText);
    if (settings.signature_update_last_error) {
      setText('signature-detail', `Son otomatik denetim: ${settings.signature_update_last_error}`);
    }
    if (!scanning) {
      setText('scan-page-summary', `${scanLimitText(settings.scan_max_files)} dosya incelenir. Dosyalara otomatik işlem uygulanmaz.`);
    }
  };

  const applySettings = async () => {
    if (!engine?.getSettings) return;
    try {
      const result = await engine.getSettings();
      if (!result?.ok || !result.settings) throw new Error('settings unavailable');
      renderSettings(result.settings);
    } catch {
      setText('settings-save-state', 'Ayarlar okunamadı');
    }
  };

  const renderAnalysisCacheStatus = (result) => {
    const entries = Number(result?.entries) || 0;
    const hits = Number(result?.hits) || 0;
    const misses = Number(result?.misses) || 0;
    const rate = Number(result?.hit_rate) || 0;
    setText('cache-summary', entries ? `${entries.toLocaleString('tr-TR')} kayıt hazır` : 'Önbellek boş');
    setText('cache-detail', entries
      ? `${formatBytes(result?.result_bytes)} yerel sonuç · ${hits + misses} kontrolde %${rate.toLocaleString('tr-TR')} isabet.`
      : 'İlk taramada sonuçlar hazırlanır; değişmeyen dosyalar sonraki taramalarda daha hızlı geçilir.');
  };

  const applyAnalysisCacheStatus = async () => {
    if (!engine?.getAnalysisCacheStatus) return;
    try {
      const result = await engine.getAnalysisCacheStatus();
      if (!result?.ok) throw new Error(result?.message || 'Önbellek okunamadı');
      renderAnalysisCacheStatus(result);
    } catch (error) {
      setText('cache-summary', 'Durum okunamadı');
      setText('cache-detail', error?.message || 'Tarama önbelleği kullanılamıyor.');
    }
  };

  const saveSetting = async (key, value) => {
    if (!engine?.updateSetting) return false;
    setText('settings-save-state', 'Kaydediliyor…');
    const result = await engine.updateSetting(key, value);
    if (!result?.ok || !result.settings) {
      setText('settings-save-state', result?.message || 'Ayar kaydedilemedi');
      if (currentSettings) renderSettings(currentSettings);
      return false;
    }
    renderSettings(result.settings);
    if (key === 'behavior_protection_enabled') {
      const enabled = Boolean(result.settings.behavior_protection_enabled);
      setBehaviorProtectionState(
        enabled,
        false,
        enabled ? 'Başlatılıyor' : 'Kapalı',
        enabled
          ? 'Davranış izleme başlatılıyor.'
          : 'Süreçler ve kalıcılık noktaları şu anda izlenmiyor.',
      );
    }
    if (key === 'protection_enabled' || key === 'behavior_protection_enabled' || key === 'web_protection_enabled') {
      await applyProtectionStatus();
    }
    return true;
  };

  const exclusionKindLabel = (kind) => ({
    folder: 'Klasör',
    extension: 'Uzantı',
    hash: 'Güvenilir dosya',
  }[kind] || 'İstisna');

  const renderExclusions = (result) => {
    const list = document.querySelector('[data-role="exclusion-list"]');
    const history = document.querySelector('[data-role="exclusion-history"]');
    if (!list || !history) return;
    const items = Array.isArray(result?.items) ? result.items : [];
    const events = Array.isArray(result?.history) ? result.history : [];
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Henüz bir istisna eklenmedi.';
      list.append(empty);
    }
    items.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'exclusion-row';
      const kind = document.createElement('span');
      kind.className = 'exclusion-kind';
      kind.textContent = exclusionKindLabel(item.kind);
      const value = document.createElement('span');
      value.className = 'exclusion-value';
      value.textContent = item.label || item.value;
      value.title = item.label ? `${item.label}\n${item.value}` : item.value;
      const remove = document.createElement('button');
      remove.className = 'exclusion-remove';
      remove.type = 'button';
      remove.textContent = 'Kaldır';
      remove.addEventListener('click', async () => {
        remove.disabled = true;
        const outcome = await engine?.removeExclusion?.(Number(item.id));
        if (!outcome?.ok) {
          remove.disabled = false;
          setText('exclusion-state', outcome?.message || 'İstisna kaldırılamadı');
          return;
        }
        renderExclusions(outcome);
        setText('exclusion-state', 'İstisna kaldırıldı · koruma kapsamı yenilendi');
      });
      row.append(kind, value, remove);
      list.append(row);
    });

    history.replaceChildren();
    if (!events.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Henüz değişiklik yok.';
      history.append(empty);
    }
    events.forEach((event) => {
      const row = document.createElement('div');
      row.className = 'exclusion-history-row';
      const action = document.createElement('strong');
      action.textContent = event.action === 'removed' ? 'Kaldırıldı' : 'Eklendi';
      const kind = document.createElement('span');
      kind.textContent = exclusionKindLabel(event.exclusion_kind);
      const value = document.createElement('span');
      value.textContent = event.exclusion_value;
      value.title = event.exclusion_value;
      const date = document.createElement('time');
      date.dateTime = event.occurred_at || '';
      date.textContent = formatScanDate(event.occurred_at);
      row.append(action, kind, value, date);
      history.append(row);
    });
  };

  const applyExclusions = async () => {
    if (!engine?.getExclusions) return;
    try {
      const result = await engine.getExclusions();
      if (!result?.ok) throw new Error(result?.message || 'İstisnalar okunamadı');
      renderExclusions(result);
      setText('exclusion-state', `${Array.isArray(result.items) ? result.items.length : 0} istisna etkin`);
    } catch (error) {
      setText('exclusion-state', error?.message || 'İstisnalar okunamadı');
    }
  };

  const updateScanResult = (title, detail) => {
    setText('scan-page-result-title', title);
    setText('scan-page-result-detail', detail);
  };

  const renderFindings = (findings) => {
    const list = document.querySelector('[data-role="finding-list"]');
    const count = document.querySelector('[data-role="finding-count"]');
    if (!list || !count) return;
    list.replaceChildren();
    if (!findings.length) {
      count.textContent = 'Bulgu yok';
      const empty = document.createElement('p');
      empty.className = 'history-empty';
      empty.textContent = 'Bu taramada gösterilecek test imzası veya inceleme işareti bulunmadı.';
      list.append(empty);
      return;
    }
    count.textContent = `${findings.length} bulgu`;
    findings.forEach((finding) => {
      const row = document.createElement('article');
      row.className = 'finding-row';
      const content = document.createElement('div');
      const title = document.createElement('h3');
      title.textContent = finding.path || 'Bilinmeyen dosya';
      const detail = document.createElement('p');
      detail.textContent = finding.reason || 'İnceleme işareti';
      content.append(title, detail);
      const badge = document.createElement('span');
      const signatureMatch = finding.kind === 'test-signature' || finding.kind === 'signature';
      badge.className = signatureMatch ? 'finding-badge' : 'finding-badge finding-badge--review';
      const findingLabel = finding.kind === 'test-signature'
        ? 'EICAR TEST'
        : signatureMatch ? 'İMZA'
          : finding.kind === 'yara' ? 'YARA'
            : finding.kind === 'pe-analysis' ? 'PE ANALİZİ'
              : finding.kind === 'archive-warning' ? 'ARŞİV UYARISI'
                : finding.kind === 'archive-structure' ? 'ARŞİV YAPISI' : 'İNCELEME';
      badge.textContent = Number.isFinite(finding.risk_score) && finding.risk_score > 0
        ? `${findingLabel} · ${finding.risk_score}/100`
        : findingLabel;
      const actions = document.createElement('div');
      actions.className = 'finding-actions';
      const action = document.createElement('button');
      action.className = 'finding-action';
      action.type = 'button';
      action.textContent = 'Karantinaya al';
      action.addEventListener('click', async () => {
        const actionablePath = finding.container_path || finding.path;
        const approved = window.confirm(`“${actionablePath}” dosyası Neutron karantina alanına taşınsın mı? Dosya silinmez.`);
        if (!approved) return;
        action.disabled = true;
        action.textContent = 'Taşınıyor…';
        const result = await engine?.addToQuarantine?.({ path: actionablePath, reason: finding.reason || 'Tarama bulgusu' });
        if (result?.ok) {
          action.textContent = 'Karantinaya alındı';
          applyQuarantine();
          return;
        }
        action.disabled = false;
        action.textContent = result?.message || 'Tekrar dene';
      });
      actions.append(action);
      if (/^[a-f0-9]{64}$/i.test(finding.sha256 || '')) {
        const trust = document.createElement('button');
        trust.className = 'finding-action finding-action--trust';
        trust.type = 'button';
        trust.textContent = 'Güvenilir say';
        trust.addEventListener('click', async () => {
          const approved = window.confirm(`“${finding.path}” dosyasının mevcut SHA-256 özeti güvenilir sayılsın mı? Dosya değişirse yeniden taranır.`);
          if (!approved) return;
          trust.disabled = true;
          trust.textContent = 'Kaydediliyor…';
          const result = await engine?.trustFileHash?.(finding.sha256, finding.path || 'Güvenilir dosya');
          if (!result?.ok) {
            trust.disabled = false;
            trust.textContent = result?.message || 'Tekrar dene';
            return;
          }
          trust.textContent = 'Güvenilir';
          action.disabled = true;
          applyExclusions();
        });
        actions.append(trust);
      }
      row.append(content, badge, actions);
      list.append(row);
    });
  };

  const applyQuarantine = async () => {
    const list = document.querySelector('[data-role="quarantine-list"]');
    const empty = document.querySelector('[data-role="quarantine-empty"]');
    if (!list || !empty || !engine?.getQuarantine) return;
    const result = await engine.getQuarantine();
    const items = Array.isArray(result?.items) ? result.items : [];
    list.replaceChildren();
    empty.hidden = items.length > 0;
    items.forEach((item) => {
      const row = document.createElement('article');
      row.className = 'quarantine-row';
      const content = document.createElement('div');
      const title = document.createElement('h2');
      title.textContent = item.file_name;
      const detail = document.createElement('p');
      detail.textContent = item.reason;
      const path = document.createElement('p');
      path.className = 'quarantine-row__path';
      path.textContent = item.original_path;
      content.append(title, detail, path);
      const actions = document.createElement('div');
      actions.className = 'quarantine-row__actions';
      const restore = document.createElement('button');
      restore.type = 'button'; restore.textContent = 'Geri yükle';
      restore.addEventListener('click', async () => {
        if (!window.confirm(`“${item.file_name}” dosyası eski konumuna geri yüklensin mi?`)) return;
        const outcome = await engine.restoreFromQuarantine(item.id);
        if (!outcome?.ok) window.alert(outcome?.message || 'Geri yükleme tamamlanamadı.');
        applyQuarantine();
      });
      const remove = document.createElement('button');
      remove.type = 'button'; remove.className = 'quarantine-delete'; remove.textContent = 'Kalıcı sil';
      remove.addEventListener('click', async () => {
        if (!window.confirm(`“${item.file_name}” kalıcı olarak silinsin mi? Bu işlem geri alınamaz.`)) return;
        const outcome = await engine.deleteFromQuarantine(item.id);
        if (!outcome?.ok) window.alert(outcome?.message || 'Silme tamamlanamadı.');
        applyQuarantine();
      });
      actions.append(restore, remove);
      row.append(content, actions);
      list.append(row);
    });
  };

  const applyFirewall = async () => {
    const list = document.querySelector('[data-role="firewall-rule-list"]');
    const empty = document.querySelector('[data-role="firewall-rule-empty"]');
    if (!list || !empty || !engine?.getFirewallRules) return;
    const result = await engine.getFirewallRules();
    const items = Array.isArray(result?.items) ? result.items : [];
    list.replaceChildren();
    empty.hidden = items.length > 0;
    items.forEach((item) => {
      const row = document.createElement('article');
      row.className = 'quarantine-row';
      const content = document.createElement('div');
      const title = document.createElement('h2');
      title.textContent = item.program_name;
      const detail = document.createElement('p');
      const actionLabel = item.action === 'allow' ? 'İzin veriliyor' : 'Engelleniyor';
      const directionLabel = item.direction === 'in' ? 'gelen' : 'giden';
      detail.textContent = `${actionLabel} · ${directionLabel} bağlantı${item.enabled ? '' : ' · kural kapalı'}`;
      const path = document.createElement('p');
      path.className = 'quarantine-row__path';
      path.textContent = item.program_path;
      content.append(title, detail, path);
      const actions = document.createElement('div');
      actions.className = 'quarantine-row__actions';
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.textContent = item.enabled ? 'Kapat' : 'Aç';
      toggle.addEventListener('click', async () => {
        toggle.disabled = true;
        const outcome = await engine.toggleFirewallRule(item.id, item.rule_name, !item.enabled);
        if (!outcome?.ok) window.alert(outcome?.message || 'Kural güncellenemedi.');
        applyFirewall();
      });
      const remove = document.createElement('button');
      remove.type = 'button'; remove.className = 'quarantine-delete'; remove.textContent = 'Kaldır';
      remove.addEventListener('click', async () => {
        if (!window.confirm(`“${item.program_name}” için güvenlik duvarı kuralı kaldırılsın mı?`)) return;
        remove.disabled = true;
        const outcome = await engine.removeFirewallRule(item.id, item.rule_name);
        if (!outcome?.ok) window.alert(outcome?.message || 'Kural kaldırılamadı.');
        applyFirewall();
      });
      actions.append(toggle, remove);
      row.append(content, actions);
      list.append(row);
    });
  };

  const addFirewallRuleWithFeedback = async (programPath, action) => {
    const result = await engine?.addFirewallRule?.(programPath, action, 'out');
    if (!result?.ok && !result?.cancelled) {
      window.alert(result?.message || 'Kural eklenemedi. Yönetici izni gerekiyor olabilir.');
    }
    applyFirewall();
    return result;
  };

  const applyFirewallRecentApps = async () => {
    const list = document.querySelector('[data-role="firewall-recent-apps-list"]');
    if (!list || !engine?.getFirewallRecentApps) return;
    const result = await engine.getFirewallRecentApps();
    const items = Array.isArray(result?.items) ? result.items : [];
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Ağa bağlı uygulama bulunamadı.';
      list.append(empty);
      return;
    }
    items.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'settings-preference';
      const info = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = item.name;
      const path = document.createElement('p');
      path.textContent = item.path;
      info.append(name, path);
      const actions = document.createElement('div');
      actions.className = 'quarantine-row__actions';
      const block = document.createElement('button');
      block.type = 'button'; block.textContent = 'Engelle';
      block.addEventListener('click', () => addFirewallRuleWithFeedback(item.path, 'block'));
      const allow = document.createElement('button');
      allow.type = 'button'; allow.textContent = 'İzin ver';
      allow.addEventListener('click', () => addFirewallRuleWithFeedback(item.path, 'allow'));
      actions.append(block, allow);
      row.append(info, actions);
      list.append(row);
    });
  };

  const applyStartupItems = async () => {
    const list = document.querySelector('[data-role="startup-item-list"]');
    if (!list || !engine?.getStartupItems) return;
    const result = await engine.getStartupItems();
    const items = Array.isArray(result?.items) ? result.items : [];
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Başlangıç öğesi bulunamadı.';
      list.append(empty);
      return;
    }
    items.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'settings-preference';
      const info = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = item.value_name;
      const detail = document.createElement('p');
      const locationLabel = item.source === 'registry' ? item.hive : 'Başlangıç klasörü';
      detail.textContent = `${locationLabel} · ${item.command}`;
      info.append(name, detail);
      const actions = document.createElement('div');
      actions.className = 'quarantine-row__actions';
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.textContent = item.enabled ? 'Kapat' : 'Aç';
      toggle.addEventListener('click', async () => {
        toggle.disabled = true;
        const outcome = item.enabled
          ? await engine.disableStartupItem(item)
          : await engine.restoreStartupItem(item.id);
        if (!outcome?.ok) window.alert(outcome?.message || 'İşlem tamamlanamadı.');
        applyStartupItems();
      });
      actions.append(toggle);
      row.append(info, actions);
      list.append(row);
    });
  };

  const applyVulnerableSoftware = async () => {
    const list = document.querySelector('[data-role="vulnerable-software-list"]');
    if (!list || !engine?.getVulnerableSoftware) return;
    const result = await engine.getVulnerableSoftware();
    const items = Array.isArray(result?.items) ? result.items : [];
    list.replaceChildren();
    if (!items.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Bilinen zafiyetli yazılım bulunamadı.';
      list.append(empty);
      return;
    }
    items.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'settings-preference';
      const info = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = `${item.name} ${item.version}`;
      const detail = document.createElement('p');
      detail.textContent = item.note;
      info.append(name, detail);
      row.append(info);
      list.append(row);
    });
  };

  const AUDIT_STATUS_LABELS = {
    pass: 'Geçti',
    warn: 'Uyarı',
    critical: 'Kritik',
    unknown: 'Denetlenemedi',
  };

  let auditFixInfo = {};

  const renderSystemAudit = (payload) => {
    const list = document.querySelector('[data-role="audit-check-list"]');
    if (!list) return;
    const checks = Array.isArray(payload?.checks) ? payload.checks : [];
    list.replaceChildren();

    if (!checks.length) {
      const empty = document.createElement('p');
      empty.className = 'settings-empty';
      empty.textContent = 'Denetim sonucu okunamadı.';
      list.append(empty);
      return;
    }

    // Worst first: a critical finding is what the reader has to act on, and
    // burying it under a column of green rows defeats the point of the page.
    const order = { critical: 0, warn: 1, unknown: 2, pass: 3 };
    [...checks]
      .sort((a, b) => (order[a.status] ?? 4) - (order[b.status] ?? 4))
      .forEach((check) => {
        const card = document.createElement('article');
        card.className = `audit-check audit-check--${check.status}`;

        const header = document.createElement('div');
        header.className = 'audit-check__header';
        const name = document.createElement('h3');
        name.textContent = check.title;
        const badge = document.createElement('span');
        badge.className = 'audit-check__badge';
        badge.textContent = AUDIT_STATUS_LABELS[check.status] || check.status;
        header.append(name, badge);

        const detail = document.createElement('p');
        detail.textContent = check.detail;
        card.append(header, detail);

        if (check.remedy && check.status !== 'pass') {
          const remedy = document.createElement('p');
          remedy.className = 'audit-check__remedy';
          remedy.textContent = check.remedy;
          card.append(remedy);
        }

        const fix = check.status !== 'pass' ? auditFixInfo[check.fix] : null;
        if (fix) {
          const state = document.createElement('p');
          state.className = 'audit-check__remedy';
          state.hidden = true;

          const button = document.createElement('button');
          button.className = 'settings-action';
          button.type = 'button';
          button.textContent = fix.label;
          button.addEventListener('click', async () => {
            if (!window.confirm(fix.confirm)) return;
            button.disabled = true;
            button.textContent = 'Uygulanıyor…';
            const result = await engine?.applyAuditFix?.(check.fix);
            if (result?.ok) {
              state.hidden = false;
              state.textContent = fix.note
                || (fix.restart
                  ? 'Uygulandı. Bilgisayarı yeniden başlattıktan sonra etkin olacak.'
                  : 'Uygulandı.');
              // A restart-gated fix still reads as unfixed, so re-running the
              // audit right after would only tell the user it failed. That
              // also means this card is not re-rendered, so the button has to
              // be settled here -- it used to stay disabled reading
              // "Uygulanıyor…" forever.
              if (!fix.restart) {
                await applySystemAudit();
                return;
              }
              button.textContent = 'Uygulandı';
              return;
            }
            state.hidden = false;
            state.textContent = result?.code === 'ELEVATION_CANCELLED'
              ? 'Yönetici izni verilmedi, hiçbir ayar değiştirilmedi.'
              : (result?.message || 'Düzeltme uygulanamadı.');
            button.disabled = false;
            button.textContent = fix.label;
          });
          card.append(button, state);
        }
        list.append(card);
      });

    const counts = payload?.counts || {};
    const critical = Number(counts.critical) || 0;
    const warn = Number(counts.warn) || 0;
    const pass = Number(counts.pass) || 0;
    const unknown = Number(counts.unknown) || 0;
    const score = Number(payload?.score) || 0;

    setText('audit-score', String(score));
    setText('audit-count-critical', String(critical));
    setText('audit-count-warn', String(warn));
    setText('audit-count-pass', String(pass));
    setText('audit-count-unknown', String(unknown));
    setText('audit-verdict', critical
      ? 'Acil müdahale gerekiyor'
      : (warn ? 'İyileştirilebilir' : 'Sertleştirme yeterli'));
    setText('audit-summary', critical || warn
      ? `${critical} kritik, ${warn} uyarı${unknown ? `, ${unknown} denetlenemedi` : ''}. Aşağıdaki kartlardan düzeltebilirsin.`
      : `Denetlenen ayarların hepsi güvenli tarafta${unknown ? `, ${unknown} ayar okunamadı` : ''}.`);

    // 2 * pi * r, with r = 52 as set on the circles in the markup.
    const circumference = 2 * Math.PI * 52;
    const ring = document.querySelector('[data-role="audit-ring"]');
    if (ring) {
      ring.style.strokeDasharray = String(circumference);
      ring.style.strokeDashoffset = String(circumference * (1 - Math.min(100, Math.max(0, score)) / 100));
    }

    const card = document.querySelector('.audit-score-card');
    card?.classList.remove('audit-score-card--critical', 'audit-score-card--warn', 'audit-score-card--pass');
    card?.classList.add(critical
      ? 'audit-score-card--critical'
      : (warn ? 'audit-score-card--warn' : 'audit-score-card--pass'));
  };

  const applySystemAudit = async () => {
    const button = document.querySelector('[data-action="run-system-audit"]');
    if (!engine?.runSystemAudit) return;
    if (button) {
      button.disabled = true;
      button.textContent = 'Denetleniyor…';
    }
    try {
      if (!Object.keys(auditFixInfo).length) {
        auditFixInfo = (await engine?.getAuditFixInfo?.()) || {};
      }
      const result = await engine.runSystemAudit();
      if (!result?.ok) {
        setText('audit-summary', result?.message || 'Sistem denetimi tamamlanamadı.');
        return;
      }
      renderSystemAudit(result);
      const checkedAt = result?.checked_at ? new Date(result.checked_at) : null;
      setText('audit-checked-at', checkedAt && !Number.isNaN(checkedAt.valueOf())
        ? `Son denetim: ${checkedAt.toLocaleString('tr-TR')} · yalnızca kayıt defteri okundu, hiçbir ayar değiştirilmedi.`
        : 'Denetim yalnızca kayıt defterini okur; hiçbir şey çalıştırmaz ve değiştirmez.');
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = 'Yeniden denetle';
      }
    }
  };

  document.querySelector('[data-action="run-system-audit"]')?.addEventListener('click', applySystemAudit);

  const tempCleanButton = document.querySelector('[data-action="clean-temp-files"]');
  let tempCleanableBytes = 0;

  const applyTempUsage = async () => {
    const button = document.querySelector('[data-action="scan-temp-files"]');
    if (!engine?.getTempUsage) return;
    if (button) { button.disabled = true; button.textContent = 'Hesaplanıyor…'; }
    try {
      const result = await engine.getTempUsage();
      if (!result?.ok) {
        setText('temp-usage-detail', result?.message || 'Geçici dosyalar hesaplanamadı.');
        return;
      }
      tempCleanableBytes = Number(result.total_bytes) || 0;
      setText('temp-usage-summary', `${formatBytes(tempCleanableBytes)} temizlenebilir`);
      const roots = Array.isArray(result.roots) ? result.roots : [];
      setText('temp-usage-detail', roots.length
        ? `${Number(result.total_files) || 0} dosya · ${roots.map((root) => `${root.path} (${formatBytes(root.bytes)})`).join(' · ')}`
        : 'Temizlenecek geçici dosya bulunamadı.');
      // Nothing to delete means nothing to confirm; keep the destructive
      // button unavailable rather than letting it run as a no-op.
      if (tempCleanButton) tempCleanButton.disabled = tempCleanableBytes <= 0;
    } finally {
      if (button) { button.disabled = false; button.textContent = 'Yeniden hesapla'; }
    }
  };

  document.querySelector('[data-action="scan-temp-files"]')?.addEventListener('click', applyTempUsage);

  tempCleanButton?.addEventListener('click', async () => {
    if (!engine?.cleanTempFiles) return;
    if (!window.confirm(
      `${formatBytes(tempCleanableBytes)} geçici dosya kalıcı olarak silinecek. Bu işlem geri alınamaz. Devam edilsin mi?`,
    )) return;
    tempCleanButton.disabled = true;
    tempCleanButton.textContent = 'Temizleniyor…';
    try {
      const result = await engine.cleanTempFiles();
      if (!result?.ok) {
        setText('temp-usage-detail', result?.message || 'Temizlik tamamlanamadı.');
        return;
      }
      const skipped = Number(result.skipped) || 0;
      setText('temp-usage-summary', `${formatBytes(result.removed_bytes)} temizlendi`);
      setText('temp-usage-detail', `${Number(result.removed_files) || 0} dosya silindi${
        skipped ? ` · ${skipped} dosya kullanımda olduğu için atlandı` : ''}.`);
      tempCleanableBytes = 0;
    } finally {
      tempCleanButton.textContent = 'Temizle';
      tempCleanButton.disabled = true;
    }
  });

  const renderMemoryStatus = (result) => {
    const used = Number(result.used_bytes) || 0;
    const total = Number(result.total_bytes) || 0;
    setText('memory-summary', `${formatBytes(used)} / ${formatBytes(total)} kullanımda (%${Number(result.load_percent) || 0})`);
    setText('memory-detail', `${Number(result.process_count) || 0} süreç okunabildi. Yönetici olmadan bazı sistem süreçleri görünmez.`);
    const list = document.querySelector('[data-role="memory-process-list"]');
    if (!list) return;
    list.replaceChildren();
    (Array.isArray(result.top_processes) ? result.top_processes : []).forEach((item) => {
      const row = document.createElement('div');
      row.className = 'performance-memory-row';
      const name = document.createElement('span');
      name.textContent = item.name || `PID ${item.pid}`;
      const size = document.createElement('strong');
      size.textContent = formatBytes(item.working_set_bytes);
      row.append(name, size);
      list.append(row);
    });
  };

  const applyMemoryStatus = async () => {
    if (!engine?.getMemoryStatus) return;
    const result = await engine.getMemoryStatus();
    if (!result?.ok) {
      setText('memory-detail', result?.message || 'Bellek durumu okunamadı.');
      return;
    }
    renderMemoryStatus(result);
  };

  document.querySelector('[data-action="read-memory-status"]')?.addEventListener('click', applyMemoryStatus);

  document.querySelector('[data-action="trim-memory"]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    if (!engine?.trimMemory) return;
    button.disabled = true;
    button.textContent = 'Küçültülüyor…';
    try {
      const result = await engine.trimMemory();
      if (!result?.ok) {
        setText('memory-detail', result?.message || 'Çalışma kümesi küçültülemedi.');
        return;
      }
      const freed = Number(result.freed_bytes) || 0;
      setText('memory-summary', `${formatBytes(result.total_bytes - result.after_available_bytes)} / ${formatBytes(result.total_bytes)} kullanımda (%${Number(result.load_percent) || 0})`);
      setText('memory-detail', freed > 0
        ? `${Number(result.trimmed_processes) || 0} sürecin çalışma kümesi küçültüldü, ${formatBytes(freed)} boşaldı. Windows gerekeni geri yükledikçe bu sayı düşer.`
        : `${Number(result.trimmed_processes) || 0} süreç işlendi ama ölçülebilir bir boşalma olmadı — bellek zaten sıkışık değildi.`);
      await applyMemoryStatus();
    } finally {
      button.disabled = false;
      button.textContent = 'Çalışma kümesini küçült';
    }
  });

  const applyMlShadowReport = async () => {
    const button = document.querySelector('[data-action="read-ml-shadow"]');
    const list = document.querySelector('[data-role="ml-shadow-thresholds"]');
    if (!engine?.getMlShadowReport || !list) return;
    if (button) { button.disabled = true; button.textContent = 'Okunuyor…'; }
    try {
      const result = await engine.getMlShadowReport();
      list.replaceChildren();
      if (!result?.ok) {
        setText('ml-shadow-summary', result?.message || 'Gölge raporu okunamadı.');
        return;
      }
      const total = Number(result.total) || 0;
      if (!total) {
        setText('ml-shadow-summary', 'Gözlem yok');
        const empty = document.createElement('p');
        empty.className = 'settings-empty';
        empty.textContent = result.message || 'Henüz gölge gözlem kaydedilmedi.';
        list.append(empty);
        return;
      }
      setText('ml-shadow-summary', `${total} dosya puanlandı · ${Number(result.trusted_total) || 0} tanesi geçerli imzalı`);

      const header = document.createElement('div');
      header.className = 'ml-threshold-row ml-threshold-row--header';
      ['Eşik', 'İşaretlenir', 'İmzalı', 'Yanlış pozitif oranı'].forEach((text) => {
        const cell = document.createElement('span');
        cell.textContent = text;
        header.append(cell);
      });
      list.append(header);

      (Array.isArray(result.thresholds) ? result.thresholds : []).forEach((item) => {
        const row = document.createElement('div');
        // Any signed file crossing the threshold is a file this build would
        // have quarantined by mistake, so the row is called out.
        const risky = Number(item.trusted_flagged) > 0;
        row.className = `ml-threshold-row${risky ? ' ml-threshold-row--risky' : ''}`;
        [
          `≥ ${item.threshold}`,
          `${item.flagged} (%${item.flagged_ratio})`,
          String(item.trusted_flagged),
          risky ? `%${item.trusted_flagged_ratio}` : 'temiz',
        ].forEach((text) => {
          const cell = document.createElement('span');
          cell.textContent = text;
          row.append(cell);
        });
        list.append(row);
      });
    } finally {
      if (button) { button.disabled = false; button.textContent = 'Yeniden oku'; }
    }
  };

  document.querySelector('[data-action="read-ml-shadow"]')?.addEventListener('click', applyMlShadowReport);

  pageTargets.forEach((target) => target.addEventListener('click', () => {
    showPage(target.dataset.pageTarget);
  }));

  scanModeTabs.forEach((tab) => tab.addEventListener('click', () => {
    if (!scanning) renderScanMode(tab.dataset.scanMode || 'quick');
  }));

  window.addEventListener('hashchange', () => showPage(pageNameFromHash(), { updateHash: false }));

  engine?.onProtectionEvent?.((event) => {
    if (!event || typeof event.type !== 'string') return;

    if (event.type === 'watch-ready') {
      const targetCount = Array.isArray(event.targets) ? event.targets.length : 0;
      const eventBased = event.backend === 'watchdog';
      setProtectionState(
        true,
        'Koruma etkin',
        eventBased
          ? `${targetCount || 2} klasör anlık dosya olaylarıyla izleniyor.`
          : `${targetCount || 2} klasör yedek zamanlanmış denetimle izleniyor.`
      );
      setText('engine-state', 'Gerçek zamanlı koruma etkin');
      return;
    }

    if (event.type === 'watch-checked') {
      setText('file-protection-detail', `Son kontrol: ${event.file_name || 'dosya'} — bulgu yok.`);
      return;
    }

    if (event.type === 'watch-initial-scan-complete') {
      setText('file-protection-detail', `Başlangıç denetimi tamamlandı · ${Number(event.scanned) || 0} mevcut dosya incelendi.`);
      return;
    }

    if (event.type === 'watch-finding') {
      const finding = event.finding || {};
      const quarantined = event.action === 'quarantined';
      if (quarantined) {
        activeThreatDetected = true;
        document.body.classList.add('threat-alert');
      }
      setText('activity-title', quarantined ? `${event.file_name || 'Bir dosya'} engellendi` : `${event.file_name || 'Bir dosya'} işaretlendi`);
      setText('activity-detail', quarantined ? `${finding.reason || 'Kesin imza eşleşmesi'}; dosya güvenli karantinaya taşındı.` : `${finding.reason || 'İnceleme gerekiyor'}; otomatik işlem uygulanmadı.`);
      setText('file-protection-detail', quarantined ? `${event.file_name || 'Dosya'} engellendi ve karantinaya alındı.` : `${event.file_name || 'Dosya'} inceleme için işaretlendi.`);
      if (quarantined) applyQuarantine();
      if (quarantined) setProtectionState(true, 'Tehdit engellendi', 'Kesin imza eşleşmesi güvenli karantinaya taşındı.');
      if (quarantined) applyThreatAlertState();
      applyProtectionHistory();
      return;
    }

    if (event.type === 'behavior-ready') {
      setBehaviorProtectionState(
        true,
        true,
        'Etkin',
        `${Number(event.process_count) || 0} çalışan süreç ve ${Number(event.persistence_points) || 0} otomatik başlangıç noktası izleniyor.`,
      );
      return;
    }

    if (event.type === 'behavior-finding') {
      const finding = event.finding || {};
      setText('activity-title', `${event.file_name || 'Bir davranış'} işaretlendi`);
      setText('activity-detail', `${finding.reason || 'Şüpheli davranış incelenmeli'}; otomatik işlem uygulanmadı.`);
      setText('overview-behavior-state', 'Uyarı');
      setText('behavior-protection-detail', finding.reason || 'Şüpheli davranış yerel geçmişe kaydedildi.');
      applyProtectionHistory();
      return;
    }

    if (event.type === 'behavior-stopped') {
      setBehaviorProtectionState(false, false, 'Kapalı', 'Davranış izleme durduruldu.');
      return;
    }

    if (event.type === 'behavior-error') {
      setBehaviorProtectionState(
        false, false, 'Kullanılamıyor',
        event.message || 'Davranış izleme motoru başlatılamadı.',
      );
      return;
    }

    // Bir bulgunun yalnız kaydedilmiş mi yoksa müdahale de edilmiş mi olduğu,
    // kullanıcı için tek önemli fark: hâlâ yapması gereken bir şey var mı?
    const withResponse = (reason, event, appliedText, skippedText) => {
      if (event.blocked) return `${reason} · ${appliedText}`;
      if (skippedText) return `${reason} · ${skippedText}`;
      return `${reason} · Otomatik müdahale uygulanmadı, incelemeniz gerekiyor.`;
    };

    // Sistem servisi izleyicileri: sürücü/servis kaydı, zamanlanmış görev ve
    // kendini koruma. Bunlar yalnız servis modunda olay gönderir ve kendi
    // kartları yok -- bulgular koruma geçmişine yazılır. Burada karşılığı
    // olmayan bir olay türü kullanıcı açısından görünmez demektir: geçmişte
    // durur ama kimse bakmaz, çünkü bakması gerektiğini söyleyen bir şey yok.
    if (event.type === 'driver-finding') {
      const finding = event.finding || {};
      const label = event.display_name || event.service_name || 'Bir sürücü kaydı';
      setText('activity-title', `${label} ${event.blocked ? 'engellendi' : 'işaretlendi'}`);
      setText('activity-detail', withResponse(
        finding.reason || 'Yeni ya da değiştirilmiş sürücü/servis kaydı algılandı.',
        event,
        'Servis devre dışı bırakıldı; yüklü sürücü yeniden başlatmaya kadar bellekte kalır.',
        event.block_skipped === 'boot-start'
          ? 'Önyükleme sürücüsü olduğu için devre dışı bırakılmadı: bu, Windows’un açılmamasına yol açabilirdi.'
          : event.block_skipped === 'trusted-signed'
            ? 'Geçerli bir Windows imzası taşıdığı için otomatik olarak devre dışı bırakılmadı; yalnız yeni sürücü kurulumları BYOVD kontrolü amacıyla bildirilir.'
            : '',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'task-finding') {
      const finding = event.finding || {};
      const label = String(event.task || '').split('/').pop() || 'Zamanlanmış görev';
      setText('activity-title', `${label} ${event.blocked ? 'devre dışı bırakıldı' : 'işaretlendi'}`);
      setText('activity-detail', withResponse(
        finding.reason || 'Yeni ya da değiştirilmiş zamanlanmış görev algılandı.',
        event,
        'Görev devre dışı bırakıldı.',
        event.block_skipped === 'microsoft-task'
          ? 'Windows’un kendi görevi olduğu için dokunulmadı.'
          : '',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'integrity-alert') {
      const finding = event.finding || {};
      setText('activity-title', 'Neutron bileşenlerinde sorun var');
      setText('activity-detail', finding.reason || 'Bir Neutron güvenlik bileşeni eksik ya da devre dışı.');
      applyProtectionHistory();
      return;
    }

    if (event.type === 'integrity-recovered') {
      setText('activity-detail', 'Neutron bileşen sorunu giderildi.');
      return;
    }

    // İkinci grup sistem servisi izleyicileri. Aynı gerekçe: kendi kartları
    // yok, bulgular koruma geçmişine yazılıyor, ve burada karşılığı olmayan
    // bir olay türü kullanıcı için görünmez demek.
    if (event.type === 'eventlog-finding') {
      const finding = event.finding || {};
      setText('activity-title', 'Windows olay günlüğünde şüpheli kayıt');
      setText('activity-detail', finding.reason || 'İzlenen bir Windows güvenlik olayı kaydedildi.');
      applyProtectionHistory();
      return;
    }

    if (event.type === 'posture-finding') {
      const finding = event.finding || {};
      setText('activity-title', event.blocked
        ? 'Windows güvenlik ayarı geri alındı'
        : 'Windows güvenlik ayarı zayıflatıldı');
      setText('activity-detail', withResponse(
        finding.reason || 'Bir Windows güvenlik ayarı kapatılmış.',
        event,
        'Ayar eski haline getirildi; Koruma geçmişinden geri alınabilir.',
        'Bu ayar otomatik olarak geri alınmıyor (uzaktan erişim ya da önyükleme yapılandırması).',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'posture-recovered') {
      setText('activity-detail', 'Windows güvenlik ayarı sorunu giderildi.');
      return;
    }

    if (event.type === 'certificate-finding') {
      const finding = event.finding || {};
      setText('activity-title', event.blocked
        ? 'Yeni sertifika güven deposundan kaldırıldı'
        : 'Güven deposuna yeni sertifika eklendi');
      setText('activity-detail', withResponse(
        finding.reason || 'Makine sertifika deposuna yeni bir sertifika eklendi.',
        event,
        'Sertifika kaldırıldı; Koruma geçmişinden geri yüklenebilir.',
        '',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'wmi-finding') {
      const finding = event.finding || {};
      setText('activity-title', event.blocked ? 'WMI kalıcılık kaydı silindi' : 'WMI kalıcılık kaydı değişti');
      setText('activity-detail', withResponse(
        finding.reason || 'Bir WMI olay aboneliği oluşturuldu ya da değiştirildi.',
        event,
        'Abonelik silindi. Bu işlem geri alınamaz; silinen tanım Koruma geçmişinde kayıtlı.',
        '',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'process-finding') {
      const finding = event.finding || {};
      const chain = Array.isArray(event.chain) && event.chain.length
        ? event.chain.join(' → ')
        : (event.file_name || 'Bir süreç');
      setText('activity-title', `${event.file_name || 'Bir süreç'} ${event.blocked ? 'sonlandırıldı' : 'işaretlendi'}`);
      setText('activity-detail', withResponse(
        `${finding.reason || 'Şüpheli süreç başlatma'} · ${chain}`,
        event,
        'Süreç sonlandırıldı.',
        event.block_skipped === 'trusted-signed'
          ? 'Geçerli bir Windows imzası taşıdığı için sonlandırılmadı; incelemeniz gerekiyor.'
          : '',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'credential-finding') {
      const finding = event.finding || {};
      setText('activity-title', event.blocked
        ? 'LSASS erişimi sonlandırıldı'
        : 'LSASS belleğine erişim algılandı');
      setText('activity-detail', withResponse(
        finding.reason || 'Bir süreç LSASS belleğini okuma erişimiyle açık tutuyor.',
        event,
        'Erişimi açık tutan süreç sonlandırıldı.',
        event.block_skipped === 'trusted-signed'
          ? 'Geçerli bir Windows imzası taşıdığı için sonlandırılmadı; incelemeniz gerekiyor.'
          : '',
      ));
      applyProtectionHistory();
      return;
    }

    if (event.type === 'web-ready') {
      setWebProtectionState(true, true, 'Etkin', 'İndirilen dosyalar ve kaynak adresleri yerel olarak denetleniyor.');
      return;
    }
    if (event.type === 'web-checked') {
      setText('overview-web-detail', `Son indirme denetlendi: ${event.file_name || 'dosya'}.`);
      return;
    }
    if (event.type === 'web-finding') {
      setText('overview-web-state', 'Uyarı');
      setText('overview-web-detail', `${event.file_name || 'İndirme'} zararlı kaynakla eşleşti.`);
      setText('web-protection-detail', event.finding?.reason || 'Zararlı indirme kaynağı algılandı.');
      applyProtectionHistory();
      return;
    }
    if (event.type === 'web-stopped') {
      setWebProtectionState(false, false, 'Kapalı', 'İndirme ve bağlantı itibarı denetimi kapalı.');
      return;
    }
    if (event.type === 'web-error') {
      setWebProtectionState(false, false, 'Kullanılamıyor', event.message || 'Web koruması başlatılamadı.');
      return;
    }

    if (event.type === 'watch-stopped') {
      setProtectionState(false, 'Koruma kapalı', 'Yeni ve değişen dosyalar şu anda izlenmiyor.');
      setText('engine-state', 'Gerçek zamanlı koruma kapalı');
      return;
    }

    if (event.type === 'watch-error') {
      setProtectionState(false, 'Koruma başlatılamadı', event.message || 'Koruma motoru kullanılamıyor.');
      setText('engine-state', 'Koruma motoru kullanılamıyor');
    }
  });

  engine?.onOpenProtectionEvent?.((payload) => {
    pendingProtectionEventId = Number.isInteger(payload?.eventId) ? payload.eventId : null;
    showPage('activity');
    applyProtectionHistory();
  });

  engine?.onProtonUpdateEvent?.((event) => {
    if (!event || typeof event.stage !== 'string') return;
    const progress = Number.isFinite(event.progress) ? ` %${event.progress}` : '';
    const states = {
      checking: ['Denetleniyor…', 'Proton güncellemeleri kontrol ediliyor.'],
      downloading: [`İndiriliyor${progress}`, `Proton ${event.version || ''} indiriliyor${progress}.`],
      verifying: ['Hazırlanıyor…', 'Güncelleme kullanıma hazırlanıyor.'],
      installing: ['Kuruluyor…', 'Proton güncellemesi uygulanıyor.'],
      current: ['Proton güncel', `Kurulu Proton ${event.version || ''} en yeni sürüm.`],
      complete: ['Proton güncel', `Proton ${event.version || ''} başarıyla kuruldu.`],
      revoked: ['Geri alınıyor…', `Proton ${event.version || ''} geri çekildi; doğrulanmış ${event.target || ''} sürümüne dönülüyor.`],
      'revoked-no-target': ['Tekrar dene', event.message || 'Kurulu Proton sürümü geri çekildi.'],
      'rolled-back': ['Proton güncel', `Doğrulanmış Proton ${event.version || ''} sürümüne dönüldü.`],
      error: ['Tekrar dene', event.message || 'Proton güncellenemedi.'],
    };
    const state = states[event.stage];
    if (!state) return;
    if (signatureUpdateButton) signatureUpdateButton.textContent = state[0];
    setText('signature-detail', state[1]);
    if (['complete', 'current', 'rolled-back', 'revoked-no-target'].includes(event.stage)) {
      applyEngineStatus();
      applySettings();
      applySignatureStatus();
    }
  });

  engine?.onFeatureUpdateEvent?.((event) => {
    if (!event || typeof event.stage !== 'string') return;
    const progress = Number.isFinite(event.progress) ? ` ${event.progress}%` : '';
    const states = {
      checking: ['Checking…', 'Checking GitHub Releases for a Machine Learning Feature Update.'],
      'downloading-manifest': ['Preparing…', `Verifying Feature Update ${event.version || ''}.`],
      downloading: [`Downloading${progress}`, `Downloading encrypted model components${progress}.`],
      installing: ['Installing…', 'The verified Feature Update is being activated.'],
      current: ['Up to date', `Machine Learning Feature Update ${event.version || ''} is current.`],
      complete: ['Up to date', `Machine Learning Feature Update ${event.version || ''} was installed successfully.`],
      revoked: ['Disabled', `Machine Learning Feature Update ${event.version || ''} was revoked and has been disabled on this device.`],
      error: ['Try Again', event.message || 'Feature Update could not be installed.'],
    };
    const state = states[event.stage];
    if (!state) return;
    if (featureUpdateButton) featureUpdateButton.textContent = state[0];
    setText('feature-update-detail', state[1]);
    if (event.stage === 'complete' || event.stage === 'current' || event.stage === 'revoked') applyFeatureUpdateStatus();
  });

  protectionToggle?.addEventListener('click', async () => {
    if (!engine?.startProtection || !engine?.stopProtection) return;
    protectionToggle.disabled = true;
    setText('protection-toggle-label', protectionEnabled ? 'Kapatılıyor' : 'Başlatılıyor');
    const result = protectionEnabled
      ? await engine.stopProtection()
      : await engine.startProtection();
    if (!result?.ok) {
      if (result?.code === 'CONFIRMATION_CANCELLED') {
        await applyProtectionStatus();
        return;
      }
      setProtectionState(false, 'Koruma başlatılamadı', result?.message || 'Koruma motoru kullanılamıyor.');
      return;
    }
    applySettings();
    if (!result.enabled) {
      setProtectionState(false, 'Koruma kapalı', 'Yeni ve değişen dosyalar şu anda izlenmiyor.');
    } else if (!result.ready) {
      setProtectionState(true, 'Koruma başlatılıyor', 'İzlenecek klasörlerin ilk görüntüsü hazırlanıyor.');
    }
  });

  behaviorProtectionToggle?.addEventListener('click', async () => {
    if (!engine?.updateSetting || typeof behaviorEnabled !== 'boolean') return;
    behaviorProtectionToggle.disabled = true;
    setText('behavior-toggle-label', behaviorEnabled ? 'Kapatılıyor' : 'Başlatılıyor');
    try {
      const result = await engine.updateSetting('behavior_protection_enabled', !behaviorEnabled);
      if (!result?.ok) throw new Error(result?.message || 'Davranış izleme değiştirilemedi.');
      if (result.settings) renderSettings(result.settings);
      await applyProtectionStatus();
    } catch (error) {
      const message = error?.message || 'Davranış izleme değiştirilemedi.';
      await applyProtectionStatus();
      setText('behavior-protection-detail', message);
      behaviorProtectionToggle.disabled = false;
    }
  });

  webProtectionToggle?.addEventListener('click', async () => {
    if (!engine?.updateSetting || typeof webEnabled !== 'boolean') return;
    webProtectionToggle.disabled = true;
    setText('web-toggle-label', webEnabled ? 'Kapatılıyor' : 'Başlatılıyor');
    try {
      const result = await engine.updateSetting('web_protection_enabled', !webEnabled);
      if (!result?.ok) throw new Error(result?.message || 'Web koruması değiştirilemedi.');
      if (result.settings) renderSettings(result.settings);
      await applyProtectionStatus();
    } catch (error) {
      const message = error?.message || 'Web koruması değiştirilemedi.';
      await applyProtectionStatus();
      setText('web-protection-detail', message);
      webProtectionToggle.disabled = false;
    }
  });

  amsiProtectionToggle?.addEventListener('click', async () => {
    if (!engine?.registerAmsiProtection || !engine?.unregisterAmsiProtection) return;
    amsiProtectionToggle.disabled = true;
    setText('amsi-toggle-label', amsiEnabled ? 'Kapatılıyor' : 'Etkinleştiriliyor');
    try {
      const result = amsiEnabled
        ? await engine.unregisterAmsiProtection()
        : await engine.registerAmsiProtection();
      if (!result?.ok) {
        const message = result?.code === 'ELEVATION_CANCELLED'
          ? 'Yönetici izni verilmedi, betik koruması açılamadı.'
          : (result?.message || 'Betik koruması değiştirilemedi.');
        throw new Error(message);
      }
      if (result.settings) currentSettings = result.settings;
      await applyProtectionStatus();
    } catch (error) {
      // Resync against what the machine actually has before showing the
      // error: the privileged step may have been declined, in which case the
      // toggle must go back to reflecting reality rather than the click.
      const message = error?.message || 'Betik koruması değiştirilemedi.';
      await applyProtectionStatus();
      setText('amsi-protection-detail', message);
      amsiProtectionToggle.disabled = false;
    }
  });

  watchdogProtectionToggle?.addEventListener('click', async () => {
    if (!engine?.registerWatchdogProtection || !engine?.unregisterWatchdogProtection) return;
    watchdogProtectionToggle.disabled = true;
    setText('watchdog-toggle-label', watchdogEnabled ? 'Kapatılıyor' : 'Etkinleştiriliyor');
    try {
      const result = watchdogEnabled
        ? await engine.unregisterWatchdogProtection()
        : await engine.registerWatchdogProtection();
      if (!result?.ok) {
        const message = result?.code === 'ELEVATION_CANCELLED'
          ? 'Yönetici izni verilmedi, watchdog açılamadı.'
          : (result?.message || 'Watchdog değiştirilemedi.');
        throw new Error(message);
      }
      if (result.settings) currentSettings = result.settings;
      await applyProtectionStatus();
    } catch (error) {
      const message = error?.message || 'Watchdog değiştirilemedi.';
      await applyProtectionStatus();
      setText('watchdog-protection-detail', message);
      watchdogProtectionToggle.disabled = false;
    }
  });

  wscProtectionToggle?.addEventListener('click', async () => {
    if (!engine?.registerWscProtection || !engine?.unregisterWscProtection) return;
    wscProtectionToggle.disabled = true;
    setText('wsc-toggle-label', wscEnabled ? 'Kapatılıyor' : 'Etkinleştiriliyor');
    try {
      const result = wscEnabled
        ? await engine.unregisterWscProtection()
        : await engine.registerWscProtection();
      if (!result?.ok) {
        const message = result?.code === 'ELEVATION_CANCELLED'
          ? 'Yönetici izni verilmedi, kayıt yapılamadı.'
          : (result?.message || 'Güvenlik Merkezi kaydı değiştirilemedi.');
        throw new Error(message);
      }
      if (result.settings) currentSettings = result.settings;
      await applyProtectionStatus();
    } catch (error) {
      const message = error?.message || 'Güvenlik Merkezi kaydı değiştirilemedi.';
      await applyProtectionStatus();
      setText('wsc-protection-detail', message);
      wscProtectionToggle.disabled = false;
    }
  });

  serviceProtectionToggle?.addEventListener('click', async () => {
    if (!engine?.installProtectionService || !engine?.uninstallProtectionService) return;
    serviceProtectionToggle.disabled = true;
    setText('service-toggle-label', serviceEnabled ? 'Kapatılıyor' : 'Kuruluyor');
    try {
      const result = serviceEnabled
        ? await engine.uninstallProtectionService()
        : await engine.installProtectionService();
      if (!result?.ok) {
        const message = result?.code === 'ELEVATION_CANCELLED'
          ? 'Yönetici izni verilmedi, servis kurulamadı.'
          : (result?.message || 'Sistem servisi modu değiştirilemedi.');
        throw new Error(message);
      }
      if (result.settings) currentSettings = result.settings;
      await applyProtectionStatus();
    } catch (error) {
      const message = error?.message || 'Sistem servisi modu değiştirilemedi.';
      await applyProtectionStatus();
      setText('service-protection-detail', message);
      serviceProtectionToggle.disabled = false;
    }
  });

  webCheckForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const url = webCheckInput?.value?.trim();
    if (!url || !engine?.openSafeUrl) return;
    const submit = webCheckForm.querySelector('button');
    if (submit) submit.disabled = true;
    setText('web-check-result', 'Bağlantı yerel veritabanında denetleniyor…');
    try {
      const result = await engine.openSafeUrl(url);
      if (!result?.ok) throw new Error(result?.message || 'Bağlantı denetlenemedi.');
      setText('web-check-result', result.safe
        ? `Temiz: ${result.host} denetlendi ve tarayıcıda açıldı.`
        : `ENGELLENDİ: ${result.name || result.matched_value} · ${result.severity || 'yüksek'} risk.`);
      webCheckForm.classList.toggle('is-danger', !result.safe);
      webCheckForm.classList.toggle('is-safe', result.safe);
    } catch (error) {
      setText('web-check-result', error?.message || 'Bağlantı denetlenemedi.');
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  signatureUpdateButton?.addEventListener('click', async () => {
    if (!engine?.updateSignatures) return;
    signatureUpdateButton.disabled = true;
    signatureUpdateButton.textContent = 'Denetleniyor…';
    try {
      const result = await engine.updateSignatures();
      if (!result?.ok) throw new Error(result?.message || 'İmzalar güncellenemedi.');
      const count = Number(result.signature_count) || 0;
      const databaseName = result.database_name || 'Proton';
      signatureLabel = `${databaseName} ${result.version || '1.00.001'}`;
      setText('database-state', signatureLabel);
      setText('signature-version', `${databaseName} ${result.version || '1.00.001'}`);
      const outcome = result.updated
        ? `Proton ${result.version || ''} güncellendi · ${count} etkin tehdit tanımı.`
        : (result.message || `${count} etkin tehdit tanımı kullanılıyor.`);
      setText('signature-detail', result.archive_warning ? `${outcome} ${result.archive_warning}` : outcome);
      signatureUpdateButton.textContent = 'Proton güncel';
    } catch (error) {
      setText('signature-detail', error?.message || 'Yerel imzalar denetlenemedi.');
      signatureUpdateButton.textContent = 'Tekrar dene';
    } finally {
      signatureUpdateButton.disabled = false;
    }
  });

  signatureRollbackButton?.addEventListener('click', async () => {
    if (!engine?.rollbackSignatures) return;
    const version = signatureRollbackButton.dataset.version || '';
    if (!version || !window.confirm(`Proton ${version} sürümüne geri dönülsün mü?`)) return;
    signatureRollbackButton.disabled = true;
    try {
      const result = await engine.rollbackSignatures(version);
      if (!result?.ok) throw new Error(result?.message || 'Proton geri alınamadı.');
      await applySignatureStatus();
      await applyYaraStatus();
    } catch (error) {
      setText('signature-detail', error?.message || 'Proton geri alınamadı.');
    } finally {
      signatureRollbackButton.disabled = false;
    }
  });

  featureUpdateButton?.addEventListener('click', async () => {
    if (!engine?.updateFeatures) return;
    featureUpdateButton.disabled = true;
    featureUpdateButton.textContent = 'Checking…';
    try {
      const result = await engine.updateFeatures();
      if (!result?.ok) throw new Error(result?.message || 'Feature Update could not be installed.');
      await applyFeatureUpdateStatus();
      if (result.message) setText('feature-update-detail', result.message);
    } catch (error) {
      setText('feature-update-detail', error?.message || 'Feature Update could not be installed.');
      featureUpdateButton.textContent = 'Try Again';
    } finally {
      featureUpdateButton.disabled = false;
    }
  });

  clearAnalysisCacheButton?.addEventListener('click', async () => {
    if (!engine?.clearAnalysisCache) return;
    clearAnalysisCacheButton.disabled = true;
    clearAnalysisCacheButton.textContent = 'Temizleniyor…';
    try {
      const result = await engine.clearAnalysisCache();
      if (!result?.ok) throw new Error(result?.message || 'Önbellek temizlenemedi.');
      renderAnalysisCacheStatus(result);
      clearAnalysisCacheButton.textContent = 'Önbellek temizlendi';
    } catch (error) {
      setText('cache-detail', error?.message || 'Tarama önbelleği temizlenemedi.');
      clearAnalysisCacheButton.textContent = 'Tekrar dene';
    } finally {
      window.setTimeout(() => {
        clearAnalysisCacheButton.disabled = false;
        clearAnalysisCacheButton.textContent = 'Önbelleği temizle';
      }, 900);
    }
  });

  settingToggles.forEach((button) => button.addEventListener('click', async () => {
    const key = button.dataset.settingToggle;
    if (!key || !currentSettings) return;
    button.disabled = true;
    await saveSetting(key, !Boolean(currentSettings[key]));
  }));

  scanLimitSelect?.addEventListener('change', async () => {
    scanLimitSelect.disabled = true;
    await saveSetting('scan_max_files', Number(scanLimitSelect.value));
  });

  chooseFirewallAppButton?.addEventListener('click', async () => {
    if (!engine?.chooseFirewallApp) return;
    chooseFirewallAppButton.disabled = true;
    try {
      const selection = await engine.chooseFirewallApp();
      if (!selection?.ok || !selection.path) return;
      await addFirewallRuleWithFeedback(selection.path, 'block');
    } finally {
      chooseFirewallAppButton.disabled = false;
    }
  });

  scanVulnerableSoftwareButton?.addEventListener('click', async () => {
    scanVulnerableSoftwareButton.disabled = true;
    scanVulnerableSoftwareButton.textContent = 'Taranıyor…';
    try {
      await applyVulnerableSoftware();
    } finally {
      scanVulnerableSoftwareButton.disabled = false;
      scanVulnerableSoftwareButton.textContent = 'Yeniden tara';
    }
  });

  addWatchFolderButton?.addEventListener('click', async () => {
    if (!engine?.chooseWatchFolder || !currentSettings) return;
    addWatchFolderButton.disabled = true;
    try {
      const selection = await engine.chooseWatchFolder();
      if (!selection?.ok || !selection.path) return;
      const paths = [...new Set([...(currentSettings.watch_paths || []), selection.path])];
      await saveSetting('watch_paths', paths);
    } finally {
      addWatchFolderButton.disabled = false;
    }
  });

  addExclusionFolderButton?.addEventListener('click', async () => {
    if (!engine?.addExclusionFolder) return;
    addExclusionFolderButton.disabled = true;
    setText('exclusion-state', 'Klasör seçiliyor…');
    try {
      const result = await engine.addExclusionFolder();
      if (result?.cancelled) {
        setText('exclusion-state', 'Klasör seçimi iptal edildi');
        return;
      }
      if (!result?.ok) {
        setText('exclusion-state', result?.message || 'Klasör eklenemedi');
        return;
      }
      renderExclusions(result);
      setText('exclusion-state', 'Klasör istisnası etkin · koruma kapsamı yenilendi');
    } finally {
      addExclusionFolderButton.disabled = false;
    }
  });

  exclusionExtensionForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const extension = exclusionExtensionInput?.value?.trim();
    if (!extension || !engine?.addExclusionExtension) return;
    const submit = exclusionExtensionForm.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    setText('exclusion-state', 'Uzantı ekleniyor…');
    try {
      const result = await engine.addExclusionExtension(extension);
      if (!result?.ok) {
        setText('exclusion-state', result?.message || 'Uzantı eklenemedi');
        return;
      }
      if (exclusionExtensionInput) exclusionExtensionInput.value = '';
      renderExclusions(result);
      setText('exclusion-state', 'Uzantı istisnası etkin · koruma kapsamı yenilendi');
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  mbApiKeyForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = mbApiKeyForm.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    setText('mb-api-key-state', 'Kaydediliyor…');
    try {
      const saved = await saveSetting('malwarebazaar_api_key', mbApiKeyInput?.value?.trim() || '');
      setText('mb-api-key-state', saved ? 'Anahtar kaydedildi.' : 'Anahtar kaydedilemedi.');
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  vtApiKeyForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = vtApiKeyForm.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    setText('vt-api-key-state', 'Kaydediliyor…');
    try {
      const saved = await saveSetting('virustotal_api_key', vtApiKeyInput?.value?.trim() || '');
      setText('vt-api-key-state', saved ? 'Anahtar kaydedildi.' : 'Anahtar kaydedilemedi.');
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  engine?.onScanEvent?.((event) => {
    if (!event || typeof event.type !== 'string') return;

    if (event.type === 'started') {
      scanning = true;
      const modeLabel = event.mode === 'full' ? 'Tam tarama' : event.mode === 'custom' ? 'Özel tarama' : 'Hızlı tarama';
      setText('engine-state', `${modeLabel} sürüyor`);
      setText('protection-label', 'TARAMA SÜRÜYOR');
      setText('scan-heading', 'Neutron dosyaları inceliyor.');
      setText('scan-summary', 'Dosyalar yalnız okunuyor; hiçbir dosya silinmez veya taşınmaz.');
      setText('scan-page-heading', 'Tarama devam ediyor');
      setText('scan-page-summary', 'Dosyalar yalnız okunuyor. Tarama sırasında hiçbir işlem uygulanmaz.');
      setText('activity-title', `${modeLabel} başlatıldı`);
      setText('activity-detail', `${event.targets.join(' ve ')} hedefi inceleniyor.`);
      updateScanResult(`${modeLabel} başlatıldı`, 'Dosya listesi hazırlanıyor.');
      renderFindings([]);
      return;
    }

    if (event.type === 'progress') {
      const hits = Number(event.cache_hits) || 0;
      const detail = `${event.scanned} dosya tarandı.${hits ? ` ${hits} değişmeyen dosya önbellekten doğrulandı.` : ''} Güvenli salt-okunur kontrol devam ediyor.`;
      setButtons(`${event.scanned} dosya inceleniyor`, true);
      setText('scan-summary', detail);
      setText('scan-page-summary', detail);
      updateScanResult('Tarama devam ediyor', detail);
      return;
    }

    if (event.type === 'complete') {
      scanning = false;
      const confirmed = Number(event.confirmed_count) || 0;
      const review = Number(event.review_count) || 0;
      const cacheHits = Number(event.cache_hits) || 0;
      const resultTitle = confirmed > 0 ? `${confirmed} imza eşleşmesi bulundu` : 'Doğrulanmış tehdit bulunmadı';
      const detail = `${event.scanned} dosya ${formatDuration(event.elapsed_ms)} içinde incelendi.${cacheHits ? ` ${cacheHits} değişmeyen dosya önbellekten doğrulandı.` : ''}${event.limited ? ' Tarama güvenlik sınırına ulaştı.' : ''}`;
      setReadyState();
      renderScanMode(selectedScanMode);
      setText('last-scan', 'Az önce');
      setText('threat-count', String(confirmed));
      setText('scan-page-heading', resultTitle);
      setText('scan-page-summary', detail);
      setText('activity-title', resultTitle);
      setText('activity-detail', review > 0 ? `${review} dosya yalnızca inceleme için işaretlendi; hiçbir işlem uygulanmadı.` : 'Salt-okunur hızlı tarama tamamlandı; hiçbir dosyaya işlem uygulanmadı.');
      updateScanResult(resultTitle, detail);
      renderFindings(Array.isArray(event.findings) ? event.findings : []);
      applyHistory();
      return;
    }

    if (event.type === 'error') {
      scanning = false;
      setReadyState();
      renderScanMode(selectedScanMode);
      const message = event.message || 'Beklenmeyen bir motor hatası oluştu.';
      setText('engine-state', 'Tarama başlatılamadı');
      setText('scan-page-heading', 'Tarama tamamlanamadı');
      setText('scan-page-summary', message);
      setText('activity-title', 'Tarama hatası');
      setText('activity-detail', message);
      updateScanResult('Tarama tamamlanamadı', message);
      return;
    }

    if (event.type === 'cancelled') {
      scanning = false;
      setReadyState();
      renderScanMode(selectedScanMode);
      const message = 'Tarama kullanıcı tarafından iptal edildi.';
      setText('scan-page-heading', 'Tarama iptal edildi');
      setText('scan-page-summary', message);
      setText('activity-title', 'Tarama iptal edildi');
      setText('activity-detail', message);
      updateScanResult('Tarama iptal edildi', message);
    }
  });

  cancelScanButton?.addEventListener('click', async () => {
    if (!scanning || !engine?.cancelScan) return;
    cancelScanButton.disabled = true;
    await engine.cancelScan();
  });

  quickScanButtons.forEach((button) => button.addEventListener('click', async () => {
    if (scanning) return;
    if (button === heroPrimaryAction && protectionEnabled === false) {
      if (!engine?.startProtection) return;
      button.disabled = true;
      const label = button.querySelector('[data-action-label]');
      if (label) label.textContent = 'Koruma başlatılıyor';
      const result = await engine.startProtection();
      if (!result?.ok) {
        setProtectionState(false, 'Koruma başlatılamadı', result?.message || 'Koruma motoru kullanılamıyor.');
        return;
      }
      applySettings();
      await applyProtectionStatus();
      return;
    }
    const scanPageButton = button !== heroPrimaryAction;
    if (scanPageButton && selectedScanMode === 'custom') {
      showPage('scan');
      setButtons('Seçim bekleniyor', true);
      const result = await engine?.chooseCustomScan?.();
      if (result?.cancelled) {
        setButtons('Hızlı tarama başlat', false);
        renderScanMode('custom');
        return;
      }
      if (!result?.ok) {
        setReadyState();
        updateScanResult('Tarama başlatılamadı', result?.message || 'Dosya veya klasör seçilemedi.');
      }
      return;
    }
    if (scanPageButton && selectedScanMode === 'full') {
      if (!selectedFullScanDrive) {
        updateScanResult('Sürücü seçilmedi', 'Tam tarama için önce bir sürücü seçin.');
        return;
      }
      showPage('scan');
      setButtons('Tarama hazırlanıyor', true);
      const result = await engine?.startFullScan?.(selectedFullScanDrive);
      if (!result?.ok) {
        setReadyState();
        updateScanResult('Tarama başlatılamadı', result?.message || 'Sürücü taraması başlatılamadı.');
      }
      return;
    }
    if (!engine?.startQuickScan) return;
    showPage('scan');
    setButtons('Tarama hazırlanıyor', true);
    const result = await engine.startQuickScan();
    if (!result?.ok) {
      scanning = false;
      setReadyState();
      const message = result?.message || 'Tarama başlatılamadı.';
      setText('scan-summary', message);
      setText('scan-page-summary', message);
      updateScanResult('Tarama başlatılamadı', message);
    }
  }));

  document.querySelector('[data-action="check-for-update"]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    setText('update-detail', 'Güncellemeler denetleniyor…');
    try {
      const result = await engine?.checkForAppUpdate?.();
      setText('update-detail', result?.ok
        ? 'Denetim başlatıldı. Güncelleme bulunursa bildirim gösterilecek.'
        : (result?.message || 'Güncelleme denetimi yalnızca kurulu sürümde çalışır.'));
    } finally {
      button.disabled = false;
    }
  });

  document.querySelector('[data-action="prepare-uninstall"]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    if (!window.confirm('Watchdog, AMSI, WSC ve güvenlik duvarı kayıtları kaldırılsın mı? Yönetici izni istenecek.')) return;
    button.disabled = true;
    const originalText = button.textContent;
    button.textContent = 'Hazırlanıyor…';
    try {
      const result = await engine?.prepareUninstall?.();
      button.textContent = result?.ok ? 'Kaldırmaya hazır' : 'Tamamlanamadı';
      // The failure text names the components that could not be removed and
      // is far too long for a button label, where it used to be dumped.
      setText('prepare-uninstall-detail', result?.ok
        ? 'Watchdog, AMSI, Güvenlik Merkezi, servis ve güvenlik duvarı kayıtları kaldırıldı. Neutron\'u şimdi Denetim Masası\'ndan kaldırabilirsin.'
        : (result?.code === 'ELEVATION_CANCELLED'
          ? 'Yönetici izni verilmedi, hiçbir kayıt kaldırılmadı.'
          : (result?.message || 'İşlem tamamlanamadı.')));
    } finally {
      setTimeout(() => {
        button.disabled = false;
        button.textContent = originalText;
      }, 3000);
    }
  });

  folderScanButtons.forEach((button) => button.addEventListener('click', async () => {
    if (scanning || !engine?.chooseFolderAndScan) return;
    setButtons('Klasör seçiliyor', true);
    const result = await engine.chooseFolderAndScan();
    if (result?.cancelled) {
      setReadyState();
      return;
    }
    if (!result?.ok) {
      scanning = false;
      setReadyState();
      const message = result?.message || 'Klasör taraması başlatılamadı.';
      setText('scan-page-summary', message);
      updateScanResult('Tarama başlatılamadı', message);
    }
  }));

  initializeLicense();
  setReadyState();
  renderScanMode('quick');
  showPage(pageNameFromHash(), { updateHash: false });
  applyHistory();
  applyProtectionHistory();
  applySignatureStatus();
  applyFeatureUpdateStatus();
  applyYaraStatus();
  applySettings();
  renderLicenseAccount();
  applyExclusions();
  applyAnalysisCacheStatus();
  applyProtectionStatus();
  applyAppVersion();
})();

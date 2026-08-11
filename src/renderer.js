(() => {
  'use strict';

  const engine = window.neutronEngine;
  const dashboard = document.querySelector('.dashboard');
  const pages = [...document.querySelectorAll('.app-page[data-page]')];
  const pageTargets = [...document.querySelectorAll('[data-page-target]')];
  const quickScanButtons = [...document.querySelectorAll('[data-action="quick-scan"]')];
  const folderScanButtons = [...document.querySelectorAll('[data-action="choose-folder-scan"]')];
  const protectionToggle = document.querySelector('[data-action="toggle-protection"]');
  const signatureUpdateButton = document.querySelector('[data-action="update-signatures"]');
  const settingToggles = [...document.querySelectorAll('[data-setting-toggle]')];
  const scanLimitSelect = document.querySelector('[data-setting-select="scan_max_files"]');
  const addWatchFolderButton = document.querySelector('[data-action="add-watch-folder"]');
  const addExclusionFolderButton = document.querySelector('[data-action="add-exclusion-folder"]');
  const exclusionExtensionForm = document.querySelector('[data-role="exclusion-extension-form"]');
  const exclusionExtensionInput = document.querySelector('[data-role="exclusion-extension-input"]');
  const textTargets = (role) => [...document.querySelectorAll(`[data-role="${role}"]`)];
  let scanning = false;
  let protectionEnabled = null;
  let behaviorReady = null;
  let signatureLabel = 'Proton hazırlanıyor';
  let currentSettings = null;
  let pendingProtectionEventId = null;

  const setText = (role, value) => textTargets(role).forEach((element) => {
    element.textContent = value;
  });

  const formatDuration = (milliseconds) => {
    const value = Number(milliseconds) || 0;
    return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} sn`;
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
  };

  const pageNameFromHash = () => window.location.hash.slice(1);

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
    if (pageName === 'settings') {
      applySettings();
      applyExclusions();
    }
  };

  const setReadyState = () => {
    const scanLimit = Number(currentSettings?.scan_max_files) || 1500;
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
      ? 'Masaüstü ve İndirilenler klasörlerindeki yeni ve değişen dosyalar izleniyor.'
      : 'Gerçek zamanlı dosya izleme kapalı. Koruma sayfasından yeniden açabilirsiniz.');
    setText('scan-page-heading', 'Masaüstü ve İndirilenler');
    setText('scan-page-summary', `En fazla ${scanLimit.toLocaleString('tr-TR')} dosya incelenir. Dosyalar silinmez, taşınmaz veya karantinaya alınmaz.`);
    setButtons('Hızlı tarama başlat', false);
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
    setText('dashboard-state-heading', enabled ? 'Bilgisayarınız izleniyor.' : 'Koruma kapalı.');
    setText('dashboard-state-detail', enabled
      ? 'Yeni ve değişen dosyalar Neutron tarafından yerel olarak denetleniyor.'
      : 'Yeni ve değişen dosyalar izlenmiyor. Koruma sayfasından korumayı açın.');
    setText('overview-file-protection-state', enabled ? 'Koruma etkin' : 'Koruma kapalı');
    if (!enabled) {
      behaviorReady = false;
      setText('overview-behavior-state', 'Koruma kapalı');
      setText('behavior-protection-state', 'Koruma kapalı');
      setText('behavior-protection-detail', 'Süreçler ve kalıcılık noktaları şu anda izlenmiyor.');
    } else if (behaviorReady === true) {
      setText('overview-behavior-state', 'Davranış izleme etkin');
      setText('behavior-protection-state', 'Etkin');
      setText('behavior-protection-detail', 'Yeni süreçler ve Windows otomatik başlangıç noktaları izleniyor.');
    } else {
      setText('overview-behavior-state', 'Başlatılıyor');
      setText('behavior-protection-state', 'Başlatılıyor');
      setText('behavior-protection-detail', 'Süreç ve kalıcılık başlangıç görüntüsü hazırlanıyor.');
    }
    setText('protection-label', enabled ? 'KORUMA ETKİN' : 'KORUMA KAPALI');
    setText('scan-heading', enabled ? 'Neutron seni koruyor.' : 'Korumayı açın.');
    setText('scan-summary', enabled
      ? 'Masaüstü ve İndirilenler klasörlerindeki yeni ve değişen dosyalar izleniyor.'
      : 'Gerçek zamanlı dosya izleme kapalı. Koruma sayfasından yeniden açabilirsiniz.');
    setText('protection-toggle-label', enabled ? 'Kapat' : 'Aç');
    if (protectionToggle) {
      protectionToggle.classList.toggle('is-active', enabled);
      protectionToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      protectionToggle.disabled = false;
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
      row.className = 'history-row glass-dom-surface';

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
    const criticalPending = pendingEvents.some((event) => ['high', 'critical'].includes(event.severity));
    const hadThreatAlert = document.body.classList.contains('threat-alert');
    document.body.classList.toggle('threat-alert', criticalPending);
    if (criticalPending) {
      setText('engine-state', 'Tehdit müdahalesi gerekiyor');
      setText('protection-label', 'TEHDİT BULUNDU');
      setText('file-protection-detail', `${pendingEvents.length} gerçek zamanlı koruma olayı işlem bekliyor.`);
    } else if (hadThreatAlert && !scanning) {
      setReadyState();
    }
    count.textContent = pendingEvents.length
      ? `${pendingEvents.length} müdahale bekliyor · ${events.length} olay`
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
      row.classList.toggle('is-resolved', disposition !== 'pending');
      row.classList.toggle('is-critical', disposition === 'pending' && ['high', 'critical'].includes(event.severity));
      const content = document.createElement('div');
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
            : event.finding_kind === 'behavior' ? 'DAVRANIŞ'
              : event.finding_kind === 'persistence' ? 'KALICILIK' : 'İNCELEME';
      const stamp = document.createElement('time');
      stamp.textContent = formatScanDate(event.occurred_at);
      const dispositionLabel = document.createElement('strong');
      dispositionLabel.className = `protection-disposition protection-disposition--${disposition}`;
      dispositionLabel.textContent = ({
        pending: 'MÜDAHALE BEKLİYOR',
        quarantined: 'KARANTİNADA',
        trusted: 'GÜVENİLİR',
        ignored: 'YOK SAYILDI',
      }[disposition] || disposition.toLocaleUpperCase('tr-TR'));
      meta.append(badge, dispositionLabel, stamp);
      const actions = document.createElement('div');
      actions.className = 'protection-event-row__actions';
      if (disposition === 'pending') {
        const actionDefinitions = [
          ['quarantine', 'Karantinaya al'],
          ['trust', 'Güvenilir say'],
          ['ignore', 'Yoksay'],
        ];
        actionDefinitions.forEach(([actionName, label]) => {
          if (event.finding_kind === 'persistence' && actionName !== 'ignore') return;
          if (actionName === 'trust' && !/^[a-f0-9]{64}$/i.test(event.sha256 || '')) return;
          const button = document.createElement('button');
          button.type = 'button';
          button.dataset.protectionAction = actionName;
          button.textContent = label;
          button.addEventListener('click', async () => {
            const confirmations = {
              quarantine: `“${event.file_path}” karantinaya taşınsın mı? Dosya silinmez.`,
              trust: `Bu dosyanın mevcut SHA-256 özeti güvenilir sayılsın mı? Dosya değişirse yeniden taranır.`,
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
            if (actionName === 'trust') applyExclusions();
            applyProtectionHistory();
          });
          actions.append(button);
        });
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
      setText('signature-detail', `${count} etkin tehdit tanımı · Proton kullanıma hazır.`);
    } catch {
      signatureLabel = 'İmza veritabanı kullanılamıyor';
      setText('database-state', signatureLabel);
      setText('signature-version', 'Durum okunamadı');
      setText('signature-detail', 'Yerel imza veritabanına bağlanılamadı.');
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
      empty.textContent = 'Varsayılan olarak Masaüstü ve İndirilenler izleniyor.';
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
      const enabled = Boolean(settings[button.dataset.settingToggle]);
      button.classList.toggle('is-active', enabled);
      button.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      const label = button.querySelector('span');
      if (label) label.textContent = enabled ? 'Açık' : 'Kapalı';
      button.disabled = false;
    });
    if (scanLimitSelect) {
      scanLimitSelect.value = String(settings.scan_max_files || 1500);
      scanLimitSelect.disabled = false;
    }
    renderWatchPaths(Array.isArray(settings.watch_paths) ? settings.watch_paths : []);
    setText('settings-save-state', 'Tüm ayarlar bu bilgisayarda saklanıyor');
    if (!scanning) {
      const limit = Number(settings.scan_max_files) || 1500;
      setText('scan-page-summary', `En fazla ${limit.toLocaleString('tr-TR')} dosya incelenir. Dosyalara otomatik işlem uygulanmaz.`);
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
      badge.textContent = finding.kind === 'test-signature'
        ? 'EICAR TEST'
        : signatureMatch ? 'İMZA' : finding.kind === 'yara' ? 'YARA' : 'İNCELEME';
      const actions = document.createElement('div');
      actions.className = 'finding-actions';
      const action = document.createElement('button');
      action.className = 'finding-action';
      action.type = 'button';
      action.textContent = 'Karantinaya al';
      action.addEventListener('click', async () => {
        const approved = window.confirm(`“${finding.path}” dosyası Neutron karantina alanına taşınsın mı? Dosya silinmez.`);
        if (!approved) return;
        action.disabled = true;
        action.textContent = 'Taşınıyor…';
        const result = await engine?.addToQuarantine?.({ path: finding.path, reason: finding.reason || 'Tarama bulgusu' });
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

  pageTargets.forEach((target) => target.addEventListener('click', () => {
    showPage(target.dataset.pageTarget);
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

    if (event.type === 'watch-finding') {
      const finding = event.finding || {};
      setText('activity-title', `${event.file_name || 'Bir dosya'} işaretlendi`);
      setText('activity-detail', `${finding.reason || 'İnceleme gerekiyor'}; otomatik işlem uygulanmadı.`);
      setText('file-protection-detail', `${event.file_name || 'Dosya'} inceleme için işaretlendi.`);
      applyProtectionHistory();
      return;
    }

    if (event.type === 'behavior-ready') {
      behaviorReady = true;
      setText('overview-behavior-state', 'Davranış izleme etkin');
      setText('behavior-protection-state', 'Etkin');
      setText('behavior-protection-detail', `${Number(event.process_count) || 0} çalışan süreç ve ${Number(event.persistence_points) || 0} otomatik başlangıç noktası izleniyor.`);
      return;
    }

    if (event.type === 'behavior-finding') {
      const finding = event.finding || {};
      setText('activity-title', `${event.file_name || 'Bir davranış'} işaretlendi`);
      setText('activity-detail', `${finding.reason || 'Şüpheli davranış incelenmeli'}; otomatik işlem uygulanmadı.`);
      setText('overview-behavior-state', 'İnceleme gerekiyor');
      setText('behavior-protection-detail', finding.reason || 'Şüpheli davranış yerel geçmişe kaydedildi.');
      applyProtectionHistory();
      return;
    }

    if (event.type === 'behavior-stopped') {
      behaviorReady = false;
      setText('overview-behavior-state', 'Koruma kapalı');
      setText('behavior-protection-state', 'Koruma kapalı');
      setText('behavior-protection-detail', 'Davranış izleme durduruldu.');
      return;
    }

    if (event.type === 'behavior-error') {
      behaviorReady = false;
      setText('overview-behavior-state', 'Kullanılamıyor');
      setText('behavior-protection-state', 'Kullanılamıyor');
      setText('behavior-protection-detail', event.message || 'Davranış izleme motoru başlatılamadı.');
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
      error: ['Tekrar dene', event.message || 'Proton güncellenemedi.'],
    };
    const state = states[event.stage];
    if (!state) return;
    if (signatureUpdateButton) signatureUpdateButton.textContent = state[0];
    setText('signature-detail', state[1]);
  });

  protectionToggle?.addEventListener('click', async () => {
    if (!engine?.startProtection || !engine?.stopProtection) return;
    protectionToggle.disabled = true;
    setText('protection-toggle-label', protectionEnabled ? 'Kapatılıyor' : 'Başlatılıyor');
    const result = protectionEnabled
      ? await engine.stopProtection()
      : await engine.startProtection();
    if (!result?.ok) {
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

  engine?.onScanEvent?.((event) => {
    if (!event || typeof event.type !== 'string') return;

    if (event.type === 'started') {
      scanning = true;
      setText('engine-state', 'Hızlı tarama sürüyor');
      setText('protection-label', 'TARAMA SÜRÜYOR');
      setText('scan-heading', 'Neutron dosyaları inceliyor.');
      setText('scan-summary', 'Dosyalar yalnız okunuyor; hiçbir dosya silinmez veya taşınmaz.');
      setText('scan-page-heading', 'Tarama devam ediyor');
      setText('scan-page-summary', 'Dosyalar yalnız okunuyor. Tarama sırasında hiçbir işlem uygulanmaz.');
      setText('activity-title', 'Tarama başlatıldı');
      setText('activity-detail', `${event.targets.join(' ve ')} klasörleri inceleniyor.`);
      updateScanResult('Tarama başlatıldı', 'Dosya listesi hazırlanıyor.');
      renderFindings([]);
      return;
    }

    if (event.type === 'progress') {
      const detail = `${event.scanned} dosya tarandı. Güvenli salt-okunur kontrol devam ediyor.`;
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
      const resultTitle = confirmed > 0 ? `${confirmed} imza eşleşmesi bulundu` : 'Doğrulanmış tehdit bulunmadı';
      const detail = `${event.scanned} dosya ${formatDuration(event.elapsed_ms)} içinde incelendi.${event.limited ? ' Tarama güvenlik sınırına ulaştı.' : ''}`;
      setReadyState();
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
      const message = event.message || 'Beklenmeyen bir motor hatası oluştu.';
      setText('engine-state', 'Tarama başlatılamadı');
      setText('scan-page-heading', 'Tarama tamamlanamadı');
      setText('scan-page-summary', message);
      setText('activity-title', 'Tarama hatası');
      setText('activity-detail', message);
      updateScanResult('Tarama tamamlanamadı', message);
    }
  });

  quickScanButtons.forEach((button) => button.addEventListener('click', async () => {
    if (scanning || !engine?.startQuickScan) return;
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

  setReadyState();
  showPage(pageNameFromHash(), { updateHash: false });
  applyHistory();
  applyProtectionHistory();
  applySignatureStatus();
  applyYaraStatus();
  applySettings();
  applyExclusions();
  engine?.getProtectionStatus?.().then((status) => {
    if (status?.enabled) {
      behaviorReady = Boolean(status.behaviorReady);
      setProtectionState(true, status.ready ? 'Koruma etkin' : 'Koruma başlatılıyor', status.ready
        ? 'Masaüstü ve İndirilenler klasörleri izleniyor.'
        : 'İzlenecek klasörlerin ilk görüntüsü hazırlanıyor.');
    } else {
      behaviorReady = false;
      setProtectionState(false, 'Koruma kapalı', 'Yeni ve değişen dosyalar şu anda izlenmiyor.');
    }
  }).catch(() => {
    setProtectionState(false, 'Koruma kullanılamıyor', 'Python motoruna bağlanılamadı.');
  });
})();

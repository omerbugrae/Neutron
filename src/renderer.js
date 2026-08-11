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
  const textTargets = (role) => [...document.querySelectorAll(`[data-role="${role}"]`)];
  let scanning = false;
  let protectionEnabled = false;
  let signatureLabel = 'Proton hazırlanıyor';

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
  };

  const setReadyState = () => {
    setText('engine-state', protectionEnabled ? 'Gerçek zamanlı koruma etkin' : 'Koruma kapalı');
    setText('database-state', signatureLabel);
    setText('protection-label', protectionEnabled ? 'KORUMA ETKİN' : 'KORUMA KAPALI');
    setText('scan-heading', protectionEnabled ? 'Neutron seni koruyor.' : 'Korumayı açın.');
    setText('scan-summary', protectionEnabled
      ? 'Masaüstü ve İndirilenler klasörlerindeki yeni ve değişen dosyalar izleniyor.'
      : 'Gerçek zamanlı dosya izleme kapalı. Koruma sayfasından yeniden açabilirsiniz.');
    setText('scan-page-heading', 'Masaüstü ve İndirilenler');
    setText('scan-page-summary', 'En fazla 1.500 dosya incelenir. Dosyalar silinmez, taşınmaz veya karantinaya alınmaz.');
    setButtons('Hızlı tarama başlat', false);
  };

  const setProtectionState = (enabled, heading, detail) => {
    protectionEnabled = enabled;
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
    count.textContent = `${events.length} olay`;

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
        : event.finding_kind === 'signature' ? 'İMZA' : event.finding_kind === 'yara' ? 'YARA' : 'İNCELEME';
      const stamp = document.createElement('time');
      stamp.textContent = formatScanDate(event.occurred_at);
      meta.append(badge, stamp);
      row.append(content, meta);
      list.append(row);
    });
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
      setText('signature-detail', `${count} etkin imza · Yalnızca paketle gelen çevrimdışı Proton tanımları.`);
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
      row.append(content, badge);
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
      row.append(action);
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
      setProtectionState(
        true,
        'Koruma etkin',
        `${targetCount || 2} klasör izleniyor. Yalnız yeni ve değişen dosyalar yerel olarak incelenir.`
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
      setText('signature-detail', `${count} etkin Proton imzası doğrulandı. Ağ bağlantısı kullanılmadı.`);
      signatureUpdateButton.textContent = 'Proton güncel';
    } catch (error) {
      setText('signature-detail', error?.message || 'Yerel imzalar denetlenemedi.');
      signatureUpdateButton.textContent = 'Tekrar dene';
    } finally {
      signatureUpdateButton.disabled = false;
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
  engine?.getProtectionStatus?.().then((status) => {
    if (status?.enabled) {
      setProtectionState(true, status.ready ? 'Koruma etkin' : 'Koruma başlatılıyor', status.ready
        ? 'Masaüstü ve İndirilenler klasörleri izleniyor.'
        : 'İzlenecek klasörlerin ilk görüntüsü hazırlanıyor.');
    } else {
      setProtectionState(false, 'Koruma kapalı', 'Yeni ve değişen dosyalar şu anda izlenmiyor.');
    }
  }).catch(() => {
    setProtectionState(false, 'Koruma kullanılamıyor', 'Python motoruna bağlanılamadı.');
  });
})();

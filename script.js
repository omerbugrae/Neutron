(() => {
  'use strict';

  // Mobil menü
  const navToggle = document.getElementById('navToggle');
  const mobileNav = document.getElementById('mobileNav');

  if (navToggle && mobileNav) {
    navToggle.addEventListener('click', () => {
      const isOpen = mobileNav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', String(isOpen));
    });

    mobileNav.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        mobileNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
      });
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && mobileNav.classList.contains('is-open')) {
        mobileNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.focus();
      }
    });
  }

  // Başa dön düğmesi
  const backToTop = document.getElementById('backToTop');
  if (backToTop) {
    const toggleBackToTop = () => {
      backToTop.classList.toggle('is-visible', window.scrollY > 480);
    };
    toggleBackToTop();
    window.addEventListener('scroll', toggleBackToTop, { passive: true });
    backToTop.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // Detay atlası: sayaç her zaman gerçek içerik adedini gösterir.
  const detailCount = document.getElementById('detailCount');
  if (detailCount) {
    detailCount.textContent = String(document.querySelectorAll('.atlas-item').length);
  }

  // Doğrulama komutunu kopyala.
  //
  // Kopyalandığını söylemek yeterli değil: kopyalanmadığında da bunu söylemesi
  // gerekiyor. Clipboard API güvenli olmayan bağlamlarda (file:// üzerinden
  // açılan bir sayfa) sessizce reddediyor, ve sessizce başarısız olan bir
  // kopyalama düğmesi kullanıcının yanlış komutu yapıştırmasıyla sonuçlanır.
  document.querySelectorAll('[data-copy-target]').forEach((button) => {
    const source = document.getElementById(button.dataset.copyTarget);
    if (!source) return;

    const label = button.textContent;
    let resetTimer = null;

    const report = (text, ok) => {
      button.textContent = text;
      button.classList.toggle('is-done', ok);
      window.clearTimeout(resetTimer);
      resetTimer = window.setTimeout(() => {
        button.textContent = label;
        button.classList.remove('is-done');
      }, 2000);
    };

    button.addEventListener('click', async () => {
      const text = source.textContent.trim();
      try {
        if (!navigator.clipboard) throw new Error('clipboard unavailable');
        await navigator.clipboard.writeText(text);
        report('Kopyalandı', true);
      } catch {
        // Panoya yazamıyorsak en azından komutu seçili bırak: kullanıcı
        // Ctrl+C ile kendisi alabilir.
        const range = document.createRange();
        range.selectNodeContents(source);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        report('Seçildi, Ctrl+C', false);
      }
    });
  });

  // Kaydırıldıkça beliren bölümler
  const revealTargets = document.querySelectorAll(
    '.feature-card, .atlas-group, .step, .requirement, .faq-item, .flow-diagram, .risk-panel,'
    + ' .license-panel, .explore-card, .install-ladder li, .verify-step, .uninstall-card,'
    + ' .service-card, .limit-card, .support-card, .limit-list li, .notice-panel'
  );

  if ('IntersectionObserver' in window && revealTargets.length) {
    revealTargets.forEach((el) => el.classList.add('reveal'));

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
    );

    revealTargets.forEach((el) => observer.observe(el));
  } else {
    revealTargets.forEach((el) => el.classList.add('is-visible'));
  }

  // Sayfa içi bağlantılar için kaydırma takibi.
  //
  // Sitenin çok sayfalı hale gelmesinden sonra menü artık sayfalar arasında
  // geziniyor ve aktif sayfa aria-current ile HTML tarafında işaretleniyor.
  // Bu blok yalnız aynı sayfada bölüm bağlantısı olan sayfalar için çalışır;
  // olmadığında hiçbir gözlemci kurulmaz.
  const inPageLinks = document.querySelectorAll('.nav a[href^="#"]');
  const sections = document.querySelectorAll('main section[id]');

  if ('IntersectionObserver' in window && sections.length && inPageLinks.length) {
    const sectionObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const id = entry.target.getAttribute('id');
          inPageLinks.forEach((link) => {
            link.classList.toggle('is-active', link.getAttribute('href') === `#${id}`);
          });
        });
      },
      { rootMargin: '-45% 0px -50% 0px' }
    );

    sections.forEach((section) => sectionObserver.observe(section));
  }
})();

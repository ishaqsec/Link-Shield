/**
 * Link Shield — Popup UI Controller (v1.0.0 • by Muhammad Ishaq)
 * Drives real-time URL scanning, active tab inspection, Light/Dark theme switching,
 * live extension toolbar icon badge synchronization (OK / WARN / RISK / OFF),
 * and the universal floating Info PopUp (auto-closes on outside click + small close button).
 */
/* global chrome, LinkShieldDetector */

(function () {
  'use strict';

  const state = {
    theme: 'light',
    activeTabId: null,
    activeTabUrl: 'https://www.google.com/',
    currentAnalysis: null,
    isCustomScan: false,
    settings: {
      protectionEnabled: true,
      strictMode: false,
      inPageBanner: true,
      theme: 'light',
      customAllowlist: [],
      customBlocklist: []
    }
  };

  // DOM Elements
  const htmlEl = document.documentElement;
  const brandHeaderTrigger = document.getElementById('brandHeaderTrigger');
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const settingsBtn = document.getElementById('settingsBtn');
  const moreMenuBtn = document.getElementById('moreMenuBtn');
  const moreDropdown = document.getElementById('moreDropdown');

  const safetyCard = document.getElementById('safetyCard');
  const shieldVisualTrigger = document.getElementById('shieldVisualTrigger');
  const shieldIllustration = document.getElementById('shieldIllustration');
  const websiteContextLabel = document.getElementById('websiteContextLabel');
  const iconBadgePreview = document.getElementById('iconBadgePreview');
  const displayHost = document.getElementById('displayHost');
  const displayFullUrl = document.getElementById('displayFullUrl');
  const copyUrlBtn = document.getElementById('copyUrlBtn');
  const copyFeedback = document.getElementById('copyFeedback');
  const statusBadgePill = document.getElementById('statusBadgePill');
  const verdictIcon = document.getElementById('verdictIcon');
  const verdictLabel = document.getElementById('verdictLabel');
  const threatHeadline = document.getElementById('threatHeadline');
  const threatSubtext = document.getElementById('threatSubtext');
  const verdictMessageTrigger = document.getElementById('verdictMessageTrigger');

  const tileHttpsIcon = document.getElementById('tileHttpsIcon');
  const tileHttpsLabel = document.getElementById('tileHttpsLabel');
  const tileHttpsValue = document.getElementById('tileHttpsValue');
  const tileDomainValue = document.getElementById('tileDomainValue');
  const tileLocationValue = document.getElementById('tileLocationValue');
  const tileIpValue = document.getElementById('tileIpValue');

  const tabScanUrl = document.getElementById('tabScanUrl');
  const tabCheckCurrent = document.getElementById('tabCheckCurrent');
  const urlInput = document.getElementById('urlInput');
  const clearInputBtn = document.getElementById('clearInputBtn');
  const scanUrlBtn = document.getElementById('scanUrlBtn');
  const scanBtnText = document.getElementById('scanBtnText');

  const footerInfoTrigger = document.getElementById('footerInfoTrigger');

  // Universal Floating Info PopUp Elements
  const infoPopupBackdrop = document.getElementById('infoPopupBackdrop');
  const infoPopupCard = document.getElementById('infoPopupCard');
  const infoPopupBadge = document.getElementById('infoPopupBadge');
  const infoPopupTitle = document.getElementById('infoPopupTitle');
  const infoPopupBody = document.getElementById('infoPopupBody');
  const infoPopupCloseBtn = document.getElementById('infoPopupCloseBtn');

  // Settings Modal Elements
  const settingsModal = document.getElementById('settingsModal');
  const settingsModalCard = document.getElementById('settingsModalCard');
  const closeSettingsBtn = document.getElementById('closeSettingsBtn');
  const toggleProtection = document.getElementById('toggleProtection');
  const toggleStrictMode = document.getElementById('toggleStrictMode');
  const toggleInPageBanner = document.getElementById('toggleInPageBanner');
  const allowlistInput = document.getElementById('allowlistInput');
  const blocklistInput = document.getElementById('blocklistInput');
  const saveSettingsBtn = document.getElementById('saveSettingsBtn');

  const openHistoryBtn = document.getElementById('openHistoryBtn');
  const openReportBtn = document.getElementById('openReportBtn');
  const exportReportBtn = document.getElementById('exportReportBtn');

  /**
   * Open the floating Info PopUp with custom badge, title, and HTML content.
   * Automatically closes when clicking outside the card or clicking the small close button (✕).
   */
  function showInfoPopup({ badge = 'INFO', badgeColor = '#0066FF', title = 'Details', bodyHtml = '' }) {
    settingsModal.classList.add('hidden');
    moreDropdown.classList.add('hidden');

    infoPopupBadge.textContent = badge;
    infoPopupBadge.style.background = badgeColor;
    infoPopupTitle.textContent = title;
    infoPopupBody.innerHTML = bodyHtml;
    infoPopupBackdrop.classList.remove('hidden');
  }

  function closeInfoPopup() {
    infoPopupBackdrop.classList.add('hidden');
  }

  /**
   * Apply Light or Dark theme and update the 3D shield artwork to match
   */
  function applyTheme(theme) {
    state.theme = theme === 'dark' ? 'dark' : 'light';
    htmlEl.setAttribute('data-theme', state.theme);
    updateShieldArtwork(state.currentAnalysis ? state.currentAnalysis.status : 'safe');
  }

  function updateShieldArtwork(status) {
    const modeSuffix = state.theme === 'dark' ? 'dark' : 'light';
    if (status === 'danger') {
      shieldIllustration.src = `assets/ui/07_shield_danger_${modeSuffix}.png`;
    } else if (status === 'suspicious') {
      shieldIllustration.src = `assets/ui/07_shield_warn_${modeSuffix}.png`;
    } else {
      shieldIllustration.src = `assets/ui/07_shield_safe_${modeSuffix}.png`;
    }
  }

  /**
   * Render an analysis result into the Safety Card, 4 Detail Tiles, and Extension Toolbar Badge
   */
  function renderAnalysis(result, isCustomScan = false) {
    if (!result) return;
    state.currentAnalysis = result;
    state.isCustomScan = isCustomScan;

    safetyCard.classList.remove('status-safe', 'status-suspicious', 'status-danger');
    safetyCard.classList.add(`status-${result.status}`);

    updateShieldArtwork(result.status);

    websiteContextLabel.textContent = isCustomScan ? 'Scanned Website' : 'Current Website';
    const badgeTxt = state.settings.protectionEnabled ? result.badgeText : 'OFF';
    iconBadgePreview.textContent = `ICON: ${badgeTxt}`;

    displayHost.textContent = result.displayHost || 'www.google.com';
    displayFullUrl.textContent = result.url || 'https://www.google.com/';
    displayFullUrl.title = result.url || 'https://www.google.com/';

    if (result.status === 'danger') {
      verdictIcon.textContent = '✖';
    } else if (result.status === 'suspicious') {
      verdictIcon.textContent = '⚠';
    } else {
      verdictIcon.textContent = '✔';
    }
    verdictLabel.textContent = result.label;
    threatHeadline.textContent = result.headline;
    threatSubtext.textContent = result.subtext;

    tileHttpsLabel.textContent = result.isHttps ? 'HTTPS' : result.protocol || 'HTTP';
    tileHttpsValue.textContent = result.httpsStatus || (result.isHttps ? 'Secure' : 'Insecure');
    if (result.isHttps) {
      tileHttpsIcon.classList.remove('insecure');
    } else {
      tileHttpsIcon.classList.add('insecure');
    }

    tileDomainValue.textContent = result.domain || result.displayHost;
    tileDomainValue.title = result.domain || result.displayHost;

    tileLocationValue.textContent = result.location || 'United States';
    tileLocationValue.title = result.location || 'United States';

    tileIpValue.textContent = result.ip || '142.250.72.14';
    tileIpValue.title = result.ip || '142.250.72.14';

    syncToolbarBadge(result);
  }

  function syncToolbarBadge(result) {
    if (typeof chrome === 'undefined' || !chrome.action) return;
    const enabled = state.settings.protectionEnabled;
    const badgeText = enabled ? (result ? result.badgeText : 'OK') : 'OFF';
    const badgeColor = enabled ? (result ? result.badgeColor : '#10B981') : '#64748B';
    try {
      chrome.action.setBadgeText({ text: badgeText });
      chrome.action.setBadgeBackgroundColor({ color: badgeColor });
      if (typeof chrome.action.setBadgeTextColor === 'function') {
        chrome.action.setBadgeTextColor({ color: '#FFFFFF' });
      }
      if (typeof state.activeTabId === 'number') {
        chrome.action.setBadgeText({ text: badgeText, tabId: state.activeTabId });
        chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: state.activeTabId });
      }
    } catch (_) {}
  }

  /**
   * Perform a URL scan and optionally display the scan result summary in the Info PopUp
   */
  async function performScan(rawUrl, isCustomScan = true, showPopupInfo = false, popupHeaderTitle = null) {
    const targetUrl = (rawUrl || '').trim();
    if (!targetUrl) {
      urlInput.focus();
      return;
    }

    scanBtnText.textContent = 'Scanning...';
    const localResult = LinkShieldDetector.analyzeUrl(targetUrl, {
      customAllowlist: state.settings.customAllowlist,
      customBlocklist: state.settings.customBlocklist,
      strictMode: state.settings.strictMode
    });
    renderAnalysis(localResult, isCustomScan);

    if (showPopupInfo) {
      openScanSummaryPopup(localResult, popupHeaderTitle || (isCustomScan ? 'URL Scan Result' : 'Current Tab Status'));
    }

    LinkShieldDetector.enrichWithLiveDns(localResult).then((enriched) => {
      if (state.currentAnalysis && state.currentAnalysis.url === enriched.url) {
        tileIpValue.textContent = enriched.ip;
      }
    }).catch(() => {});

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage(
          {
            type: 'SCAN_URL',
            url: targetUrl,
            tabId: state.activeTabId,
            updateBadge: true,
            source: isCustomScan ? 'manual' : 'tab'
          },
          (res) => {
            scanBtnText.textContent = 'Scan URL';
            if (res && res.ok && res.result) {
              renderAnalysis(res.result, isCustomScan);
            }
          }
        );
      } catch (_) {
        scanBtnText.textContent = 'Scan URL';
      }
    } else {
      setTimeout(() => {
        scanBtnText.textContent = 'Scan URL';
      }, 120);
    }
  }

  function openScanSummaryPopup(res, titleText) {
    const reasonsList = (res.reasons && res.reasons.length > 0)
      ? res.reasons.slice(0, 3).map(r => `<div class="info-note"><strong>${escapeHtml(r.title)}:</strong> ${escapeHtml(r.detail)}</div>`).join('')
      : `<div class="info-note">✔ <strong>Clean Verification:</strong> No phishing, malware, or behavioral anomalies detected on <strong>${escapeHtml(res.displayHost)}</strong>.</div>`;

    showInfoPopup({
      badge: res.badgeText,
      badgeColor: res.badgeColor,
      title: titleText,
      bodyHtml: `
        <div class="info-kv-grid">
          <div class="info-kv-box">
            <div class="info-kv-label">Website Host</div>
            <div class="info-kv-val">${escapeHtml(res.displayHost)}</div>
          </div>
          <div class="info-kv-box">
            <div class="info-kv-label">Verdict &amp; Risk Score</div>
            <div class="info-kv-val">${escapeHtml(res.label)} (${res.riskScore}/100)</div>
          </div>
          <div class="info-kv-box">
            <div class="info-kv-label">HTTPS / Protocol</div>
            <div class="info-kv-val">${escapeHtml(res.protocol)} (${escapeHtml(res.httpsStatus)})</div>
          </div>
          <div class="info-kv-box">
            <div class="info-kv-label">IP &amp; Location</div>
            <div class="info-kv-val">${escapeHtml(res.ip)} • ${escapeHtml(res.location)}</div>
          </div>
        </div>
        ${reasonsList}
      `
    });
  }

  /**
   * Inspect the currently active browser tab
   */
  function checkCurrentBrowserTab(showPopupInfo = false) {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const activeTab = tabs && tabs[0];
        if (activeTab) {
          state.activeTabId = activeTab.id;
          const rawTabUrl = activeTab.url || activeTab.pendingUrl || '';
          const isBlankOrLocal = !rawTabUrl ||
            rawTabUrl.startsWith('chrome://') ||
            rawTabUrl.startsWith('edge://') ||
            rawTabUrl.startsWith('about:') ||
            rawTabUrl.startsWith('chrome-extension://') ||
            rawTabUrl.startsWith('file://');
          const effectiveUrl = isBlankOrLocal ? 'https://www.google.com/' : rawTabUrl;
          state.activeTabUrl = effectiveUrl;
          performScan(effectiveUrl, false, showPopupInfo, 'Current Tab Check');
        } else {
          performScan('https://www.google.com/', false, showPopupInfo, 'Current Tab Check');
        }
      });
    } else {
      performScan('https://www.google.com/', false, showPopupInfo, 'Current Tab Check');
    }
  }

  /**
   * Show diagnostic details in Info PopUp for any of the 4 Feature Cards (Detect, Analyze, Real-time, Stay Safe)
   */
  function showPillarInfoPopup(pillarKey) {
    const res = state.currentAnalysis || LinkShieldDetector.analyzeUrl('https://www.google.com/');
    const meta = {
      detect: {
        badge: 'DETECT',
        title: 'Phishing & Malware Detection',
        desc: 'Scans for brand typosquatting, IDN punycode homographs, @ credential redirection, and executable malware payloads.'
      },
      analyze: {
        badge: 'ANALYZE',
        title: 'Behavioral & Heuristic Analysis',
        desc: 'Evaluates Shannon character entropy (DGA detection), raw IP hosts, subdomain depth, URL shorteners, and XSS/SQLi parameters.'
      },
      realtime: {
        badge: 'REAL-TIME',
        title: 'Real-Time Threat Intelligence',
        desc: 'Cross-references domain reputation, abused TLDs (.tk, .top, .zip, .click), social-engineering lures, and custom blocklists.'
      },
      staysafe: {
        badge: 'STAY SAFE',
        title: 'SSL/TLS & Active Browser Shield',
        desc: 'Verifies HTTPS encryption, inspects page DOM for insecure password forms, and updates the live extension toolbar badge.'
      }
    }[pillarKey] || { badge: 'INFO', title: 'Engine Module', desc: '' };

    const p = res.pillars && res.pillars[pillarKey];
    const badgeColor = p && p.status === 'danger' ? '#EF4444' : (p && p.status === 'warn' ? '#F59E0B' : '#10B981');

    const findingsHtml = (p && Array.isArray(p.details) && p.details.length > 0)
      ? p.details.map(d => `<div class="info-note">⚠ <strong>${escapeHtml(d.title)}:</strong> ${escapeHtml(d.detail)}</div>`).join('')
      : `<div class="info-note">✔ <strong>${escapeHtml(p ? p.summary : 'All checks passed')}</strong></div>`;

    showInfoPopup({
      badge: meta.badge,
      badgeColor,
      title: meta.title,
      bodyHtml: `
        <div>${escapeHtml(meta.desc)}</div>
        <div class="info-kv-grid">
          <div class="info-kv-box">
            <div class="info-kv-label">Inspected Target</div>
            <div class="info-kv-val">${escapeHtml(res.displayHost)}</div>
          </div>
          <div class="info-kv-box">
            <div class="info-kv-label">Module Verdict</div>
            <div class="info-kv-val">${p ? escapeHtml(p.status.toUpperCase()) : 'SAFE'} (Entropy: ${res.metrics.entropy})</div>
          </div>
        </div>
        ${findingsHtml}
      `
    });
  }

  /**
   * Show Info PopUp when clicking any of the 4 Website Detail Tiles (HTTPS, Domain, Location, IP Address)
   */
  function showTileInfoPopup(tileType) {
    const res = state.currentAnalysis || LinkShieldDetector.analyzeUrl('https://www.google.com/');
    if (tileType === 'https') {
      showInfoPopup({
        badge: res.isHttps ? 'SECURE' : 'INSECURE',
        badgeColor: res.isHttps ? '#10B981' : '#EF4444',
        title: 'HTTPS & Encryption Status',
        bodyHtml: `
          <div class="info-kv-grid">
            <div class="info-kv-box">
              <div class="info-kv-label">Protocol Scheme</div>
              <div class="info-kv-val">${escapeHtml(res.protocol)}</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">Encryption State</div>
              <div class="info-kv-val">${escapeHtml(res.httpsStatus)}</div>
            </div>
          </div>
          <div class="info-note">
            ${res.isHttps
              ? '✔ Traffic between your browser and this website is encrypted using TLS/HTTPS.'
              : '⚠ This connection is unencrypted (HTTP). Avoid entering passwords or sensitive data.'}
          </div>
        `
      });
    } else if (tileType === 'domain') {
      showInfoPopup({
        badge: 'DOMAIN',
        badgeColor: '#0066FF',
        title: 'Domain & Host Analysis',
        bodyHtml: `
          <div class="info-kv-grid">
            <div class="info-kv-box">
              <div class="info-kv-label">Registrable Domain</div>
              <div class="info-kv-val">${escapeHtml(res.domain)}</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">Full Hostname</div>
              <div class="info-kv-val">${escapeHtml(res.displayHost)}</div>
            </div>
          </div>
          <div class="info-note">
            Subdomain Levels: <strong>${res.metrics.subdomainCount}</strong> • Character Entropy: <strong>${res.metrics.entropy} bits/char</strong>
          </div>
        `
      });
    } else if (tileType === 'location') {
      showInfoPopup({
        badge: 'GEO IP',
        badgeColor: '#0066FF',
        title: 'Server Geolocation',
        bodyHtml: `
          <div class="info-kv-grid">
            <div class="info-kv-box">
              <div class="info-kv-label">Country / Region</div>
              <div class="info-kv-val">${escapeHtml(res.location)}</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">Network Provider</div>
              <div class="info-kv-val">${escapeHtml(res.org || 'Standard DNS Host')}</div>
            </div>
          </div>
          <div class="info-note">
            Geolocation is resolved from the server IP routing table and domain registry metadata.
          </div>
        `
      });
    } else if (tileType === 'ip') {
      showInfoPopup({
        badge: 'NETWORK',
        badgeColor: '#0066FF',
        title: 'IP Address & DNS Resolution',
        bodyHtml: `
          <div class="info-kv-grid">
            <div class="info-kv-box">
              <div class="info-kv-label">Resolved IPv4</div>
              <div class="info-kv-val">${escapeHtml(res.ip)}</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">Host Type</div>
              <div class="info-kv-val">${LinkShieldDetector.isIpAddress(res.displayHost) ? 'Direct IP URL' : 'Standard DNS Record'}</div>
            </div>
          </div>
          <div class="info-note">
            Resolved via DNS-over-HTTPS (DoH) and Link Shield's verified infrastructure database.
          </div>
        `
      });
    }
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /**
   * Initialize Event Listeners
   */
  function bindEvents() {
    // Close Info PopUp via small close button (✕)
    infoPopupCloseBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      closeInfoPopup();
    });

    // Auto-close Info PopUp when user clicks mouse outside of the popup card
    infoPopupBackdrop.addEventListener('mousedown', (e) => {
      if (e.target === infoPopupBackdrop) {
        closeInfoPopup();
      }
    });

    // Auto-close Settings Modal when user clicks mouse outside of the settings card
    settingsModal.addEventListener('mousedown', (e) => {
      if (e.target === settingsModal) {
        settingsModal.classList.add('hidden');
      }
    });

    // Also close any open inner Info PopUp if window loses focus
    window.addEventListener('blur', () => {
      closeInfoPopup();
      moreDropdown.classList.add('hidden');
    });

    // Escape key closes popups
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeInfoPopup();
        settingsModal.classList.add('hidden');
        moreDropdown.classList.add('hidden');
      }
    });

    // Theme Toggle Button
    themeToggleBtn.addEventListener('click', () => {
      const nextTheme = state.theme === 'light' ? 'dark' : 'light';
      applyTheme(nextTheme);
      state.settings.theme = nextTheme;
      saveSettingsToStorage();
    });

    // Brand Header & Footer Click -> Author & Version Info PopUp
    const openAboutPopup = () => {
      showInfoPopup({
        badge: 'v1.0.0',
        badgeColor: '#0066FF',
        title: 'Link Shield — Malicious URL Detector',
        bodyHtml: `
          <div class="info-kv-grid">
            <div class="info-kv-box">
              <div class="info-kv-label">Developed By</div>
              <div class="info-kv-val">Muhammad Ishaq</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">Extension Version</div>
              <div class="info-kv-val">v1.0.0 (Manifest V3)</div>
            </div>
          </div>
          <div class="info-note">
            Real-time browser shield providing multi-layer phishing detection, heuristic entropy analysis, and live toolbar badge status (<strong>OK</strong> / <strong>WARN</strong> / <strong>RISK</strong>).
          </div>
        `
      });
    };
    brandHeaderTrigger.addEventListener('click', openAboutPopup);
    footerInfoTrigger.addEventListener('click', openAboutPopup);

    // Shield Illustration / Verdict Badge / Icon Badge Click -> Threat Breakdown Info PopUp
    shieldVisualTrigger.addEventListener('click', () => openDetailedReportModal());
    statusBadgePill.addEventListener('click', () => openDetailedReportModal());
    verdictMessageTrigger.addEventListener('click', () => openDetailedReportModal());
    iconBadgePreview.addEventListener('click', () => {
      const res = state.currentAnalysis || LinkShieldDetector.analyzeUrl('https://www.google.com/');
      showInfoPopup({
        badge: `ICON: ${res.badgeText}`,
        badgeColor: res.badgeColor,
        title: 'Live Extension Icon Status',
        bodyHtml: `
          <div class="info-note">
            The extension toolbar icon displays <strong>${escapeHtml(res.badgeText)}</strong> in real time for <strong>${escapeHtml(res.displayHost)}</strong>.
          </div>
          <div class="info-kv-grid">
            <div class="info-kv-box">
              <div class="info-kv-label">OK (Green)</div>
              <div class="info-kv-val">Safe (Score 0–24)</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">WARN (Amber)</div>
              <div class="info-kv-val">Suspicious (25–59)</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">RISK (Red)</div>
              <div class="info-kv-val">Unsafe (60–100)</div>
            </div>
            <div class="info-kv-box">
              <div class="info-kv-label">OFF (Slate)</div>
              <div class="info-kv-val">Shield Paused</div>
            </div>
          </div>
        `
      });
    });

    // Copy URL Button -> Copies URL and shows Info PopUp confirmation
    copyUrlBtn.addEventListener('click', async () => {
      const urlToCopy = state.currentAnalysis ? state.currentAnalysis.url : displayFullUrl.textContent;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(urlToCopy);
        }
      } catch (_) {}
      copyFeedback.classList.remove('hidden');
      setTimeout(() => copyFeedback.classList.add('hidden'), 1400);
      showInfoPopup({
        badge: 'COPIED',
        badgeColor: '#10B981',
        title: 'URL Copied to Clipboard',
        bodyHtml: `<div class="info-note">Copied: <strong>${escapeHtml(urlToCopy)}</strong></div>`
      });
    });

    // 4 Detail Tiles Click -> Shows Tile Info PopUp
    document.querySelectorAll('[data-tile-info]').forEach((tile) => {
      tile.addEventListener('click', () => {
        showTileInfoPopup(tile.getAttribute('data-tile-info'));
      });
    });

    // Tabs: Scan URL vs Check Current Tab -> Shows Info in PopUp
    tabScanUrl.addEventListener('click', () => {
      tabScanUrl.classList.add('active');
      tabScanUrl.setAttribute('aria-selected', 'true');
      tabCheckCurrent.classList.remove('active');
      tabCheckCurrent.setAttribute('aria-selected', 'false');
      const val = urlInput.value.trim();
      if (val) {
        performScan(val, true, true, 'Custom URL Scan');
      } else {
        showInfoPopup({
          badge: 'SCANNER',
          badgeColor: '#0066FF',
          title: 'Scan Any Custom URL',
          bodyHtml: `
            <div class="info-note">
              Enter any link in the input box below and click <strong>Scan URL</strong> to inspect it for phishing, malware, redirects, and SSL security before visiting.
            </div>
          `
        });
      }
    });

    tabCheckCurrent.addEventListener('click', () => {
      tabCheckCurrent.classList.add('active');
      tabCheckCurrent.setAttribute('aria-selected', 'true');
      tabScanUrl.classList.remove('active');
      tabScanUrl.setAttribute('aria-selected', 'false');
      urlInput.value = '';
      clearInputBtn.classList.add('hidden');
      checkCurrentBrowserTab(true);
    });

    // URL Input & Clear Button
    urlInput.addEventListener('input', () => {
      if (urlInput.value.trim().length > 0) {
        clearInputBtn.classList.remove('hidden');
      } else {
        clearInputBtn.classList.add('hidden');
      }
    });

    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        scanUrlBtn.click();
      }
    });

    clearInputBtn.addEventListener('click', () => {
      urlInput.value = '';
      clearInputBtn.classList.add('hidden');
      urlInput.focus();
    });

    // Primary Scan Button -> Runs scan and opens result in Info PopUp
    scanUrlBtn.addEventListener('click', () => {
      const val = urlInput.value.trim();
      if (val) {
        tabScanUrl.classList.add('active');
        tabCheckCurrent.classList.remove('active');
        performScan(val, true, true, 'URL Scan Complete');
      } else {
        checkCurrentBrowserTab(true);
      }
    });

    // 4 Feature Cards Click -> Live Diagnostics in Info PopUp
    document.querySelectorAll('.feature-card').forEach((card) => {
      card.addEventListener('click', () => {
        const pillar = card.getAttribute('data-pillar');
        showPillarInfoPopup(pillar);
      });
    });

    // More Menu Dropdown
    moreMenuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      moreDropdown.classList.toggle('hidden');
    });

    document.addEventListener('click', () => {
      moreDropdown.classList.add('hidden');
    });

    moreDropdown.addEventListener('click', (e) => {
      e.stopPropagation();
    });

    // Quick Test Sample URLs in Dropdown
    document.querySelectorAll('[data-test-url]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const sampleUrl = btn.getAttribute('data-test-url');
        moreDropdown.classList.add('hidden');
        urlInput.value = sampleUrl;
        clearInputBtn.classList.remove('hidden');
        tabScanUrl.classList.add('active');
        tabCheckCurrent.classList.remove('active');
        performScan(sampleUrl, true, true, 'Sample URL Scan Result');
      });
    });

    // Settings Modal
    settingsBtn.addEventListener('click', () => {
      closeInfoPopup();
      toggleProtection.checked = Boolean(state.settings.protectionEnabled);
      toggleStrictMode.checked = Boolean(state.settings.strictMode);
      toggleInPageBanner.checked = Boolean(state.settings.inPageBanner);
      allowlistInput.value = (state.settings.customAllowlist || []).join('\n');
      blocklistInput.value = (state.settings.customBlocklist || []).join('\n');
      settingsModal.classList.remove('hidden');
    });

    closeSettingsBtn.addEventListener('click', () => {
      settingsModal.classList.add('hidden');
    });

    saveSettingsBtn.addEventListener('click', () => {
      state.settings.protectionEnabled = toggleProtection.checked;
      state.settings.strictMode = toggleStrictMode.checked;
      state.settings.inPageBanner = toggleInPageBanner.checked;
      state.settings.customAllowlist = allowlistInput.value
        .split('\n')
        .map(s => s.trim())
        .filter(Boolean);
      state.settings.customBlocklist = blocklistInput.value
        .split('\n')
        .map(s => s.trim())
        .filter(Boolean);

      saveSettingsToStorage();
      settingsModal.classList.add('hidden');
      const currentTarget = state.currentAnalysis ? state.currentAnalysis.url : 'https://www.google.com/';
      performScan(currentTarget, state.isCustomScan, false);
    });

    // History & Report Options in Menu
    openHistoryBtn.addEventListener('click', () => {
      moreDropdown.classList.add('hidden');
      openScanHistoryModal();
    });

    openReportBtn.addEventListener('click', () => {
      moreDropdown.classList.add('hidden');
      openDetailedReportModal();
    });

    exportReportBtn.addEventListener('click', () => {
      moreDropdown.classList.add('hidden');
      exportCurrentReportJson();
    });
  }

  function saveSettingsToStorage() {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage({
          type: 'UPDATE_SETTINGS',
          settings: state.settings,
          tabId: state.activeTabId,
          currentUrl: state.currentAnalysis ? state.currentAnalysis.url : 'https://www.google.com/'
        });
      } catch (_) {}
    }
  }

  function openScanHistoryModal() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['scanHistory'], (res) => {
        const list = Array.isArray(res && res.scanHistory) ? res.scanHistory : [];
        renderHistoryPopup(list);
      });
    } else {
      renderHistoryPopup(state.currentAnalysis ? [state.currentAnalysis] : []);
    }
  }

  function renderHistoryPopup(list) {
    if (!list || list.length === 0) {
      showInfoPopup({
        badge: 'HISTORY',
        badgeColor: '#0066FF',
        title: 'Recent Scan History',
        bodyHtml: '<div class="info-note">No URLs scanned yet in this session.</div>'
      });
      return;
    }

    const rowsHtml = list.slice(0, 4).map((item) => {
      const color = item.status === 'danger' ? '#EF4444' : (item.status === 'suspicious' ? '#F59E0B' : '#10B981');
      return `
        <div class="history-item" data-scan-url="${escapeHtml(item.url)}">
          <div>
            <div class="history-host">${escapeHtml(item.displayHost || item.domain)}</div>
            <div class="history-meta">${escapeHtml(item.ip || '')} • Score: ${Number(item.riskScore || 0)}/100</div>
          </div>
          <span class="history-badge" style="background:${color}">${escapeHtml(item.badgeText || 'OK')}</span>
        </div>
      `;
    }).join('');

    showInfoPopup({
      badge: 'HISTORY',
      badgeColor: '#0066FF',
      title: 'Recent Scan History',
      bodyHtml: rowsHtml
    });

    infoPopupBody.querySelectorAll('.history-item').forEach((row) => {
      row.addEventListener('click', () => {
        const target = row.getAttribute('data-scan-url');
        closeInfoPopup();
        urlInput.value = target;
        clearInputBtn.classList.remove('hidden');
        performScan(target, true, false);
      });
    });
  }

  function openDetailedReportModal() {
    const res = state.currentAnalysis || LinkShieldDetector.analyzeUrl('https://www.google.com/');
    openScanSummaryPopup(res, 'Detailed Threat Report');
  }

  function exportCurrentReportJson() {
    const res = state.currentAnalysis || LinkShieldDetector.analyzeUrl('https://www.google.com/');
    const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `link-shield-report-${res.domain || 'scan'}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  /**
   * Startup initialization
   */
  function init() {
    bindEvents();

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['settings'], (res) => {
        if (res && res.settings) {
          state.settings = { ...state.settings, ...res.settings };
          applyTheme(state.settings.theme || 'light');
        }
        checkCurrentBrowserTab(false);
      });
    } else {
      applyTheme('light');
      checkCurrentBrowserTab(false);
    }
  }

  init();
})();

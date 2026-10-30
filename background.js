/**
 * Link Shield — Background Service Worker (Manifest V3)
 * Manages real-time tab URL monitoring, live extension icon badge status (OK / WARN / RISK / OFF),
 * scan history persistence, and communication between Popup and Content Scripts.
 */
/* global importScripts, LinkShieldDetector, chrome */

try {
  importScripts('detector.js');
} catch (e) {
  console.error('Failed to import detector.js:', e);
}

const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  strictMode: false,
  inPageBanner: true,
  theme: 'light',
  customAllowlist: [],
  customBlocklist: []
};

// In-memory cache of latest analysis per tabId
const tabAnalysisCache = new Map();

async function getSettings() {
  return new Promise((resolve) => {
    if (!chrome || !chrome.storage || !chrome.storage.local) {
      resolve({ ...DEFAULT_SETTINGS });
      return;
    }
    chrome.storage.local.get(['settings'], (res) => {
      resolve({ ...DEFAULT_SETTINGS, ...(res && res.settings ? res.settings : {}) });
    });
  });
}

async function appendScanHistory(result, source = 'auto') {
  if (!result || result.isSystemPage) return;
  if (!chrome || !chrome.storage || !chrome.storage.local) return;

  chrome.storage.local.get(['scanHistory'], (res) => {
    const history = Array.isArray(res && res.scanHistory) ? res.scanHistory : [];
    const entry = {
      url: result.url,
      displayHost: result.displayHost,
      domain: result.domain,
      status: result.status,
      badgeText: result.badgeText,
      riskScore: result.riskScore,
      label: result.label,
      ip: result.ip,
      location: result.location,
      source,
      timestamp: new Date().toISOString()
    };

    // Deduplicate consecutive identical URL scans
    if (history.length > 0 && history[0].url === entry.url && history[0].status === entry.status) {
      history[0].timestamp = entry.timestamp;
    } else {
      history.unshift(entry);
    }

    chrome.storage.local.set({ scanHistory: history.slice(0, 50) });
  });
}

/**
 * Updates the Chrome Extension toolbar icon badge (`OK`, `WARN`, `RISK`, `OFF`)
 */
async function updateExtensionBadge(tabId, analysisResult, protectionEnabled = true) {
  if (!chrome || !chrome.action) return;

  const badgeText = protectionEnabled ? (analysisResult ? analysisResult.badgeText : 'OK') : 'OFF';
  const badgeColor = protectionEnabled ? (analysisResult ? analysisResult.badgeColor : '#10B981') : '#64748B';
  const titleText = protectionEnabled && analysisResult
    ? `Link Shield [${badgeText}] — ${analysisResult.label}: ${analysisResult.displayHost} (Score: ${analysisResult.riskScore}/100)`
    : 'Link Shield [OFF] — Protection Paused';

  try {
    // Set global default badge so toolbar always shows live status
    await chrome.action.setBadgeText({ text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ color: badgeColor });
    if (typeof chrome.action.setBadgeTextColor === 'function') {
      await chrome.action.setBadgeTextColor({ color: '#FFFFFF' });
    }
    await chrome.action.setTitle({ title: titleText });

    // Also set tab-specific badge if tabId is valid
    if (typeof tabId === 'number' && tabId >= 0) {
      await chrome.action.setBadgeText({ text: badgeText, tabId });
      await chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
      if (typeof chrome.action.setBadgeTextColor === 'function') {
        await chrome.action.setBadgeTextColor({ color: '#FFFFFF', tabId });
      }
      await chrome.action.setTitle({ title: titleText, tabId });
    }
  } catch (err) {
    // Tab may have closed before badge update completed
  }
}

/**
 * Analyze a tab's URL and update the badge + cache
 */
async function analyzeTabAndUpdateBadge(tabId, url, pageSignals = null, source = 'tab') {
  const settings = await getSettings();
  if (!settings.protectionEnabled) {
    await updateExtensionBadge(tabId, null, false);
    return null;
  }

  // If newtab or empty internal page, analyze https://www.google.com/ for default display or keep OK badge
  const effectiveUrl = (!url || url === 'chrome://newtab/' || url === 'about:newtab' || url === 'edge://newtab/')
    ? 'https://www.google.com/'
    : url;

  const result = LinkShieldDetector.analyzeUrl(effectiveUrl, {
    customAllowlist: settings.customAllowlist,
    customBlocklist: settings.customBlocklist,
    strictMode: settings.strictMode,
    pageSignals
  });

  // Enrich with live DNS in background if non-cached domain
  LinkShieldDetector.enrichWithLiveDns(result).then((enriched) => {
    if (typeof tabId === 'number') {
      tabAnalysisCache.set(tabId, enriched);
    }
  }).catch(() => {});

  if (typeof tabId === 'number') {
    tabAnalysisCache.set(tabId, result);
  }

  await updateExtensionBadge(tabId, result, true);
  if (source === 'navigation' || source === 'manual') {
    await appendScanHistory(result, source);
  }

  return result;
}

// Initialize extension state on install & startup
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.onInstalled.addListener(async () => {
    const current = await getSettings();
    chrome.storage.local.set({ settings: current });
    const defaultScan = LinkShieldDetector.analyzeUrl('https://www.google.com/');
    await updateExtensionBadge(null, defaultScan, current.protectionEnabled);
  });

  chrome.runtime.onStartup.addListener(async () => {
    const current = await getSettings();
    const defaultScan = LinkShieldDetector.analyzeUrl('https://www.google.com/');
    await updateExtensionBadge(null, defaultScan, current.protectionEnabled);
  });

  // Listen for tab URL changes
  if (chrome.tabs) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.url || changeInfo.status === 'complete') {
        const targetUrl = changeInfo.url || (tab && tab.url);
        if (targetUrl) {
          analyzeTabAndUpdateBadge(tabId, targetUrl, null, changeInfo.status === 'complete' ? 'navigation' : 'tab');
        }
      }
    });

    chrome.tabs.onActivated.addListener(async (activeInfo) => {
      try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (tab && tab.url) {
          await analyzeTabAndUpdateBadge(activeInfo.tabId, tab.url, null, 'tab');
        } else {
          const settings = await getSettings();
          const fallback = LinkShieldDetector.analyzeUrl('https://www.google.com/');
          await updateExtensionBadge(activeInfo.tabId, fallback, settings.protectionEnabled);
        }
      } catch (_) {}
    });

    chrome.tabs.onRemoved.addListener((tabId) => {
      tabAnalysisCache.delete(tabId);
    });
  }

  // Message handler for Popup & Content Script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) return false;

    if (message.type === 'SCAN_URL') {
      (async () => {
        const settings = await getSettings();
        const result = LinkShieldDetector.analyzeUrl(message.url, {
          customAllowlist: settings.customAllowlist,
          customBlocklist: settings.customBlocklist,
          strictMode: settings.strictMode
        });
        await LinkShieldDetector.enrichWithLiveDns(result);
        if (message.updateBadge !== false) {
          await updateExtensionBadge(message.tabId, result, settings.protectionEnabled);
        }
        await appendScanHistory(result, message.source || 'manual');
        sendResponse({ ok: true, result, settings });
      })();
      return true;
    }

    if (message.type === 'GET_ACTIVE_TAB_ANALYSIS') {
      (async () => {
        const settings = await getSettings();
        const tabId = message.tabId;
        const tabUrl = message.url;
        const result = await analyzeTabAndUpdateBadge(tabId, tabUrl, null, 'tab');
        sendResponse({ ok: true, result, settings });
      })();
      return true;
    }

    if (message.type === 'PAGE_DOM_SIGNALS') {
      (async () => {
        const tabId = sender && sender.tab ? sender.tab.id : null;
        const tabUrl = (sender && sender.tab && sender.tab.url) || message.url;
        const settings = await getSettings();
        const result = await analyzeTabAndUpdateBadge(tabId, tabUrl, message.signals, 'dom');
        sendResponse({
          ok: true,
          result,
          showBanner: Boolean(settings.protectionEnabled && settings.inPageBanner && result && result.status !== 'safe')
        });
      })();
      return true;
    }

    if (message.type === 'UPDATE_SETTINGS') {
      (async () => {
        const current = await getSettings();
        const updated = { ...current, ...(message.settings || {}) };
        chrome.storage.local.set({ settings: updated }, async () => {
          if (message.currentUrl) {
            const res = LinkShieldDetector.analyzeUrl(message.currentUrl, {
              customAllowlist: updated.customAllowlist,
              customBlocklist: updated.customBlocklist,
              strictMode: updated.strictMode
            });
            await updateExtensionBadge(message.tabId, res, updated.protectionEnabled);
            sendResponse({ ok: true, settings: updated, result: res });
          } else {
            await updateExtensionBadge(message.tabId, null, updated.protectionEnabled);
            sendResponse({ ok: true, settings: updated });
          }
        });
      })();
      return true;
    }

    if (message.type === 'CLEAR_HISTORY') {
      chrome.storage.local.set({ scanHistory: [] }, () => {
        sendResponse({ ok: true });
      });
      return true;
    }

    return false;
  });
}

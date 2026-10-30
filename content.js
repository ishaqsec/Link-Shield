/**
 * Link Shield — Real-Time Content Script
 * Inspects page DOM signals (insecure password forms, external form actions) and
 * displays a non-intrusive Shadow-DOM security banner if a page is flagged as Suspicious or Unsafe.
 */
/* global chrome, LinkShieldDetector */

(function () {
  'use strict';

  if (window.__linkShieldContentInjected) return;
  window.__linkShieldContentInjected = true;

  function collectPageDomSignals() {
    try {
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      const hasPasswordInput = passwordInputs.length > 0;
      let externalFormAction = null;

      const currentDomain = (typeof LinkShieldDetector !== 'undefined')
        ? LinkShieldDetector.getRegistrableDomain(window.location.hostname)
        : window.location.hostname;

      const forms = document.querySelectorAll('form[action]');
      for (const form of forms) {
        const rawAction = form.getAttribute('action');
        if (rawAction && /^https?:\/\//i.test(rawAction)) {
          try {
            const actionUrl = new URL(rawAction, window.location.href);
            const actionDomain = (typeof LinkShieldDetector !== 'undefined')
              ? LinkShieldDetector.getRegistrableDomain(actionUrl.hostname)
              : actionUrl.hostname;
            if (actionDomain && currentDomain && actionDomain !== currentDomain) {
              externalFormAction = actionUrl.hostname;
              break;
            }
          } catch (_) {}
        }
      }

      return {
        hasPasswordInput,
        externalFormAction,
        iframeCount: document.querySelectorAll('iframe').length
      };
    } catch (_) {
      return { hasPasswordInput: false, externalFormAction: null, iframeCount: 0 };
    }
  }

  function renderWarningBanner(result) {
    if (!result || result.status === 'safe') return;
    if (document.getElementById('link-shield-alert-host')) return;

    const host = document.createElement('div');
    host.id = 'link-shield-alert-host';
    const shadow = host.attachShadow({ mode: 'closed' });

    const isDanger = result.status === 'danger';
    const bgGradient = isDanger
      ? 'linear-gradient(90deg, #991B1B 0%, #DC2626 100%)'
      : 'linear-gradient(90deg, #92400E 0%, #D97706 100%)';
    const badgeBg = isDanger ? '#FEE2E2' : '#FEF3C7';
    const badgeColor = isDanger ? '#991B1B' : '#92400E';

    shadow.innerHTML = `
      <style>
        .ls-banner {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          z-index: 2147483647;
          background: ${bgGradient};
          color: #FFFFFF;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          font-size: 13px;
          padding: 10px 18px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.28);
          border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        .ls-left {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .ls-badge {
          background: ${badgeBg};
          color: ${badgeColor};
          font-weight: 700;
          font-size: 11px;
          padding: 3px 8px;
          border-radius: 999px;
          letter-spacing: 0.4px;
          text-transform: uppercase;
        }
        .ls-title {
          font-weight: 700;
        }
        .ls-detail {
          opacity: 0.92;
        }
        .ls-actions {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .ls-btn {
          background: rgba(255, 255, 255, 0.18);
          color: #FFFFFF;
          border: 1px solid rgba(255, 255, 255, 0.35);
          padding: 4px 10px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 12px;
          font-weight: 600;
        }
        .ls-btn:hover {
          background: rgba(255, 255, 255, 0.28);
        }
      </style>
      <div class="ls-banner" role="alert">
        <div class="ls-left">
          <span class="ls-badge">Link Shield • ${result.badgeText}</span>
          <span class="ls-title">${result.headline}:</span>
          <span class="ls-detail">${result.subtext} (Risk Score: ${result.riskScore}/100)</span>
        </div>
        <div class="ls-actions">
          <button class="ls-btn" id="ls-dismiss">Dismiss</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(host);
    const dismissBtn = shadow.getElementById('ls-dismiss');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => host.remove());
    }
  }

  function initContentCheck() {
    const signals = collectPageDomSignals();
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage(
          { type: 'PAGE_DOM_SIGNALS', url: window.location.href, signals },
          (response) => {
            if (chrome.runtime.lastError) return;
            if (response && response.showBanner && response.result) {
              renderWarningBanner(response.result);
            }
          }
        );
      } catch (_) {}
    }
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    initContentCheck();
  } else {
    window.addEventListener('DOMContentLoaded', initContentCheck, { once: true });
  }
})();

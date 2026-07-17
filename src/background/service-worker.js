import { extractDomain, CONFIG } from '../shared/utils.js';
import { getCachedResult, setCachedResult, checkAllowlist, checkLocalSignature, syncSignatures, checkSensitiveDomain, setSessionFlag, getSessionFlag, checkSessionAllowlist, addSessionAllowlist, checkUserBlocklist } from './cache-manager.js';
import { computeDHash } from './hasher.js';

// Redirect Chain Tracking (Feature 3)
const redirectChains = {}; // tabId -> { count, urls[] }
const SUSPICIOUS_NODES = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'clickbank.net', 'tiny.cc', 'shorturl.at'];

// Sync offline signatures on extension startup and every 24 hours
chrome.runtime.onStartup.addListener(syncSignatures);
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === chrome.runtime.OnInstalledReason.INSTALL) {
    chrome.tabs.create({ url: chrome.runtime.getURL("src/ui/onboarding.html") });
  }
  syncSignatures();
  chrome.alarms.create('sync_signatures', { periodInMinutes: 1440 }); // 24 hours
  
  // Clear old result cache so new logic triggers immediately
  chrome.storage.local.get(null, (items) => {
    const keys = Object.keys(items).filter(k => k.startsWith('cache_'));
    if (keys.length > 0) {
      chrome.storage.local.remove(keys);
    }
    
    // Prune history > 30 days old on startup
    if (items.history_log) {
      const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
      const filtered = items.history_log.filter(e => e.timestamp > thirtyDaysAgo);
      chrome.storage.local.set({ history_log: filtered });
    }
  });
  
  // Setup heartbeat alarm
  chrome.alarms.create('heartbeat_ping', { periodInMinutes: 720 }); // 12 hours
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'sync_signatures') {
    syncSignatures();
  } else if (alarm.name === 'heartbeat_ping') {
    sendHeartbeat();
  }
});

async function sendHeartbeat() {
  const { caregiverId, pairingToken } = await chrome.storage.local.get(['caregiverId', 'pairingToken']);
  if (!caregiverId || !pairingToken) return;

  try {
    await fetch(`${CONFIG.BACKEND_URL}/extension/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caregiverId, token: pairingToken })
    });
  } catch (e) {
    console.error("Heartbeat failed", e);
  }
}

async function sendAlertToDashboard(domain, reason, metadata = null) {
  const { caregiverId, pairingToken } = await chrome.storage.local.get(['caregiverId', 'pairingToken']);
  if (!caregiverId || !pairingToken) return;

  try {
    await fetch(`${CONFIG.BACKEND_URL}/extension/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caregiverId, token: pairingToken, domain, reason, metadata })
    });
  } catch (e) {
    console.error("Alert broadcast failed", e);
  }
}

if (chrome.webRequest) {
  chrome.webRequest.onBeforeRedirect.addListener((details) => {
    if (details.frameId === 0) {
      if (!redirectChains[details.tabId]) {
        redirectChains[details.tabId] = { count: 0, urls: [details.url] };
      }
      redirectChains[details.tabId].count++;
      redirectChains[details.tabId].urls.push(details.redirectUrl || details.url);
    }
  }, { urls: ["<all_urls>"] });
}

if (chrome.webNavigation) {

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && redirectChains[details.tabId]) {
      // Record the final url if it's different
      if (redirectChains[details.tabId].urls[redirectChains[details.tabId].urls.length - 1] !== details.url) {
        redirectChains[details.tabId].urls.push(details.url);
      }
    }
  });
}

async function checkDomainWithBackend(domain, rChainCount, rChainUrls, hasAdTracking, favicon) {
  try {
    const { pairingToken } = await chrome.storage.local.get(['pairingToken']);
    const tokenParam = pairingToken ? `&token=${pairingToken}` : '';
    
    const response = await fetch(`${CONFIG.BACKEND_URL}/domain-check?domain=${encodeURIComponent(domain)}${tokenParam}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        domain, 
        token: pairingToken,
        hasAdTracking,
        rChainCount,
        rChainUrls,
        favicon
      })
    });
    if (!response.ok) {
        throw new Error('Backend check failed');
    }
    return await response.json();
  } catch (error) {
    console.error("Backend error:", error);
    // Fail open if backend is unreachable
    return { status: 'SAFE', reason: 'Backend unreachable' };
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'CHECK_DOMAIN') {
    const url = request.url;
    const favicon = request.favicon;
    const domain = extractDomain(url);
    const tabId = sender.tab ? sender.tab.id : null;
    const rChain = (tabId && redirectChains[tabId]) ? redirectChains[tabId] : { count: 0, urls: [] };
    
    // Clear the redirect chain for next navigation
    if (tabId) {
      delete redirectChains[tabId];
    }

    let hasAdTracking = false;
    try {
      const urlObj = new URL(url);
      hasAdTracking = urlObj.searchParams.has('gclid') || 
                      urlObj.searchParams.has('fbclid') || 
                      urlObj.searchParams.has('msclkid');
    } catch (e) {}

    if (!domain) {
      sendResponse({ status: 'SAFE' });
      return true;
    }

    (async () => {
      // 0. Check if protection is disabled
      const { protection_disabled } = await chrome.storage.local.get(['protection_disabled']);
      if (protection_disabled) {
        return sendResponse({ status: 'SAFE', reason: 'Protection Disabled' });
      }

      // 1. Check Allowlist
      const isAllowed = await checkAllowlist(domain);
      const isSessionAllowed = await checkSessionAllowlist(domain);
      if (isAllowed || isSessionAllowed) {
        return sendResponse({ status: 'SAFE', reason: 'Allowlisted' });
      }

      // 1.5. Check User Blocklist (Manually Reported)
      const isUserBlocked = await checkUserBlocklist(domain);
      if (isUserBlocked) {
        const result = { status: 'BLOCK', reason: 'You have manually reported and blocked this site.' };
        await setSessionFlag('last_flagged_time', Date.now());
        return sendResponse({ ...result, dryRun: CONFIG.DRY_RUN });
      }

      // 2. Check Result Cache (so we don't re-run expensive checks)
      const cached = await getCachedResult(domain);
      if (cached) {
        return sendResponse({ status: cached.status, reason: cached.reason, dryRun: CONFIG.DRY_RUN });
      }

      // Feature: Punycode/Homograph Detection
      if (domain.includes('xn--')) {
        await setSessionFlag('last_flagged_time', Date.now());
        const result = { status: 'BLOCK', reason: 'High Risk: This domain uses invisible foreign characters (Punycode) to impersonate a legitimate website.' };
        await setCachedResult(domain, result);
        return sendResponse({ ...result, dryRun: CONFIG.DRY_RUN });
      }

      // ----------------------------------------------------------------
      // TIER 1: LOCAL CHECKS (Instant)
      // ----------------------------------------------------------------
      const localSig = await checkLocalSignature(domain);
      if (localSig.isMalicious) {
        await setSessionFlag('last_flagged_time', Date.now());
        const result = { status: 'BLOCK', reason: `Flagged by known threat list: ${localSig.source}` };
        await setCachedResult(domain, result);
        return sendResponse({ ...result, dryRun: CONFIG.DRY_RUN });
      }

      // ----------------------------------------------------------------
      // TIER 2: ASYNC BACKEND CHECKS (Safe Browsing & RDAP Domain Age & Scoring)
      // ----------------------------------------------------------------
      const backendResult = await checkDomainWithBackend(domain, rChain.count, rChain.urls, hasAdTracking, favicon);

      if (backendResult.status !== 'SAFE') {
        await setSessionFlag('last_flagged_time', Date.now());
      }
      
      let finalResult = backendResult;

      // Feature 1: Screenshot-Based Visual Similarity Check
      if (finalResult.status === 'WARN' || finalResult.isNewDomain) {
        if (tabId) {
          // Ask background to capture tab asynchronously, don't block response
          setTimeout(() => {
            chrome.tabs.captureVisibleTab(sender.tab.windowId, { format: "jpeg", quality: 20 }, async (dataUrl) => {
              if (chrome.runtime.lastError || !dataUrl) return;
              
              const pHash = await computeDHash(dataUrl);
              if (!pHash) return;

              console.log(`[TrustPause Feature 1] Computed pHash for ${domain}: ${pHash}`);

              // If it's a lookalike, we know which brand it matched against
              let targetBrand = finalResult.matchedBrand;

              if (targetBrand) {
                try {
                  const { pairingToken } = await chrome.storage.local.get(['pairingToken']);
                  const response = await fetch(`${CONFIG.BACKEND_URL}/analyze-hash`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pHash, targetBrand, token: pairingToken })
                  });
                  
                  if (response.ok) {
                    const data = await response.json();
                    if (data.match) {
                      console.warn(`[TrustPause Feature 1] Visual match confirmed against ${targetBrand} (Distance: ${data.distance}). Escalating to BLOCK.`);
                      
                      // Escalate and redirect the active tab instantly
                      const escalatedReason = `High Risk: This site looks identical to the real ${targetBrand} website, but the address is wrong. This is a confirmed phishing clone.`;
                      
                      const newResult = { status: 'BLOCK', reason: escalatedReason };
                      await setCachedResult(domain, newResult);

                      // Redirect to interstitial
                      const interstitialUrl = chrome.runtime.getURL(
                          `src/ui/interstitial.html?target=${encodeURIComponent(url)}&reason=${encodeURIComponent(escalatedReason)}&status=BLOCK`
                      );
                      
                      const [tab] = await chrome.tabs.query({ active: true, windowId: sender.tab.windowId });
                      if (tab && tab.id === tabId) {
                        chrome.tabs.update(tabId, { url: interstitialUrl });
                      }
                    }
                  }
                } catch (e) {
                  console.error("Hash analysis failed", e);
                }
              }
            });
          }, 1000); // Wait 1s for render
        }
      }

      if (finalResult.status !== 'SAFE') {
        const { blocked_count, history_log } = await chrome.storage.local.get(['blocked_count', 'history_log']);
        await chrome.storage.local.set({ blocked_count: (blocked_count || 0) + 1 });

        // Feature 4: Record to history log
        const log = history_log || [];
        log.unshift({
          timestamp: Date.now(),
          domain: domain,
          reason: finalResult.reason,
          status: finalResult.status,
          action: 'pending',
          redirects: rChain.urls // Store redirect chain for details
        });
        // Keep it reasonable, max 500 items
        if (log.length > 500) log.length = 500;
        await chrome.storage.local.set({ history_log: log });

        // Feature: Send to Caregiver Dashboard
        if (finalResult.status === 'BLOCK' || finalResult.status === 'WARN') {
          await sendAlertToDashboard(domain, finalResult.reason, {
            redirectChain: rChain.urls,
            domainAgeDays: finalResult.domainAgeDays || null,
            hasAdTracking: hasAdTracking,
            matchedBrand: finalResult.matchedBrand || null
          });
        }
      }

      await setCachedResult(domain, finalResult);
      sendResponse({ ...finalResult, dryRun: CONFIG.DRY_RUN });
    })();

    return true;
  } else if (request.type === 'REPORT_SENSITIVE_FORMS') {
    (async () => {
      const domain = extractDomain(request.url);
      if (!domain) return;
      
      const cached = await getCachedResult(domain);
      if (cached) {
        let escalatedStatus = null;
        let escalatedReason = null;

        // Feature 2: Form Field Monitoring Escalation
        if (cached.status === 'WARN' && cached.isLookalike) {
          escalatedStatus = 'BLOCK';
          escalatedReason = 'High Risk: Site is impersonating a brand AND requesting highly sensitive data (passwords, SSN, or cards).';
        } else if (cached.status === 'SAFE' && cached.isNewDomain) {
          escalatedStatus = 'WARN';
          escalatedReason = 'Warning: This domain is very new AND is asking for sensitive data.';
        }

        if (escalatedStatus) {
          const newResult = { ...cached, status: escalatedStatus, reason: escalatedReason };
          await setCachedResult(domain, newResult);
          
          await sendAlertToDashboard(domain, escalatedReason);

          // Redirect current tab to interstitial
          const interstitialUrl = chrome.runtime.getURL(
              `src/ui/interstitial.html?target=${encodeURIComponent(request.url)}&reason=${encodeURIComponent(escalatedReason)}&status=${escalatedStatus}`
          );
          
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab) {
            chrome.tabs.update(tab.id, { url: interstitialUrl });
          }
        }
      }
    })();
    return true;
  } else if (request.type === 'REPORT_DOMAIN') {
    (async () => {
      try {
        const { caregiverId, pairingToken } = await chrome.storage.local.get(['caregiverId', 'pairingToken']);
        if (!caregiverId || !pairingToken) return sendResponse({ success: false });

        await fetch(`${CONFIG.BACKEND_URL}/extension/report`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: request.domain, reason: request.reason, token: pairingToken, caregiverId })
        });
        
        // Optimistically add to local user_blocklist
        const { user_blocklist } = await chrome.storage.local.get(['user_blocklist']);
        const list = user_blocklist || [];
        if (!list.includes(request.domain)) {
          list.push(request.domain);
          await chrome.storage.local.set({ user_blocklist: list });
        }
        
        sendResponse({ success: true });
      } catch (e) {
        console.error("Failed to report domain", e);
        sendResponse({ success: false });
      }
    })();
    return true;
  } else if (request.type === 'UNREPORT_DOMAIN') {
    (async () => {
      try {
        const { caregiverId, pairingToken } = await chrome.storage.local.get(['caregiverId', 'pairingToken']);
        if (!caregiverId || !pairingToken) return sendResponse({ success: false });

        await fetch(`${CONFIG.BACKEND_URL}/extension/report`, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: request.domain, token: pairingToken, caregiverId })
        });
        
        // Optimistically remove from local user_blocklist
        const { user_blocklist } = await chrome.storage.local.get(['user_blocklist']);
        if (user_blocklist) {
          const list = user_blocklist.filter(d => d !== request.domain);
          await chrome.storage.local.set({ user_blocklist: list });
        }
        
        sendResponse({ success: true });
      } catch (e) {
        console.error("Failed to un-report domain", e);
        sendResponse({ success: false });
      }
    })();
    return true;
  } else if (request.type === 'REPORT_SUSPICIOUS_DOM') {
    (async () => {
      const domain = extractDomain(request.url);
      if (!domain) return;
      
      const isAllowed = await checkAllowlist(domain);
      if (isAllowed) return;

      const safeDomains = ['microsoft.com', 'google.com', 'apple.com', 'trustpause.app', 'localhost'];
      if (safeDomains.some(d => domain === d || domain.endsWith('.' + d))) return;

      // Update stats
      const { blocked_count } = await chrome.storage.local.get(['blocked_count']);
      await chrome.storage.local.set({ blocked_count: (blocked_count || 0) + 1 });
      
      // Redirect current tab to interstitial
      const interstitialUrl = chrome.runtime.getURL(
          `src/ui/interstitial.html?target=${encodeURIComponent(request.url)}&reason=${encodeURIComponent(request.reason)}&status=WARN`
      );
      
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        chrome.tabs.update(tab.id, { url: interstitialUrl });
      }
    })();
    return true;
  } else if (request.type === 'SESSION_ALLOW') {
    (async () => {
      if (request.permanent) {
        // Feature 5: Permanent Whitelist
        const { allowlist } = await chrome.storage.local.get(['allowlist']);
        const list = allowlist || [];
        if (!list.includes(request.domain)) {
          list.push(request.domain);
          await chrome.storage.local.set({ allowlist: list });
        }
      } else {
        await addSessionAllowlist(request.domain);
      }
      
      // Update action in history
      const { history_log } = await chrome.storage.local.get(['history_log']);
      if (history_log && history_log.length > 0 && history_log[0].domain === request.domain) {
         history_log[0].action = request.permanent ? 'whitelisted' : 'continued';
         await chrome.storage.local.set({ history_log });
      }
      
      sendResponse({ success: true });
    })();
    return true;
  } else if (request.type === 'HISTORY_BACK') {
    (async () => {
      const { history_log } = await chrome.storage.local.get(['history_log']);
      if (history_log && history_log.length > 0 && history_log[0].domain === request.domain) {
         history_log[0].action = 'went_back';
         await chrome.storage.local.set({ history_log });
      }
      sendResponse({ success: true });
    })();
    return true;
  } else if (request.type === 'CLEAR_CACHE_HOTFIX') {
    (async () => {
      await chrome.storage.local.remove(['offline_signatures', 'sensitive_domains', 'allowlist']);
      const cacheKeys = await chrome.storage.local.get(null);
      for (const key of Object.keys(cacheKeys)) {
        if (key.startsWith('cache_')) await chrome.storage.local.remove(key);
      }
      sendResponse({ success: true });
    })();
    return true;

  } else if (request.type === 'KILL_TAB') {
    if (sender.tab && sender.tab.id) {
      console.warn(`[TrustPause] Killing tab ${sender.tab.id} due to: ${request.reason}`);
      chrome.tabs.remove(sender.tab.id);
    }
    return true;
  } else if (request.type === 'TRIGGER_HEARTBEAT') {
    sendHeartbeat();
    return true;
  } else if (request.type === 'RECORD_CLIENT_REDIRECT') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      if (!redirectChains[tabId]) {
        redirectChains[tabId] = { count: 0, urls: [request.url] };
      }
      redirectChains[tabId].count++;
      // We don't know the exact destination yet, but webNavigation or the next content-script will pick it up.
      console.log(`[TrustPause] Recorded client-side redirect in tab ${tabId}`);
    }
    return true;
  }
});

// ---------------------------------------------------------
// PHASE 1: Dangerous Download Interceptor
// ---------------------------------------------------------
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  if (downloadItem.state !== 'in_progress') return;

  const url = downloadItem.url || downloadItem.finalUrl;
  if (!url || url.startsWith('data:') || url.startsWith('blob:')) return;

  const domain = extractDomain(url);
  if (!domain) return;

  const isExecutable = /\.(exe|msi|bat|scr|cmd)$/i.test(downloadItem.filename);
  if (!isExecutable) return;

  const { protection_disabled } = await chrome.storage.local.get(['protection_disabled']);
  if (protection_disabled) return;

  const isAllowed = await checkAllowlist(domain);
  if (isAllowed) return;

  const safeDomains = ['microsoft.com', 'google.com', 'apple.com', 'zoom.us', 'mozilla.org', 'trustpause.app', 'localhost'];
  if (safeDomains.some(d => domain === d || domain.endsWith('.' + d))) return;

  chrome.downloads.pause(downloadItem.id, () => {
    chrome.tabs.create({
      url: `chrome-extension://${chrome.runtime.id}/src/ui/download-warning.html?id=${downloadItem.id}&domain=${encodeURIComponent(domain)}&file=${encodeURIComponent(downloadItem.filename)}`
    });
  });
});

import { CONFIG } from '../shared/utils.js';

export async function getCachedResult(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get([domain], (result) => {
      const data = result[domain];
      if (data && (Date.now() - data.timestamp < CONFIG.CACHE_TTL_MS)) {
        resolve(data.status);
      } else {
        resolve(null);
      }
    });
  });
}

export async function setCachedResult(domain, status) {
  const data = {
    status,
    timestamp: Date.now()
  };
  return new Promise((resolve) => {
    chrome.storage.local.set({ [domain]: data }, () => resolve());
  });
}

export async function checkAllowlist(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['allowlist'], (result) => {
      const allowlist = result.allowlist || [];
      resolve(allowlist.includes(domain));
    });
  });
}

export async function addToAllowlist(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['allowlist'], (result) => {
      const allowlist = result.allowlist || [];
      if (!allowlist.includes(domain)) {
        allowlist.push(domain);
        chrome.storage.local.set({ allowlist }, () => resolve());
      } else {
        resolve();
      }
    });
  });
}

// ---------------------------------------------------------
// NEW LOGIC: Offline Threat Signatures
// ---------------------------------------------------------
export async function syncSignatures() {
  try {
    const result = await new Promise(resolve => chrome.storage.local.get(['pairingToken'], resolve));
    const tokenParam = result.pairingToken ? `?token=${result.pairingToken}` : '';
    
    const response = await fetch(`${CONFIG.BACKEND_URL}/sync-signatures${tokenParam}`);
    if (response.ok) {
      const data = await response.json();
      
      if (data.allowlist) {
        await new Promise(resolve => chrome.storage.local.set({ allowlist: data.allowlist }, resolve));
      }
      
      if (data.protection_enabled !== undefined) {
        await new Promise(resolve => chrome.storage.local.set({ protection_disabled: !data.protection_enabled }, resolve));
      }

      if (data.signatures) {
        const sigMap = {};
        for (const row of data.signatures) {
          sigMap[row.domain] = row.source;
        }
        await new Promise((resolve) => {
          chrome.storage.local.set({ offline_signatures: sigMap }, resolve);
        });
        console.log(`Synced ${data.signatures.length} threat signatures offline.`);
      }

      if (data.sensitive_domains) {
        const sensMap = {};
        for (const row of data.sensitive_domains) {
          sensMap[row.domain] = { category: row.category, alwaysWarn: row.always_warn };
        }
        await new Promise((resolve) => {
          chrome.storage.local.set({ sensitive_domains: sensMap }, resolve);
        });
        console.log(`Synced ${data.sensitive_domains.length} sensitive domains offline.`);
      }
    }
  } catch (error) {
    console.error("Failed to sync offline signatures:", error);
  }
}

export async function checkLocalSignature(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['offline_signatures'], (result) => {
      const sigMap = result.offline_signatures || {};
      if (sigMap[domain]) {
        resolve({ isMalicious: true, source: sigMap[domain] });
      } else {
        resolve({ isMalicious: false });
      }
    });
  });
}

export async function checkSensitiveDomain(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['sensitive_domains'], (result) => {
      const sensMap = result.sensitive_domains || {};
      resolve(sensMap[domain] || null);
    });
  });
}

// ---------------------------------------------------------
// NEW LOGIC: Ephemeral Session Flags
// ---------------------------------------------------------
export async function setSessionFlag(key, value) {
  return new Promise((resolve) => {
    if (chrome.storage.session) {
      chrome.storage.session.set({ [key]: value }, resolve);
    } else {
      // Fallback if session is unsupported
      chrome.storage.local.set({ [`session_${key}`]: value }, resolve);
    }
  });
}

export async function getSessionFlag(key) {
  return new Promise((resolve) => {
    if (chrome.storage.session) {
      chrome.storage.session.get([key], (result) => resolve(result[key]));
    } else {
      chrome.storage.local.get([`session_${key}`], (result) => resolve(result[`session_${key}`]));
    }
  });
}

export async function addSessionAllowlist(domain) {
  const list = await getSessionFlag('session_allowlist') || [];
  if (!list.includes(domain)) {
    list.push(domain);
    await setSessionFlag('session_allowlist', list);
  }
}

export async function checkSessionAllowlist(domain) {
  const list = await getSessionFlag('session_allowlist') || [];
  return list.includes(domain);
}

import { extractDomain } from '../shared/utils.js';
import { CONFIG } from '../shared/utils.js';
import { getCachedResult, checkAllowlist } from '../background/cache-manager.js';

document.addEventListener('DOMContentLoaded', async () => {
    const statusIndicator = document.getElementById('status-indicator');
    const statusTitle = document.getElementById('status-title');
    const statusDomain = document.getElementById('status-domain');
    const toggleProtection = document.getElementById('toggle-protection');
    const btnClearAllowlist = document.getElementById('btn-clear-allowlist');

    // 1. Get current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (tab && tab.url && !tab.url.startsWith('chrome://')) {
        const domain = extractDomain(tab.url);
        statusDomain.textContent = domain;

        // Check if it's in the allowlist
        const isAllowed = await checkAllowlist(domain);
        if (isAllowed) {
            statusTitle.textContent = "Site Allowlisted";
            statusIndicator.className = "status-indicator safe";
        } else {
            // Check cache for recent results
            const cached = await getCachedResult(domain);
            if (cached) {
                if (cached.status === 'SAFE') {
                    statusTitle.textContent = "Safe Website";
                    statusIndicator.className = "status-indicator safe";
                } else {
                    statusTitle.textContent = "Suspicious Website";
                    statusIndicator.className = "status-indicator warn";
                }
            } else {
                statusTitle.textContent = "Not yet scanned";
                statusIndicator.className = "status-indicator";
            }
        }
    } else {
        statusDomain.textContent = "System Page";
        statusTitle.textContent = "No scan needed";
    }

    // 2. Load Toggle State (We store a 'protection_disabled' flag in local storage)
    chrome.storage.local.get(['protection_disabled'], (result) => {
        toggleProtection.checked = !result.protection_disabled;
    });

    toggleProtection.addEventListener('change', (e) => {
        const isEnabled = e.target.checked;
        chrome.storage.local.set({ protection_disabled: !isEnabled });
    });

    // 3. Clear Allowlist
    btnClearAllowlist.addEventListener('click', () => {
        chrome.storage.local.set({ allowlist: [] }, () => {
            btnClearAllowlist.textContent = "Cleared!";
            setTimeout(() => {
                btnClearAllowlist.textContent = "Clear Allowlist";
            }, 1500);
            
            // Re-evaluate current domain UI
            if (statusTitle.textContent === "Site Allowlisted") {
                statusTitle.textContent = "Allowlist Cleared";
                statusIndicator.className = "status-indicator";
            }
        });
    });

    // 4. Load Stats
    chrome.storage.local.get(['blocked_count'], (result) => {
        document.getElementById('threats-blocked').textContent = result.blocked_count || 0;
    });

    // 5. Report Page
    const btnReport = document.getElementById('btn-report-page');
    btnReport.addEventListener('click', () => {
        if (!tab || !tab.url || tab.url.startsWith('chrome://')) return;
        
        btnReport.textContent = "Reporting...";
        btnReport.disabled = true;

        const domain = extractDomain(tab.url);
        chrome.runtime.sendMessage({ type: 'REPORT_DOMAIN', domain, reason: 'Reported manually via popup' }, (response) => {
            btnReport.textContent = "Reported!";
            btnReport.style.backgroundColor = "#10B981"; // Success green
            setTimeout(() => {
                btnReport.textContent = "Report Current Page";
                btnReport.disabled = false;
                btnReport.style.backgroundColor = "";
            }, 2000);
        });
    });

    // 6. Phase 3: Family Dashboard Pairing
    const btnPair = document.getElementById('btn-pair');
    const inputCode = document.getElementById('pairing-code');
    const inputPassword = document.getElementById('pairing-password');
    const errorText = document.getElementById('pairing-error');
    const statePaired = document.getElementById('paired-state');
    const stateUnpaired = document.getElementById('unpaired-state');

    // Load pairing state
    chrome.storage.local.get(['caregiverId', 'pairingToken'], (result) => {
        if (result.caregiverId && result.pairingToken) {
            statePaired.style.display = 'flex';
            stateUnpaired.style.display = 'none';
        }
    });

    if (btnPair) {
        btnPair.addEventListener('click', async () => {
            const code = inputCode.value.trim();
            const password = inputPassword.value.trim();
            
            if (code.length < 6 || password.length < 6) {
                errorText.style.display = 'block';
                errorText.textContent = 'Please enter both code and password.';
                return;
            }
            
            btnPair.textContent = 'Linking...';
            btnPair.disabled = true;
            errorText.style.display = 'none';

            try {

                const response = await fetch(`${CONFIG.BACKEND_URL}/extension/pair`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, password })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    chrome.storage.local.set({ 
                        caregiverId: data.caregiverId, 
                        pairingToken: data.token 
                    }, () => {
                        statePaired.style.display = 'flex';
                        stateUnpaired.style.display = 'none';
                        
                        // Immediately trigger a heartbeat
                        chrome.runtime.sendMessage({ type: 'TRIGGER_HEARTBEAT' });
                    });
                } else {
                    errorText.style.display = 'block';
                    errorText.textContent = data.error || 'Failed to link. Check code/password.';
                    btnPair.textContent = 'Link to Dashboard';
                    btnPair.disabled = false;
                }
            } catch (err) {
                errorText.style.display = 'block';
                errorText.textContent = 'Network error. Try again.';
                btnPair.textContent = 'Link to Dashboard';
                btnPair.disabled = false;
            }
        });
    }
});

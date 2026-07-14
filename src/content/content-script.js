// Helper to extract domain safely
function extractDomain(url) {
    try {
        const hostname = new URL(url).hostname;
        return hostname.replace(/^www\./, '').toLowerCase();
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------------------
// 1. Initial Domain Check (Tier 1, 2, 3) & Protection Features
// ---------------------------------------------------------
if (window.location.protocol !== 'chrome-extension:') {
    // ---------------------------------------------------------
    // Option 3: Automated Tracking Parameter Stripping
    // ---------------------------------------------------------
    const urlObj = new URL(window.location.href);
    const trackingParams = ['gclid', 'fbclid', 'msclkid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];
    let hasTrackers = false;
    
    trackingParams.forEach(param => {
        if (urlObj.searchParams.has(param)) {
            urlObj.searchParams.delete(param);
            hasTrackers = true;
        }
    });

    if (hasTrackers) {
        window.history.replaceState(null, '', urlObj.toString());
        console.log('[TrustPause] Stripped tracking parameters for privacy.');
    }

    // ---------------------------------------------------------
    // Option 2: JS/Meta Refresh Tracking
    // ---------------------------------------------------------
    let userClicked = false;
    document.addEventListener('mousedown', () => userClicked = true);
    document.addEventListener('keydown', () => userClicked = true);
    document.addEventListener('touchstart', () => userClicked = true);

    window.addEventListener('beforeunload', () => {
        const timeSpent = performance.now();
        // If the user leaves the page in less than 2.5 seconds without interacting, it's likely an auto-redirect (JS/Meta).
        if (timeSpent < 2500 && !userClicked) {
            chrome.runtime.sendMessage({ type: "RECORD_CLIENT_REDIRECT", url: window.location.href });
        }
    });



    chrome.runtime.sendMessage({ type: "CHECK_DOMAIN", url: window.location.href }, (response) => {
        if (!response || response.status === 'SAFE' || response.dryRun) {
            if (response && response.dryRun && response.status !== 'SAFE') {
                console.warn(`[Browser Shield - DRY RUN] Flagged as ${response.status}: ${response.reason}`);
            }
            // Page is safe (or dry run), continue loading normally and init Phase 2 features
            initInPageScanning();
        } else {
            // Redirect to interstitial (OVERRIDE)
            const themeParam = response.theme ? `&theme=${encodeURIComponent(response.theme)}` : '';
            const reasonParam = response.reason ? `&reason=${encodeURIComponent(response.reason)}` : '';
            const statusParam = response.status ? `&status=${encodeURIComponent(response.status)}` : '';
            const interstitialUrl = chrome.runtime.getURL(
                `src/ui/interstitial.html?target=${encodeURIComponent(window.location.href)}${reasonParam}${themeParam}${statusParam}`
            );
            window.location.href = interstitialUrl;
        }
    });
}

function initInPageScanning() {
    // ---------------------------------------------------------
    // 2. Zero-Day Content Scanner (Heuristics)
    // ---------------------------------------------------------
    // Check page text for common scam urgency keywords
    setTimeout(() => {
        const pageText = document.body.innerText.toLowerCase();
        const scamKeywords = [
            "your pc is infected",
            "call microsoft support",
            "windows defender has detected",
            "your computer has been locked",
            "renew your mcafee",
            "bitcoin wallet compromised"
        ];
        
        const isSuspicious = scamKeywords.some(keyword => pageText.includes(keyword));
        
        if (isSuspicious) {
            chrome.runtime.sendMessage({ 
                type: "REPORT_SUSPICIOUS_DOM", 
                url: window.location.href,
                reason: "Suspicious urgency keywords detected on the page."
            });
        }
    }, 2000); // Wait 2s for dynamic content to load

    // ---------------------------------------------------------
    // Tech Support Scam Protection (Cursor/Dialog Lock)
    // ---------------------------------------------------------
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('src/content/injected.js');
    script.onload = () => script.remove();
    (document.head || document.documentElement).appendChild(script);

    window.addEventListener('message', (e) => {
        // SECURITY: Validate message originated from the exact same window to prevent iframe attacks
        if (e.source !== window) return;
        
        if (e.data && e.data.type === 'TRUSTPAUSE_TECH_SUPPORT_SCAM') {
            chrome.runtime.sendMessage({ type: "KILL_TAB", reason: "Tech support scam dialog bombing detected." });
        }
    });

    // ---------------------------------------------------------
    // 2.5 Form-Field Monitoring (Feature 2)
    // ---------------------------------------------------------
    let sensitiveFormsReported = false;
    const scanForSensitiveFields = () => {
        if (sensitiveFormsReported) return;

        const inputs = document.querySelectorAll('input');
        let foundSensitive = false;

        for (const input of inputs) {
            const type = (input.getAttribute('type') || '').toLowerCase();
            const name = (input.getAttribute('name') || '').toLowerCase();
            const id = (input.getAttribute('id') || '').toLowerCase();
            const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();

            if (
                type === 'password' ||
                name.includes('ssn') || id.includes('ssn') ||
                autocomplete.includes('cc-number') || name.includes('cardnumber') ||
                name.includes('routing') || name.includes('accountnumber')
            ) {
                foundSensitive = true;
                break;
            }
        }

        if (foundSensitive) {
            sensitiveFormsReported = true;
            chrome.runtime.sendMessage({
                type: "REPORT_SENSITIVE_FORMS",
                url: window.location.href
            });
        }
    };

    // ---------------------------------------------------------
    // 3. Malicious Link Highlighter
    // ---------------------------------------------------------
    chrome.storage.local.get(['offline_signatures', 'protection_disabled'], (result) => {
        if (result.protection_disabled) return;
        
        const offlineSignatures = result.offline_signatures || {};
        
        const highlightMaliciousLinks = () => {
            const links = document.querySelectorAll('a[href]:not([data-trustpause-scanned])');
            
            links.forEach(link => {
                link.setAttribute('data-trustpause-scanned', 'true');
                const domain = extractDomain(link.href);
                if (!domain) return;

                if (offlineSignatures[domain]) {
                    // Highlight the link
                    link.style.border = '2px dashed red';
                    link.style.backgroundColor = '#FEE2E2';
                    link.style.color = '#DC2626';
                    link.style.position = 'relative';
                    link.title = `⚠️ TrustPause Blocked: Known Threat (${offlineSignatures[domain]})`;
                    
                    // Disable the click
                    link.addEventListener('click', (e) => {
                        e.preventDefault();
                        alert(`TrustPause Warning: This link points to a known malicious website (${domain}). Click blocked for your safety.`);
                    });
                }
            });
        };

        // Run initially
        highlightMaliciousLinks();

        // Observe DOM for newly added links (e.g., infinite scroll or SPAs like Gmail)
        const observer = new MutationObserver((mutations) => {
            let shouldScan = false;
            for (let mutation of mutations) {
                if (mutation.addedNodes.length) {
                    shouldScan = true;
                    break;
                }
            }
            if (shouldScan) {
                highlightMaliciousLinks();
                scanForSensitiveFields(); // Debounced effectively by the observer's natural rate, but could be explicitly debounced
            }
        });

        observer.observe(document.body, { childList: true, subtree: true });
        
        // Initial scan for forms
        scanForSensitiveFields();
    });
}

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
let lastCheckedUrl = window.location.href;

const getFaviconUrl = () => {
    let favicon = document.querySelector('link[rel="shortcut icon"], link[rel="icon"]');
    return favicon ? favicon.href : new URL('/favicon.ico', window.location.href).href;
};

const runDomainCheck = (url) => {
    chrome.runtime.sendMessage({ type: "CHECK_DOMAIN", url: url, favicon: getFaviconUrl() }, (response) => {
        if (!response || response.status === 'SAFE' || response.dryRun) {
            if (response && response.dryRun && response.status !== 'SAFE') {
                console.warn(`[TrustPause - DRY RUN] Flagged as ${response.status}: ${response.reason}`);
            }
            // Page is safe, init or re-init in-page scanning
            initInPageScanning();
        } else {
            const themeParam = response.theme ? `&theme=${encodeURIComponent(response.theme)}` : '';
            const reasonParam = response.reason ? `&reason=${encodeURIComponent(response.reason)}` : '';
            const statusParam = response.status ? `&status=${encodeURIComponent(response.status)}` : '';
            const alertIdParam = response.alertId ? `&alertId=${encodeURIComponent(response.alertId)}` : '';
            window.location.href = chrome.runtime.getURL(`src/ui/interstitial.html?target=${encodeURIComponent(url)}${reasonParam}${themeParam}${statusParam}${alertIdParam}`);
        }
    });
};

if (window.location.protocol !== 'chrome-extension:') {
    if (window.self !== window.top) {
        console.log('[TrustPause] Running inside cross-origin iframe. Sandboxed inspection enabled.');
    }
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
        if (timeSpent < 2500 && !userClicked) {
            chrome.runtime.sendMessage({ type: "RECORD_CLIENT_REDIRECT", url: window.location.href });
        }
    });

    window.addEventListener('popstate', () => {
        if (window.location.href !== lastCheckedUrl) {
            lastCheckedUrl = window.location.href;
            console.log('[TrustPause] SPA Route changed (popstate), re-evaluating:', lastCheckedUrl);
            runDomainCheck(lastCheckedUrl);
        }
    });

    runDomainCheck(window.location.href);
}

let inPageScannerInitialized = false;

function initInPageScanning() {
    if (inPageScannerInitialized) return;
    inPageScannerInitialized = true;
    // ---------------------------------------------------------
    // 2. Zero-Day Content Scanner (Heuristics)
    // ---------------------------------------------------------
    // Check page text for common scam urgency keywords
    setTimeout(() => {
        const pageText = document.body.innerText.toLowerCase();
        
        // 1. Global Scam Keywords (High Urgency)
        const scamKeywords = [
            "your pc is infected", "your computer is infected",
            "call microsoft immediately", "call microsoft support",
            "windows defender has detected", "trojan detected", "virus detected",
            "your computer has been locked", "account locked",
            "renew your mcafee", "security alert",
            "bitcoin wallet compromised",
            "refund department", "tech support",
            "bitcoin atm", "safe account", "wire transfer",
            "download anydesk", "install teamviewer",
            "verify your identity immediately", "suspicious activity",
            "final notice"
        ];
        
        const isSuspicious = scamKeywords.some(keyword => pageText.includes(keyword));
        
        if (isSuspicious) {
            // Tell background to set the 30-min contextual window
            chrome.runtime.sendMessage({ 
                type: "REPORT_SCAM_EXPOSURE",
                url: window.location.href
            });
            
            // Still escalate immediately for the really bad ones
            chrome.runtime.sendMessage({ 
                type: "REPORT_SUSPICIOUS_DOM", 
                url: window.location.href,
                reason: "Suspicious urgency keywords detected on the page."
            });
        }

        // 2. Domain-Specific Contextual Checks
        // Only trigger on checkout/cart pages for large gift card purchases (> $500)
        const domain = extractDomain(window.location.href);
        const giftCardRetailers = ['amazon.com', 'walmart.com', 'target.com', 'bestbuy.com', 'apple.com', 'play.google.com', 'cvs.com', 'walgreens.com', 'kroger.com', 'homedepot.com', 'lowes.com'];
        
        if (giftCardRetailers.includes(domain)) {
            const path = window.location.pathname.toLowerCase();
            const isCartOrCheckout = path.includes('cart') || path.includes('checkout') || path.includes('basket') || path.includes('bag') || path.includes('buy');
            
            if (isCartOrCheckout && pageText.includes('gift card')) {
                // Find all dollar amounts on the page (e.g. $500.00, $1,200.50)
                const priceRegex = /\$[\d,]+\.\d{2}/g;
                const prices = pageText.match(priceRegex);
                let highestPrice = 0;
                
                if (prices) {
                    prices.forEach(priceStr => {
                        const val = parseFloat(priceStr.replace(/[\$,]/g, ''));
                        if (val > highestPrice) highestPrice = val;
                    });
                }
                
                // If the cart total (or any visible price) exceeds $500, trigger the block
                if (highestPrice >= 500) {
                    chrome.runtime.sendMessage({ 
                        type: "REPORT_SUSPICIOUS_DOM",
                        url: window.location.href,
                        reason: `Urgent Warning: You are about to purchase $${highestPrice.toFixed(2)} in gift cards. Scammers demand payment in gift cards. No legitimate company or government agency accepts gift cards as payment.`
                    });
                }
            }
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
    // 2.5 Form-Field Monitoring (Feature 2) & Shadow DOM Piercing
    // ---------------------------------------------------------
    let sensitiveFormsReported = false;
    
    function queryAllInputs(root) {
        let inputs = Array.from(root.querySelectorAll('input'));
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null, false);
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (node.shadowRoot) {
                inputs = inputs.concat(queryAllInputs(node.shadowRoot));
            }
        }
        return inputs;
    }

    const scanForSensitiveFields = () => {
        if (sensitiveFormsReported) return;

        const inputs = queryAllInputs(document);
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
    // 2.6 Mixed Content Scanner
    // ---------------------------------------------------------
    const checkMixedContent = () => {
        if (window.location.protocol === 'https:') {
            const httpForms = document.querySelectorAll('form[action^="http://"]');
            const httpScripts = document.querySelectorAll('script[src^="http://"]');
            if (httpForms.length > 0 || httpScripts.length > 0) {
                chrome.runtime.sendMessage({
                    type: "REPORT_SUSPICIOUS_DOM",
                    url: window.location.href,
                    reason: "Mixed Content: Page uses HTTPS but transmits data or loads scripts via insecure HTTP."
                });
            }
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
                    link.style.border = '2px solid #854F0B';
                    link.style.backgroundColor = '#FAEEDA';
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
        checkMixedContent();

        // Observe DOM for newly added links (e.g., infinite scroll or SPAs)
        let mutationDebounceTimer = null;
        const observer = new MutationObserver((mutations) => {
            if (mutationDebounceTimer) clearTimeout(mutationDebounceTimer);
            mutationDebounceTimer = setTimeout(() => {
                if (window.location.href !== lastCheckedUrl) {
                    lastCheckedUrl = window.location.href;
                    console.log('[TrustPause] SPA Route changed (mutation), re-evaluating:', lastCheckedUrl);
                    runDomainCheck(lastCheckedUrl);
                    return; // Re-evaluating will trigger everything if safe
                }

                let shouldScan = false;
                for (let mutation of mutations) {
                    if (mutation.addedNodes.length) {
                        shouldScan = true;
                        break;
                    }
                }
                
                if (shouldScan) {
                    highlightMaliciousLinks();
                    scanForSensitiveFields(); 
                    checkMixedContent();
                }
            }, 300); // Debounce to prevent lag on heavy SPAs
        });

        observer.observe(document.documentElement, { childList: true, subtree: true });
        
        // Initial scan for forms
        scanForSensitiveFields();
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get('target');
    const reason = params.get('reason');
    const theme = params.get('theme') || 'scam';
    const status = params.get('status') || '';

    document.body.setAttribute('data-theme', theme);

    const titleEl = document.getElementById('title-text');
    const bodyEl = document.getElementById('body-text');
    const reasonEl = document.getElementById('reason-text');
    const iconContainer = document.getElementById('icon-container');
    const btnBack = document.getElementById('btn-back');
    const btnContinue = document.getElementById('btn-continue');
    const btnReport = document.getElementById('btn-report');
    const whitelistContainer = document.getElementById('whitelist-container');
    const chkWhitelist = document.getElementById('chk-whitelist');
    const btnReadAloud = document.getElementById('btn-read-aloud');

    // Feature 5: Show Whitelist option only for WARN-level alerts
    if (status === 'WARN' && theme === 'scam') {
        whitelistContainer.style.display = 'block';
    }

    if (reason && theme === 'scam') {
        reasonEl.textContent = reason;
    }

    if (theme === 'remote') {
        iconContainer.innerHTML = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>';
        titleEl.textContent = "Before you continue...";
        bodyEl.textContent = "This program lets someone control your computer from far away. Only use this if YOU called the company first, using a phone number you looked up yourself.";
        btnBack.textContent = "Go Back";
        btnContinue.textContent = "I called them myself, continue";
    } else if (theme === 'payment') {
        // SVG for a raised hand/stop
        iconContainer.innerHTML = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 11V6a2 2 0 0 0-4 0v5"></path><path d="M14 11V4a2 2 0 0 0-4 0v7"></path><path d="M10 11V5a2 2 0 0 0-4 0v6"></path><path d="M6 11V8a2 2 0 0 0-4 0v9a10 10 0 0 0 10 10h2a10 10 0 0 0 10-10V14a2 2 0 0 0-4 0v-3"></path></svg>';
        titleEl.textContent = "Quick check before you send anything";
        bodyEl.textContent = "A few minutes ago, we noticed something that looked unsafe. If someone is asking you to send money right now, please call a family member first.";
        btnBack.textContent = "Wait, let me call someone";
        btnContinue.textContent = "Continue";
    } else {
        // Scam
        iconContainer.innerHTML = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
    }

    // Feature 4: Read Aloud Warning
    if (btnReadAloud) {
        btnReadAloud.addEventListener('click', () => {
            if ('speechSynthesis' in window) {
                // Cancel any ongoing speech
                window.speechSynthesis.cancel();
                
                const textToRead = `${titleEl.textContent}. ${bodyEl.textContent}. ${reasonEl.textContent}`;
                const msg = new SpeechSynthesisUtterance(textToRead);
                msg.rate = 0.9; // Slightly slower for elderly comprehension
                window.speechSynthesis.speak(msg);
            } else {
                alert("Sorry, your browser does not support text-to-speech.");
            }
        });
    }

    // Default safe action: Go back
    btnBack.addEventListener('click', () => {
        if (!targetUrl) return;
        const { hostname } = new URL(targetUrl);
        const domain = hostname.replace(/^www\./, '').toLowerCase();

        chrome.runtime.sendMessage({ type: 'HISTORY_BACK', domain }, () => {
            if (window.history.length > 2) {
                window.history.back();
            } else {
                // If there's nowhere to go back to, close tab or go to a safe page like Google
                window.location.href = "https://www.google.com";
            }
        });
    });

    // Continue anyway (override)
    btnContinue.addEventListener('click', () => {
        if (!targetUrl) return;
        
        try {
            const { hostname } = new URL(targetUrl);
            const domain = hostname.replace(/^www\./, '').toLowerCase();
            
            if (theme === 'remote' || theme === 'payment') {
                // Ephemeral allowlist for this session only
                chrome.runtime.sendMessage({ type: 'SESSION_ALLOW', domain }, () => {
                    window.location.href = targetUrl;
                });
            } else {
                const isPermanent = chkWhitelist && chkWhitelist.checked;
                chrome.runtime.sendMessage({ type: 'SESSION_ALLOW', domain, permanent: isPermanent }, () => {
                    window.location.href = targetUrl;
                });
            }
        } catch (e) {
            console.error("Invalid target URL", e);
        }
    });

    // Report site
    btnReport.addEventListener('click', () => {
        btnReport.textContent = "Reporting...";
        btnReport.disabled = true;
        
        try {
            const { hostname } = new URL(targetUrl);
            const domain = hostname.replace(/^www\./, '').toLowerCase();
            
            chrome.runtime.sendMessage({ type: 'REPORT_DOMAIN', domain, reason: reason }, (response) => {
                btnReport.textContent = "Reported!";
                btnReport.style.backgroundColor = "#D1FAE5";
                btnReport.style.color = "#065F46";
                btnReport.style.borderColor = "#10B981";
            });
        } catch(e) {
            console.error(e);
            btnReport.textContent = "Error";
        }
    });
});

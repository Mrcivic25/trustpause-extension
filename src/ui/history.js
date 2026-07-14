document.addEventListener('DOMContentLoaded', () => {
    const historyContainer = document.getElementById('history-container');
    const whitelistContainer = document.getElementById('whitelist-container');

    const escapeHTML = (str) => {
        if (typeof str !== 'string') return '';
        return str.replace(/[&<>'"]/g, 
            tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                "'": '&#39;',
                '"': '&quot;'
            }[tag] || tag)
        );
    };

    const renderAction = (action) => {
        switch(action) {
            case 'went_back': return 'User chose to go back (Safe)';
            case 'continued': return 'User chose to continue anyway';
            case 'whitelisted': return 'User chose to continue and whitelist';
            case 'pending': return 'Closed tab or navigated away';
            default: return 'Unknown';
        }
    };

    chrome.storage.local.get(['history_log', 'allowlist'], (result) => {
        const log = result.history_log || [];
        const allowlist = result.allowlist || [];

        // Render History
        if (log.length === 0) {
            historyContainer.innerHTML = '<div class="empty-state" role="status">No threats blocked in the last 30 days.</div>';
        } else {
            historyContainer.innerHTML = '';
            log.forEach((entry, idx) => {
                const li = document.createElement('li');
                li.className = 'log-item';
                
                const date = new Date(entry.timestamp);
                const timeString = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                const hasRedirects = entry.redirects && entry.redirects.length > 1;
                
                let redirectsHtml = '';
                if (hasRedirects) {
                    redirectsHtml = `
                        <button class="toggle-redirects" aria-expanded="false" aria-controls="redir-${idx}" onclick="document.getElementById('redir-${idx}').style.display = 'block'; this.setAttribute('aria-expanded', 'true'); this.style.display='none';">Show redirect chain</button>
                        <div class="redirect-chain" id="redir-${idx}" role="region" aria-live="polite">
                            <strong>Redirect Path:</strong><br/>
                            ${entry.redirects.map((url, i) => `${i+1}. ${escapeHTML(url)}`).join('<br/>')}
                        </div>
                    `;
                }

                li.innerHTML = `
                    <div class="log-header">
                        <span class="domain">${escapeHTML(entry.domain)}</span>
                        <span class="timestamp">${timeString}</span>
                    </div>
                    <p class="reason"><span class="badge badge-${escapeHTML(entry.status.toLowerCase())}">${escapeHTML(entry.status)}</span> ${escapeHTML(entry.reason)}</p>
                    <div class="meta">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"></path></svg>
                        Action taken: <span class="action-taken">${renderAction(entry.action)}</span>
                    </div>
                    ${redirectsHtml}
                `;
                historyContainer.appendChild(li);
            });
        }

        // Render Whitelist
        if (allowlist.length === 0) {
            whitelistContainer.innerHTML = '<div style="color:var(--c-text-muted); font-size: 16px;" role="status">No sites whitelisted.</div>';
        } else {
            whitelistContainer.innerHTML = '';
            allowlist.forEach(domain => {
                const div = document.createElement('div');
                div.className = 'whitelist-item';
                div.innerHTML = `
                    <span style="font-weight:600;">${escapeHTML(domain)}</span>
                    <button class="btn-remove" aria-label="Remove ${escapeHTML(domain)} from whitelist" data-domain="${escapeHTML(domain)}">Remove</button>
                `;
                whitelistContainer.appendChild(div);
            });

            // Bind remove buttons
            document.querySelectorAll('.btn-remove').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const domainToRemove = e.target.getAttribute('data-domain');
                    chrome.storage.local.get(['allowlist'], (res) => {
                        let list = res.allowlist || [];
                        list = list.filter(d => d !== domainToRemove);
                        chrome.storage.local.set({ allowlist: list }, () => {
                            window.location.reload();
                        });
                    });
                });
            });
        }
    });
});

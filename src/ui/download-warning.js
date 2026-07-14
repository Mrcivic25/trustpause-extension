document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const downloadId = parseInt(params.get('id'), 10);
    const domain = params.get('domain');
    const filename = params.get('file');

    document.getElementById('domain-text').textContent = domain || 'Unknown Domain';
    document.getElementById('filename-text').textContent = filename || 'Unknown File';

    document.getElementById('btn-cancel').addEventListener('click', () => {
        if (downloadId) {
            chrome.downloads.cancel(downloadId, () => {
                window.close(); // Close the warning tab
            });
        } else {
            window.close();
        }
    });

    document.getElementById('btn-keep').addEventListener('click', () => {
        if (downloadId) {
            // Add domain to allowlist to prevent nagging
            if (domain) {
                chrome.runtime.sendMessage({ type: 'SESSION_ALLOW', domain }, () => {
                    chrome.downloads.resume(downloadId, () => {
                        window.close();
                    });
                });
            } else {
                chrome.downloads.resume(downloadId, () => {
                    window.close();
                });
            }
        }
    });
});

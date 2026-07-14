(function() {
    let dialogCount = 0;
    let lastDialogTime = Date.now();
    const checkSpam = () => {
        const now = Date.now();
        if (now - lastDialogTime < 5000) {
            dialogCount++;
            if (dialogCount > 3) {
                window.postMessage({ type: 'TRUSTPAUSE_TECH_SUPPORT_SCAM' }, '*');
                return true;
            }
        } else {
            dialogCount = 1;
        }
        lastDialogTime = now;
        return false;
    };
    const origAlert = window.alert;
    window.alert = function(msg) { if (!checkSpam()) origAlert.call(window, msg); };
    const origConfirm = window.confirm;
    window.confirm = function(msg) { if (!checkSpam()) return origConfirm.call(window, msg); return false; };
})();

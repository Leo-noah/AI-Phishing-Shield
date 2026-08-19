document.addEventListener('DOMContentLoaded', function () {
    // 1. Read parameters from URL query string
    const urlParams = new URLSearchParams(window.location.search);
    
    const rawUrl = urlParams.get('url');
    const rawScore = urlParams.get('score');

    // Decode URL and handle Fallbacks
    const targetUrl = rawUrl ? decodeURIComponent(rawUrl) : 'Unknown URL';
    const scorePercentage = rawScore ? Math.round(parseFloat(rawScore)) : 0;

    // 2. Select HTML Elements
    const urlDisplay = document.getElementById('blockedUrl'); 
    const scoreDisplay = document.getElementById('dangerScoreText'); 
    const ringElement = document.getElementById('scoreRing');
    const closeBtn = document.getElementById('closeTabBtn');

    // 3. Update UI Values
    if (urlDisplay) {
        urlDisplay.innerText = "🔗 " + targetUrl;
    }
    
    if (scoreDisplay) {
        scoreDisplay.innerText = scorePercentage + "%";
    }

    // 4. Render Dynamic Conic Gradient Ring
    if (ringElement) {
        ringElement.style.background = `radial-gradient(#180404 60%, transparent 61%), conic-gradient(#dc3545 ${scorePercentage}%, #33080c ${scorePercentage}%)`;
    }

    // 5. Add Event Listener for the Close Button
    if (closeBtn) {
        closeBtn.addEventListener('click', async function() {
            try {
                // Get the current extension tab and close it
                const tabs = await browser.tabs.query({ active: true, currentWindow: true });
                if (tabs.length > 0) {
                    await browser.tabs.remove(tabs[0].id);
                }
            } catch (err) {
                // Fallback for Chrome compatibility
                if (typeof chrome !== 'undefined' && chrome.tabs) {
                    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                        if (tabs[0]) chrome.tabs.remove(tabs[0].id);
                    });
                } else {
                    // Safe fallback if permissions are missing
                    window.location.href = "https://www.google.com";
                }
            }
        });
    }
});
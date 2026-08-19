// ================================================================
// AI PHISHING SHIELD - FIREFOX BACKGROUND SCRIPT
// ================================================================

console.log("======================================");
console.log("AI PHISHING SHIELD STARTED");
console.log("======================================");

// ================================================================
// 1. USER BYPASS STORAGE
// ================================================================

// URLs that the user explicitly allowed from warning.html
const allowedUrls = new Set();

// ================================================================
// 2. RECEIVE MESSAGE FROM warning.js
// ================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ALLOW_DESTINATION" && message.url) {
    try {
      const targetUrl = getUnwrappedUrl(message.url);

      // Allow only this exact URL for current browser session
      allowedUrls.add(targetUrl);

      console.log("[USER ALLOWED]", targetUrl);

      sendResponse({
        success: true,
      });
    } catch (error) {
      console.error("[ALLOW ERROR]", error);

      sendResponse({
        success: false,
      });
    }
  }

  return true;
});

// ================================================================
// 3. GOOGLE / GMAIL REDIRECT UNWRAP
// ================================================================

function getUnwrappedUrl(rawUrl) {
  try {
    const urlObj = new URL(rawUrl);

    if (urlObj.hostname.includes("google.com") && urlObj.pathname === "/url") {
      const actualDestination = urlObj.searchParams.get("q");

      if (actualDestination) {
        return actualDestination;
      }
    }
  } catch (error) {
    console.error("[URL PARSE ERROR]", error);
  }

  return rawUrl;
}

// ================================================================
// 4. CHECK LOCAL BLACKLIST
// ================================================================

async function checkCache(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["blacklist"], (result) => {
      const blacklist = result.blacklist || [];

      resolve(blacklist.includes(domain));
    });
  });
}

// ================================================================
// 5. SAVE DOMAIN TO LOCAL BLACKLIST
// ================================================================

function saveToBlacklist(domain) {
  chrome.storage.local.get(["blacklist"], (result) => {
    const blacklist = result.blacklist || [];

    if (!blacklist.includes(domain)) {
      blacklist.push(domain);

      chrome.storage.local.set(
        {
          blacklist: blacklist,
        },
        () => {
          console.log("[BLACKLIST SAVED]", domain);
        },
      );
    }
  });
}

// ================================================================
// 6. IGNORE INTERNAL FIREFOX / EXTENSION URLS
// ================================================================

function shouldIgnoreUrl(url) {
  if (!url) {
    return true;
  }

  const ignoredPrefixes = [
    "about:",
    "chrome:",
    "moz-extension:",
    "view-source:",
  ];

  return ignoredPrefixes.some((prefix) => url.startsWith(prefix));
}

// ================================================================
// 7. INTERCEPT MAIN PAGE NAVIGATION
// ================================================================

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only main frame
  if (details.frameId !== 0) {
    return;
  }

  // Ignore Firefox internal pages
  if (shouldIgnoreUrl(details.url)) {
    return;
  }

  // Ignore our own extension pages
  const extensionBaseUrl = chrome.runtime.getURL("");

  if (details.url.startsWith(extensionBaseUrl)) {
    return;
  }

  // ============================================================
  // GET REAL TARGET URL
  // ============================================================

  const targetUrl = getUnwrappedUrl(details.url);

  try {
    const urlObj = new URL(targetUrl);

    const domain = urlObj.hostname;

    console.log("======================================");

    console.log("[NAVIGATION]", targetUrl);

    console.log("[DOMAIN]", domain);

    // ==========================================================
    // 8. USER BYPASS CHECK
    // ==========================================================

    if (allowedUrls.has(targetUrl)) {
      console.log("[BYPASS ALLOWED]", targetUrl);

      return;
    }

    // ==========================================================
    // 9. LOCAL BLACKLIST CHECK
    // ==========================================================

    const isBlacklisted = await checkCache(domain);

    if (isBlacklisted) {
      console.log("[LOCAL BLACKLIST HIT]", domain);

      const blockedPageUrl = chrome.runtime.getURL(
        "blocked.html" + `?url=${encodeURIComponent(targetUrl)}` + "&score=100",
      );

      await chrome.tabs.update(details.tabId, {
        url: blockedPageUrl,
      });

      return;
    }

    // ==========================================================
    // 10. SEND URL TO FLASK BACKEND
    // ==========================================================

    console.log("[BACKEND REQUEST]", targetUrl);

    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        url: targetUrl,
      }),
    });

    // ==========================================================
    // 11. CHECK FLASK RESPONSE
    // ==========================================================

    if (!response.ok) {
      const errorText = await response.text();

      console.error(
        "[FLASK HTTP ERROR]",
        response.status,
        response.statusText,
        errorText,
      );

      return;
    }

    // ==========================================================
    // 12. READ JSON RESPONSE
    // ==========================================================

    const resData = await response.json();

    console.log("[BACKEND RESULT]", resData);

    if (typeof resData.danger_score !== "number" || !resData.status) {
      console.error("[INVALID BACKEND RESPONSE]", resData);

      return;
    }

    const dangerScore = Math.round(resData.danger_score);

    const status = resData.status;

    console.log("[DANGER SCORE]", dangerScore);

    console.log("[STATUS]", status);

    console.log("[TRUST STATUS]", resData.trust_status);

    // ==========================================================
    // 13. DANGEROUS
    // ==========================================================

    if (status === "DANGEROUS") {
      console.log("[ACTION] BLOCK");

      // Save domain to local blacklist
      saveToBlacklist(domain);

      const blockedPageUrl = chrome.runtime.getURL(
        "blocked.html" +
          `?url=${encodeURIComponent(targetUrl)}` +
          `&score=${dangerScore}`,
      );

      await chrome.tabs.update(details.tabId, {
        url: blockedPageUrl,
      });
    }

    // ==========================================================
    // 14. WARNING
    // ==========================================================
    else if (status === "WARNING") {
      console.log("[ACTION] WARNING");

      const warningPageUrl = chrome.runtime.getURL(
        "warning.html" +
          `?url=${encodeURIComponent(targetUrl)}` +
          `&score=${dangerScore}`,
      );

      await chrome.tabs.update(details.tabId, {
        url: warningPageUrl,
      });
    }

    // ==========================================================
    // 15. SAFE
    // ==========================================================
    else if (status === "SAFE") {
      console.log("[ACTION] SAFE - ALLOW");

      // Do nothing.
      // Normal navigation continues.
    } else {
      console.error("[UNKNOWN STATUS]", status);
    }

    console.log("======================================");
  } catch (error) {
    console.error("[BACKGROUND ERROR]", error);
  }
});

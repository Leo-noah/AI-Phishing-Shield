document.addEventListener("DOMContentLoaded", function () {
  const params = new URLSearchParams(window.location.search);

  const rawUrl = params.get("url");

  const rawScore = params.get("score") || "0";

  let targetUrl = rawUrl || "Unknown URL";

  if (
    targetUrl !== "Unknown URL" &&
    !targetUrl.startsWith("http://") &&
    !targetUrl.startsWith("https://")
  ) {
    targetUrl = "https://" + targetUrl;
  }

  let scorePercentage = 0;

  const parsedScore = parseFloat(rawScore);

  if (!Number.isNaN(parsedScore)) {
    scorePercentage = Math.round(parsedScore);
  }

  const warningUrl = document.getElementById("warningUrl");

  const dangerScore = document.getElementById("dangerScore");

  const backBtn = document.getElementById("backBtn");

  const proceedBtn = document.getElementById("proceedBtn");

  // ============================================================
  // SHOW URL
  // ============================================================

  if (warningUrl) {
    warningUrl.textContent = "🔗 " + targetUrl;
  }

  // ============================================================
  // SHOW DANGER SCORE
  // ============================================================

  if (dangerScore) {
    dangerScore.textContent = `Danger Score: ${scorePercentage}%`;
  }

  // ============================================================
  // GO BACK
  // ============================================================

  if (backBtn) {
    backBtn.addEventListener("click", function () {
      if (window.history.length > 2) {
        window.history.go(-2);
      } else if (document.referrer) {
        window.location.href = document.referrer;
      } else {
        window.location.href = "https://www.google.com";
      }
    });
  }

  // ============================================================
  // PROCEED ANYWAY
  // ============================================================

  if (proceedBtn) {
    proceedBtn.addEventListener("click", function () {
      if (targetUrl === "Unknown URL") {
        return;
      }

      chrome.runtime.sendMessage(
        {
          type: "ALLOW_DESTINATION",

          url: targetUrl,
        },
        function (response) {
          if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError);

            return;
          }

          if (response && response.success) {
            window.location.href = targetUrl;
          }
        },
      );
    });
  }
});

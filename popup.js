document.addEventListener("DOMContentLoaded", () => {
    const checkButton = document.getElementById("check");
    const resultText = document.getElementById("result");

    if (!checkButton) {
        console.error("[ERROR] Button element not found!");
        return;
    }

    checkButton.addEventListener("click", () => {
        checkButton.disabled = true;
        checkButton.innerHTML = `<span class="loading"></span> Checking...`;
        resultText.textContent = "";

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs.length || !tabs[0].url) {
                resultText.textContent = "❌ Error: No active tab found.";
                resetButton();
                return;
            }

            const url = tabs[0].url;
            console.log(`[INFO] Sending URL to background: ${url}`);

            chrome.runtime.sendMessage({ action: "checkPhishing", url }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("[ERROR] Message error:", chrome.runtime.lastError.message);
                    resultText.textContent = "❌ Background script not responding.";
                } else {
                    resultText.textContent = response?.result || "❌ Error: No response received.";
                }

                resetButton();
            });
        });
    });

    function resetButton() {
        checkButton.disabled = false;
        checkButton.innerHTML = "Check This Page";
    }
});

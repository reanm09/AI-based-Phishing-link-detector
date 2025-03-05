let API_KEY = "API-KEY";

console.log("[INFO] Background script loaded and ready!");

chrome.alarms.create("keepAlive", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "keepAlive") {
        console.log("[INFO] Keeping service worker alive...");
    }
});

function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch (error) {
        return false;
    }
}

async function loadPhishTankData() {
    try {
        const response = await fetch(chrome.runtime.getURL("data/phishtank.json"));
        return await response.json();
    } catch (error) {
        console.error("[ERROR] Failed to load PhishTank JSON:", error);
        return {};
    }
}

async function checkPhishTank(url) {
    try {
        const phishData = await loadPhishTankData();
        const domain = new URL(url).hostname;  

        const isPhishing = phishData.some(entry => {
            try {
                return new URL(entry.url).hostname === domain;
            } catch (error) {
                return false; 
            }
        });

        if (isPhishing) {
            return `⚠️ This is a known phishing site! Refrain from entering any personal information.`;
        }

        return null;
    } catch (error) {
        console.error("[ERROR] Failed to check PhishTank JSON:", error);
        return "❌ Error checking PhishTank.";
    }
}



async function checkSafeBrowsing(url) {        
    console.log("[INFO] Checking Safe Browsing API for:", url);

    try {
        let response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client: { clientId: "phishing-detector", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            })
        });

        if (!response.ok) {
            console.error("[ERROR] Google Safe Browsing API failed.");
            return "❌ Error checking website.";
        }

        let data = await response.json();
        return data.matches ? `⚠️ This website is dangerous!` : null;
    } catch (error) {
        console.error("[ERROR] Safe Browsing API failed:", error);
        return "❌ Error checking website.";
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("[INFO] Received message:", request);

    if (request.action === "debug_test") {
        sendResponse({ result: "✅ Background script is running!" });
        return true;
    }

    if (request.action === "checkPhishing") {
        let urlToCheck = request.url;
        if (!urlToCheck) {
            sendResponse({ result: "❌ Error: Invalid URL" });
            return false;
        }

        console.log("[INFO] Checking URL:", urlToCheck);

        (async () => {
            try {
                let safeBrowsingResult = await checkSafeBrowsing(urlToCheck);
                if (safeBrowsingResult) {
                    console.warn(`[WARNING] Google API flagged this site: ${urlToCheck}`);
                    sendResponse({ result: safeBrowsingResult });
                    return;
                }

                let phishTankResult = await checkPhishTank(urlToCheck);
                if (phishTankResult) {
                    console.warn(`[WARNING] PhishTank flagged this site: ${urlToCheck}`);
                    sendResponse({ result: phishTankResult });
                    return;
                }

                console.log("[INFO] URL is safe according to Google & PhishTank, running ML Model...");

                chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
                    if (!tabs.length || !tabs[0].id) {
                        sendResponse({ result: "❌ No active tab found." });
                        return;
                    }

                    const tabId = tabs[0].id;

                    try {
                        await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
                        console.log("[INFO] Successfully injected content script.");
                    } catch (error) {
                        console.error(`[ERROR] Failed to inject content script: ${error.message}`);
                        sendResponse({ result: "❌ Error: Could not inject content script." });
                        return;
                    }

                    chrome.tabs.sendMessage(tabId, { action: "predictML", url: urlToCheck }, (response) => {
                        if (chrome.runtime.lastError) {
                            console.error(`[ERROR] Failed to send message to content script: ${chrome.runtime.lastError.message}`);
                            sendResponse({ result: "❌ Error: Could not communicate with content script." });
                        } else {
                            console.log("[INFO] ML Model Response:", response);
                            sendResponse({ result: response?.result || "❌ Error: No response from ML." });
                        }
                    });
                });

            } catch (error) {
                sendResponse({ result: "❌ Error during phishing check." });
            }
        })();

        return true; 
    }
});

chrome.runtime.onInstalled.addListener(() => {
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach((tab) => {
            chrome.scripting.executeScript({
                target: { tabId: tab.id },
                files: ['content.js']
            }, () => {
                if (chrome.runtime.lastError) {
                    console.error(`Error injecting content script into tab ${tab.id}: ${chrome.runtime.lastError.message}`);
                } else {
                    console.log(`Injected content script into tab ${tab.id}`);
                }
            });
        });
    });
});

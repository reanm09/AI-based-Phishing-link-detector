(async () => {
    console.log("[INFO] Loading Phishing Detector Model...");

    const response = await fetch(chrome.runtime.getURL("ml-model/model.json"));
    const modelData = await response.json();

    class SimpleNeuralNet {
        constructor(weights, bias) {
            this.weights = weights;
            this.bias = bias;
        }

        sigmoid(x) {
            return 1 / (1 + Math.exp(-x));
        }

        predict(url) {
            let input1 = url.length % 100;
            let input2 = url.includes("-") ? 1 : 0;
            let weightedSum = (input1 * this.weights[0][0]) + (input2 * this.weights[0][1]) + this.bias[0];
            let output = this.sigmoid(weightedSum);
            return output > 0.3 ? "⚠️ Suspected Phishing" : "✅ Safe Website";
        }
    }

    const net = new SimpleNeuralNet(modelData.weights, modelData.bias);

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "predictML") {
            console.log("[INFO] Received URL for ML Check:", request.url);
            const result = net.predict(request.url);
            sendResponse({ result });
        }
    });

    console.log("[INFO] Phishing Detector Ready! 🚀");
})();

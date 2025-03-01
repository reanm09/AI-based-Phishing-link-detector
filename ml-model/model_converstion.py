import numpy as np
import json
from sklearn.neural_network import MLPClassifier

# ✅ Sample phishing data (Fake Example)
X = np.array([
    [15, 1],  # Short URL, has "-"
    [80, 0],  # Long URL, no "-"
    [45, 1],  # Medium URL, has "-"
    [30, 0],  # Short, no "-"
])

y = np.array([1, 0, 1, 0])  # 1 = Phishing, 0 = Safe

# ✅ Train a Simple Neural Network
clf = MLPClassifier(hidden_layer_sizes=(2,), max_iter=500, random_state=42)
clf.fit(X, y)

# ✅ Extract Weights & Biases
weights = clf.coefs_
bias = clf.intercepts_

# ✅ Save as JSON for JavaScript
model_data = {
    "weights": [weights[0].tolist(), weights[1].tolist()], 
    "bias": [bias[0].tolist(), bias[1].tolist()]
}

with open("ml-model/model.json", "w") as f:
    json.dump(model_data, f)

print("✅ Model Weights Saved!")

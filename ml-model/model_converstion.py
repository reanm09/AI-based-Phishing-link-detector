import numpy as np
import json
from sklearn.neural_network import MLPClassifier

X = np.array([
    [15, 1],  
    [80, 0],  
    [45, 1],  
    [30, 0],  
])

y = np.array([1, 0, 1, 0]) 
clf = MLPClassifier(hidden_layer_sizes=(2,), max_iter=500, random_state=42)
clf.fit(X, y)

weights = clf.coefs_
bias = clf.intercepts_

model_data = {
    "weights": [weights[0].tolist(), weights[1].tolist()], 
    "bias": [bias[0].tolist(), bias[1].tolist()]
}

with open("ml-model/model.json", "w") as f:
    json.dump(model_data, f)

print("✅ Model Weights Saved!")

import pandas as pd
import numpy as np
import joblib
import os
import json
import datetime
import requests
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from concurrent.futures import ThreadPoolExecutor

MODEL_PATH = "ml-model/model.pkl"
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

print("[INFO] Loading dataset...")
df = pd.read_csv("dataset/merged_phishing_dataset.csv")
print(f"[INFO] Loaded {df.shape[0]} rows from merged dataset")

tld_blacklist = {".xyz", ".top", ".tk", ".club", ".info", ".biz", ".cc", ".link", ".work", ".support",
                 ".science", ".site", ".gq", ".kim", ".country", ".cricket", ".party", ".racing",
                 ".date", ".win"}
suspicious_keywords = {"login", "secure", "bank", "verify", "account", "update", "free", "win"}

def extract_features(url):
    """ Extracts static features from the given URL """
    parsed = urlparse(url)
    domain = parsed.netloc
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    
    return [
        len(url),                         
        len(domain),                      
        len(parsed.path),                 
        url.count('-'),                   
        url.count('@'),                  
        url.count('?'),                   
        url.count('='),                   
        int(domain.count('.') > 2),       
        int("https" not in parsed.scheme),
        int(tld in tld_blacklist),        
        sum(word in url.lower() for word in suspicious_keywords),  
        sum(c.isdigit() for c in domain) / max(1, len(domain)),  
    ]

print("[INFO] Extracting features (this may take a while)...")
with ThreadPoolExecutor(max_workers=10) as executor:
    df["features"] = list(executor.map(extract_features, df["URL"]))

X = np.array(df["features"].tolist())
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("[INFO] Training RandomForest model...")
model = RandomForestClassifier(n_estimators=300, max_depth=15, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"[INFO] Model Accuracy: {accuracy:.2f}")

joblib.dump(model, MODEL_PATH)
print(f"[INFO] Model saved successfully at: {MODEL_PATH}")

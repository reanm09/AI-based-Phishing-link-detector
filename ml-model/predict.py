import requests
import joblib
import numpy as np
import whois
import datetime
from urllib.parse import urlparse

# Google Safe Browsing API Key (Replace with your actual key)
API_KEY = "AIzaSyDPCYyUf-a0toU0GwTSimRK3ZZpBCnmySk"
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY

# Load the trained model
model = joblib.load("ml-model/model.pkl")

# Suspicious TLDs and keywords
tld_blacklist = [".zip", ".review", ".country", ".kim", ".cricket", ".science", ".work", ".party", ".gq", ".cc"]
suspicious_keywords = ["confirm", "account", "login", "update", "verify", "password", "banking", "secure"]

# WHOIS Feature Extraction
def get_domain_age_and_expiry(domain):
    try:
        domain_info = whois.whois(domain)
        
        # Convert WHOIS dates to datetime format
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        
        # Handle cases where WHOIS returns lists
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Calculate domain age in days
        if creation_date:
            domain_age = (datetime.datetime.now() - creation_date).days
        else:
            domain_age = 0  # Unknown domain age is suspicious

        # Calculate time to expiration in days
        if expiration_date:
            time_to_expiry = (expiration_date - datetime.datetime.now()).days
        else:
            time_to_expiry = 0  # Domains with no expiry info are suspicious

        return domain_age, time_to_expiry

    except:
        return 0, 0  # If WHOIS fails, assume suspicious values

# Feature extraction function
def extract_features(url):
    parsed = urlparse(url)
    tld = "." + parsed.netloc.split(".")[-1] if "." in parsed.netloc else ""

    # Get WHOIS domain age and expiration
    domain_age, time_to_expiry = get_domain_age_and_expiry(parsed.netloc)

    return [
        len(url),                                 # URL length
        len(parsed.netloc),                       # Hostname length
        len(parsed.path),                         # Path length
        url.count('-'),                           # Number of hyphens
        url.count('@'),                           # Number of '@'
        url.count('?'),                           # Number of '?'
        url.count('='),                           # Number of '='
        int(parsed.netloc.count('.') > 2),       # More than 2 subdomains
        int("https" not in parsed.scheme),        # No HTTPS
        int(tld in tld_blacklist),                # Suspicious TLD
        sum(1 for word in suspicious_keywords if word in url.lower()),  # Keyword count
        sum(c.isdigit() for c in parsed.netloc) / max(1, len(parsed.netloc)),  # Digit-to-Char ratio
        domain_age,                               # Domain Age (days)
        time_to_expiry                            # Days to Expiration
    ]

def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(API_URL, json=payload)
    data = response.json()
    return "matches" in data  # Returns True if Google flags the URL

# Test URL
test_url = "https://www.sainsburys.cc/"
if check_google_safe_browsing(test_url):
    print("Phishing (Flagged by Google Safe Browsing)")
else:
    features = np.array(extract_features(test_url)).reshape(1, -1)
    if features.shape[1] != 14:
        print("Feature mismatch! Check extract_features in predict.py")
    prediction = model.predict(features)
    print("Phishing" if prediction[0] == 1 else "Legitimate")

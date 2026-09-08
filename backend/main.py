from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

import joblib
import pandas as pd

from urllib.parse import urlparse

from .features import extract_features


app = FastAPI(title="PhishGuard AI")


# ==================================================
# CORS
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# LOAD MODEL
# ==================================================

model = joblib.load(
    "backend/phishing_model.pkl"
)


# ==================================================
# REQUEST MODEL
# ==================================================

class URLRequest(BaseModel):
    url: str


# ==================================================
# HOME
# ==================================================

@app.get("/")
def home():

    return {
        "message": "PhishGuard AI Backend is Running!"
    }


# ==================================================
# ANALYZE URL
# ==================================================

@app.post("/analyze")
def analyze_url(request: URLRequest):

    url = request.url.strip()

    # ----------------------------------------------
    # Parse URL
    # ----------------------------------------------

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    url_lower = url.lower()

    # ----------------------------------------------
    # Extract 18 ML features
    # ----------------------------------------------

    features = extract_features(url)

    # ----------------------------------------------
    # Exact model feature order
    # ----------------------------------------------

    feature_values = pd.DataFrame(
        [features]
    )

    feature_values = feature_values[
        model.feature_names_in_
    ]

    # ----------------------------------------------
    # ML Prediction
    #
    # 0 = Phishing
    # 1 = Legitimate
    # ----------------------------------------------

    prediction = model.predict(
        feature_values
    )[0]

    probabilities = model.predict_proba(
        feature_values
    )[0]

    classes = list(model.classes_)

    phishing_index = classes.index(0)
    legitimate_index = classes.index(1)

    phishing_probability = (
        probabilities[phishing_index] * 100
    )

    legitimate_probability = (
        probabilities[legitimate_index] * 100
    )

    # ==================================================
    # RULE-BASED SECURITY CHECK
    # ==================================================

    phishing_keywords = [

        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "bank",
        "payment",
        "billing",
        "authenticate",
        "authentication",
        "wallet",
        "recover",
        "recovery",
        "confirm",
        "confirmation",
        "unlock",
        "suspended",
        "security",
        "update",
        "credential",
        "credentials"

    ]

    # ----------------------------------------------
    # Find suspicious keywords
    # ----------------------------------------------

    keyword_matches = [
        word
        for word in phishing_keywords
        if word in url_lower
    ]

    unique_keyword_matches = list(
        dict.fromkeys(keyword_matches)
    )

    # ----------------------------------------------
    # Rule score
    # ----------------------------------------------

    rule_score = 0

    # Multiple suspicious keywords
    if len(unique_keyword_matches) >= 3:

        rule_score += 50

    elif len(unique_keyword_matches) == 2:

        rule_score += 35

    elif len(unique_keyword_matches) == 1:

        rule_score += 15

    # ----------------------------------------------
    # Suspicious keyword in path
    # ----------------------------------------------

    path_keyword_matches = [
        word
        for word in phishing_keywords
        if word in path.lower()
    ]

    if len(path_keyword_matches) >= 1:

        rule_score += 25

    # ----------------------------------------------
    # Hyphenated domain
    # ----------------------------------------------

    if hostname.count("-") >= 2:

        rule_score += 20

    elif hostname.count("-") == 1:

        rule_score += 5

    # ----------------------------------------------
    # IP address
    # ----------------------------------------------

    if features["IsDomainIP"] == 1:

        rule_score += 40

    # ----------------------------------------------
    # Obfuscation
    # ----------------------------------------------

    if features["HasObfuscation"] == 1:

        rule_score += 25

    # ----------------------------------------------
    # Multiple subdomains
    # ----------------------------------------------

    if features["NoOfSubDomain"] >= 3:

        rule_score += 20

    elif features["NoOfSubDomain"] == 2:

        rule_score += 10

    # ----------------------------------------------
    # Excessive digits
    # ----------------------------------------------

    if features["NoOfDegitsInURL"] >= 8:

        rule_score += 15

    # ----------------------------------------------
    # Very long URL
    # ----------------------------------------------

    if features["URLLength"] > 100:

        rule_score += 15

    # ----------------------------------------------
    # @ symbol
    # ----------------------------------------------

    if "@" in url:

        rule_score += 30

    # ----------------------------------------------
    # Clamp rule score
    # ----------------------------------------------

    rule_score = min(
        rule_score,
        100
    )

    # ==================================================
    # FINAL SCORE
    # ==================================================

    final_score = max(
        phishing_probability,
        rule_score
    )

    # ----------------------------------------------
    # Strong phishing combination
    #
    # Example:
    # paypal-bank-login.com/account/verify
    # ----------------------------------------------

    if (
        len(unique_keyword_matches) >= 2
        and (
            hostname.count("-") >= 1
            or len(path_keyword_matches) >= 1
        )
    ):

        final_score = max(
            final_score,
            75
        )

    # ----------------------------------------------
    # IP + suspicious keyword
    # ----------------------------------------------

    if (
        features["IsDomainIP"] == 1
        and len(unique_keyword_matches) >= 1
    ):

        final_score = max(
            final_score,
            85
        )

    # ----------------------------------------------
    # @ symbol
    # ----------------------------------------------

    if "@" in url:

        final_score = max(
            final_score,
            80
        )

    final_score = min(
        final_score,
        100
    )

    # ==================================================
    # RISK LEVEL
    # ==================================================

    if final_score >= 70:

        risk = "HIGH"

    elif final_score >= 40:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    # ==================================================
    # EXPLANATION
    # ==================================================

    reasons = []

    if features["IsHTTPS"] == 0:

        reasons.append(
            "Website is not using HTTPS"
        )

    if features["IsDomainIP"] == 1:

        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    if len(unique_keyword_matches) >= 2:

        reasons.append(
            "Multiple suspicious keywords detected: "
            + ", ".join(unique_keyword_matches)
        )

    elif len(unique_keyword_matches) == 1:

        reasons.append(
            "Suspicious keyword detected: "
            + unique_keyword_matches[0]
        )

    if len(path_keyword_matches) >= 1:

        reasons.append(
            "Suspicious keyword found in the URL path"
        )

    if hostname.count("-") >= 2:

        reasons.append(
            "Domain contains multiple hyphens"
        )

    if features["NoOfSubDomain"] >= 2:

        reasons.append(
            "URL contains multiple subdomains"
        )

    if features["HasObfuscation"] == 1:

        reasons.append(
            "URL contains encoded characters"
        )

    if features["NoOfDegitsInURL"] >= 8:

        reasons.append(
            "URL contains an unusually high number of digits"
        )

    if features["URLLength"] > 100:

        reasons.append(
            "URL is unusually long"
        )

    if "@" in url:

        reasons.append(
            "URL contains an unusual @ symbol"
        )

    # ----------------------------------------------
    # ML explanation
    # ----------------------------------------------

    if (
        phishing_probability >= 70
        and not any(
            "suspicious" in reason.lower()
            for reason in reasons
        )
    ):

        reasons.append(
            "ML model detected suspicious URL characteristics"
        )

    # ----------------------------------------------
    # No suspicious indicators
    # ----------------------------------------------

    if not reasons:

        reasons.append(
            "No suspicious indicators detected"
        )

    # ==================================================
    # RESPONSE
    # ==================================================

    return {

        "url": url,

        "risk": risk,

        "score": round(
            final_score,
            2
        ),

        "prediction": int(
            prediction
        ),

        "phishing_probability": round(
            phishing_probability,
            2
        ),

        "legitimate_probability": round(
            legitimate_probability,
            2
        ),

        "rule_score": round(
            rule_score,
            2
        ),

        "features": features,

        "reasons": reasons
    }
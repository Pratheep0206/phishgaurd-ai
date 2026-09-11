from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

import joblib
import pandas as pd

from urllib.parse import urlparse
from pathlib import Path

from .features import extract_features


# ==================================================
# APP
# ==================================================

app = FastAPI(
    title="PhishGuard AI",
    description="Explainable AI-Powered Phishing Detection",
    version="1.0.0"
)


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
# MODEL PATH
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "phishing_model.pkl"


# ==================================================
# LOAD ML MODEL
# ==================================================

try:

    model = joblib.load(MODEL_PATH)

except Exception as e:

    raise RuntimeError(
        f"Could not load phishing model from {MODEL_PATH}: {e}"
    )


# ==================================================
# REQUEST MODEL
# ==================================================

class URLRequest(BaseModel):

    url: str


# ==================================================
# HOME / HEALTH CHECK
# ==================================================

@app.get("/")
def home():

    return {
        "message": "PhishGuard AI Backend is Running!",
        "status": "online"
    }


# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "model": "loaded"
    }


# ==================================================
# ANALYZE URL
# ==================================================

@app.post("/analyze")
def analyze_url(request: URLRequest):

    url = request.url.strip()


    # ==================================================
    # BASIC VALIDATION
    # ==================================================

    if not url:

        return {
            "error": "URL cannot be empty."
        }


    # Add scheme if user enters:
    # google.com instead of https://google.com

    analysis_url = url

    if not analysis_url.startswith(
        ("http://", "https://")
    ):

        analysis_url = "http://" + analysis_url


    # ==================================================
    # PARSE URL
    # ==================================================

    parsed = urlparse(analysis_url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    url_lower = analysis_url.lower()


    # ==================================================
    # EXTRACT ML FEATURES
    # ==================================================

    features = extract_features(analysis_url)


    # ==================================================
    # EXACT MODEL FEATURE ORDER
    # ==================================================

    feature_values = pd.DataFrame(
        [features]
    )

    feature_values = feature_values[
        model.feature_names_in_
    ]


    # ==================================================
    # ML PREDICTION
    #
    # 0 = Phishing
    # 1 = Legitimate
    # ==================================================

    prediction = model.predict(
        feature_values
    )[0]


    probabilities = model.predict_proba(
        feature_values
    )[0]


    classes = list(
        model.classes_
    )


    phishing_index = classes.index(0)

    legitimate_index = classes.index(1)


    phishing_probability = (
        probabilities[phishing_index] * 100
    )


    legitimate_probability = (
        probabilities[legitimate_index] * 100
    )


    # ==================================================
    # LAYER 2 — RULE BASED SECURITY ANALYSIS
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


    # ==================================================
    # FIND SUSPICIOUS KEYWORDS
    # ==================================================

    keyword_matches = [

        word

        for word in phishing_keywords

        if word in url_lower

    ]


    unique_keyword_matches = list(
        dict.fromkeys(
            keyword_matches
        )
    )


    # ==================================================
    # KEYWORDS FOUND IN PATH
    # ==================================================

    path_keyword_matches = [

        word

        for word in phishing_keywords

        if word in path.lower()

    ]


    # ==================================================
    # SECURITY INDICATORS
    # ==================================================

    security_indicators = []


    # ==================================================
    # HTTPS
    # ==================================================

    if features["IsHTTPS"] == 0:

        security_indicators.append(
            "Website is not using HTTPS"
        )


    # ==================================================
    # IP ADDRESS
    # ==================================================

    if features["IsDomainIP"] == 1:

        security_indicators.append(
            "URL uses an IP address instead of a domain name"
        )


    # ==================================================
    # SUSPICIOUS KEYWORDS
    # ==================================================

    for keyword in unique_keyword_matches:

        security_indicators.append(
            f"Suspicious keyword detected: {keyword}"
        )


    # ==================================================
    # SUSPICIOUS PATH
    # ==================================================

    if len(path_keyword_matches) >= 1:

        security_indicators.append(
            "Suspicious keyword found in the URL path"
        )


    # ==================================================
    # MULTIPLE HYPHENS
    # ==================================================

    if hostname.count("-") >= 2:

        security_indicators.append(
            "Domain contains multiple hyphens"
        )


    # ==================================================
    # MULTIPLE SUBDOMAINS
    # ==================================================

    if features["NoOfSubDomain"] >= 2:

        security_indicators.append(
            "URL contains multiple subdomains"
        )


    # ==================================================
    # OBFUSCATION
    # ==================================================

    if features["HasObfuscation"] == 1:

        security_indicators.append(
            "URL contains encoded or obfuscated characters"
        )


    # ==================================================
    # EXCESSIVE DIGITS
    # ==================================================

    if features["NoOfDegitsInURL"] >= 8:

        security_indicators.append(
            "URL contains an unusually high number of digits"
        )


    # ==================================================
    # VERY LONG URL
    # ==================================================

    if features["URLLength"] > 100:

        security_indicators.append(
            "URL is unusually long"
        )


    # ==================================================
    # @ SYMBOL
    # ==================================================

    if "@" in analysis_url:

        security_indicators.append(
            "URL contains an unusual @ symbol"
        )


    # ==================================================
    # REMOVE DUPLICATES
    # ==================================================

    security_indicators = list(
        dict.fromkeys(
            security_indicators
        )
    )


    # ==================================================
    # RULE SCORE
    # ==================================================

    rule_score = 0


    # Multiple suspicious keywords

    if len(unique_keyword_matches) >= 3:

        rule_score += 50

    elif len(unique_keyword_matches) == 2:

        rule_score += 35

    elif len(unique_keyword_matches) == 1:

        rule_score += 15


    # Suspicious keyword in path

    if len(path_keyword_matches) >= 1:

        rule_score += 25


    # Hyphenated domain

    if hostname.count("-") >= 2:

        rule_score += 20

    elif hostname.count("-") == 1:

        rule_score += 5


    # IP address

    if features["IsDomainIP"] == 1:

        rule_score += 40


    # Obfuscation

    if features["HasObfuscation"] == 1:

        rule_score += 25


    # Multiple subdomains

    if features["NoOfSubDomain"] >= 3:

        rule_score += 20

    elif features["NoOfSubDomain"] == 2:

        rule_score += 10


    # Excessive digits

    if features["NoOfDegitsInURL"] >= 8:

        rule_score += 15


    # Very long URL

    if features["URLLength"] > 100:

        rule_score += 15


    # @ symbol

    if "@" in analysis_url:

        rule_score += 30


    # Maximum rule score

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


    # ==================================================
    # STRONG PHISHING COMBINATION
    # ==================================================

    if (
        len(unique_keyword_matches) >= 2

        and (

            hostname.count("-") >= 1

            or

            len(path_keyword_matches) >= 1

        )
    ):

        final_score = max(
            final_score,
            75
        )


    # ==================================================
    # IP + SUSPICIOUS KEYWORD
    # ==================================================

    if (
        features["IsDomainIP"] == 1

        and

        len(unique_keyword_matches) >= 1
    ):

        final_score = max(
            final_score,
            85
        )


    # ==================================================
    # @ SYMBOL
    # ==================================================

    if "@" in analysis_url:

        final_score = max(
            final_score,
            80
        )


    # Maximum

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
    # EXPLANATION REASONS
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
            + ", ".join(
                unique_keyword_matches
            )
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


    if "@" in analysis_url:

        reasons.append(
            "URL contains an unusual @ symbol"
        )


    # ==================================================
    # ML EXPLANATION
    # ==================================================

    if (
        phishing_probability >= 70

        and

        not any(
            "suspicious"
            in reason.lower()

            for reason in reasons
        )
    ):

        reasons.append(
            "ML model detected suspicious URL characteristics"
        )


    # ==================================================
    # NO SUSPICIOUS INDICATORS
    # ==================================================

    if not reasons:

        reasons.append(
            "No suspicious indicators detected"
        )


    # ==================================================
    # SECURITY STATUS
    # ==================================================

    if len(security_indicators) == 0:

        security_status = (
            "No suspicious indicators detected"
        )

    elif len(security_indicators) <= 2:

        security_status = (
            "Low number of security indicators"
        )

    elif len(security_indicators) <= 4:

        security_status = (
            "Several security indicators detected"
        )

    else:

        security_status = (
            "Multiple security indicators detected"
        )


    # ==================================================
    # OVERALL VERDICT
    # ==================================================

    if final_score >= 70:

        overall_verdict = "PHISHING"

    elif final_score >= 40:

        overall_verdict = "SUSPICIOUS"

    else:

        overall_verdict = "LIKELY SAFE"


    # ==================================================
    # RECOMMENDATION
    # ==================================================

    if risk == "HIGH":

        recommendation = (
            "Avoid entering passwords, OTPs, payment details, "
            "or other sensitive information on this website."
        )

    elif risk == "MEDIUM":

        recommendation = (
            "Be cautious before entering personal information. "
            "Verify the website address and its source."
        )

    else:

        recommendation = (
            "The URL shows a low phishing risk based on the "
            "available analysis. Always verify the website "
            "before sharing sensitive information."
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

        "overall_verdict": overall_verdict,

        "recommendation": recommendation,


        # ==================================================
        # ML RESULTS
        # ==================================================

        "phishing_probability": round(
            phishing_probability,
            2
        ),

        "legitimate_probability": round(
            legitimate_probability,
            2
        ),


        # ==================================================
        # RULE BASED SECURITY RESULTS
        # ==================================================

        "rule_score": round(
            rule_score,
            2
        ),

        "security_analysis": {

            "status": security_status,

            "indicator_count": len(
                security_indicators
            ),

            "indicators": security_indicators,

            "rule_score": round(
                rule_score,
                2
            )

        },


        # ==================================================
        # URL FEATURES
        # ==================================================

        "features": features,


        # ==================================================
        # EXPLANATION
        # ==================================================

        "reasons": reasons

    }
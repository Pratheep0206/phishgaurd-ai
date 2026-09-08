from urllib.parse import urlparse
import re


def analyze_url(url: str):

    score = 0
    reasons = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    url_lower = url.lower()

    # 1. HTTPS check
    if parsed.scheme != "https":
        score += 15
        reasons.append("Website is not using HTTPS")

    # 2. IP address check
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        score += 30
        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # 3. Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "bank",
        "password",
        "signin",
        "confirm"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        score += 15
        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # 4. Very long URL
    if len(url) > 100:
        score += 15
        reasons.append("URL is unusually long")

    # 5. Too many subdomains
    domain_parts = hostname.split(".")

    if len(domain_parts) > 4:
        score += 15
        reasons.append("URL contains too many subdomains")

    # 6. @ symbol
    if "@" in url:
        score += 20
        reasons.append("URL contains an unusual @ symbol")

    # 7. Hyphen in domain
    if "-" in hostname:
        score += 10
        reasons.append("Domain contains a suspicious hyphen pattern")

    # 8. Suspicious TLDs
    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".link",
        ".shop",
        ".online"
    ]

    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        score += 20
        reasons.append("Domain uses a commonly abused TLD")

    # 9. Too many dots
    if hostname.count(".") > 3:
        score += 10
        reasons.append("Domain contains an unusually high number of dots")

    # 10. Too many special characters
    special_characters = re.findall(r"[^a-zA-Z0-9./:?=&_-]", url)

    if len(special_characters) > 3:
        score += 10
        reasons.append("URL contains many unusual characters")

    # Limit score
    score = min(score, 100)

    # Risk level
    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # If no suspicious indicators
    if not reasons:
        reasons.append("No suspicious indicators detected")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }
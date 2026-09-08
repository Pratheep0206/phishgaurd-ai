from urllib.parse import urlparse
import re


def extract_features(url: str):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Remove scheme for character calculations
    clean_url = url

    # -----------------------------
    # Basic URL information
    # -----------------------------

    url_length = len(url)
    domain_length = len(hostname)

    # -----------------------------
    # IP address check
    # -----------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    is_domain_ip = (
        1 if re.match(ip_pattern, hostname) else 0
    )

    # -----------------------------
    # TLD length
    # -----------------------------

    if "." in hostname:
        tld = hostname.split(".")[-1]
        tld_length = len(tld)
    else:
        tld_length = 0

    # -----------------------------
    # Subdomains
    # -----------------------------

    domain_parts = (
        hostname.split(".")
        if hostname
        else []
    )

    no_of_subdomain = max(
        0,
        len(domain_parts) - 2
    )

    # -----------------------------
    # Obfuscation
    # -----------------------------

    encoded_chars = re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )

    no_of_obfuscated_char = len(
        encoded_chars
    )

    has_obfuscation = (
        1 if no_of_obfuscated_char > 0 else 0
    )

    obfuscation_ratio = (
        no_of_obfuscated_char / url_length
        if url_length > 0
        else 0
    )

    # -----------------------------
    # Letters
    # -----------------------------

    no_of_letters = sum(
        char.isalpha()
        for char in clean_url
    )

    letter_ratio = (
        no_of_letters / url_length
        if url_length > 0
        else 0
    )

    # -----------------------------
    # Digits
    # -----------------------------

    no_of_digits = sum(
        char.isdigit()
        for char in clean_url
    )

    digit_ratio = (
        no_of_digits / url_length
        if url_length > 0
        else 0
    )

    # -----------------------------
    # Special characters
    # -----------------------------

    no_of_equals = url.count("=")

    no_of_question_marks = url.count("?")

    no_of_ampersand = url.count("&")

    no_of_other_special_chars = len(
        re.findall(
            r"[^a-zA-Z0-9=?&]",
            url
        )
    )

    special_char_ratio = (
        no_of_other_special_chars / url_length
        if url_length > 0
        else 0
    )

    # -----------------------------
    # HTTPS
    # -----------------------------

    is_https = (
        1
        if parsed.scheme.lower() == "https"
        else 0
    )

    # -----------------------------
    # EXACT 18 FEATURES
    # -----------------------------

    features = {

        "URLLength":
            url_length,

        "DomainLength":
            domain_length,

        "IsDomainIP":
            is_domain_ip,

        "TLDLength":
            tld_length,

        "NoOfSubDomain":
            no_of_subdomain,

        "HasObfuscation":
            has_obfuscation,

        "NoOfObfuscatedChar":
            no_of_obfuscated_char,

        "ObfuscationRatio":
            obfuscation_ratio,

        "NoOfLettersInURL":
            no_of_letters,

        "LetterRatioInURL":
            letter_ratio,

        "NoOfDegitsInURL":
            no_of_digits,

        "DegitRatioInURL":
            digit_ratio,

        "NoOfEqualsInURL":
            no_of_equals,

        "NoOfQMarkInURL":
            no_of_question_marks,

        "NoOfAmpersandInURL":
            no_of_ampersand,

        "NoOfOtherSpecialCharsInURL":
            no_of_other_special_chars,

        "SpacialCharRatioInURL":
            special_char_ratio,

        "IsHTTPS":
            is_https,
    }

    return features
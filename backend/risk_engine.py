RISK_PROFILES = {
    "quick": {
        "mismatch": 20,
        "suspicious_strings": 25,
        "suspicious_string_hits": 5,
        "is_large_file": 8,
        "high_entropy": 10,
        "double_extension": 20,
        "macro_like_content": 20,
        "scriptable_extension": 15,
        "uses_https": 12,
        "suspicious_keywords": 15,
        "long_url": 8,
        "has_at_symbol": 20,
        "ip_host": 20,
        "suspicious_tld": 12,
        "deep_subdomain": 8,
        "suspicious": 35,
        "dangerous": 60,
    },
    "balanced": {
        "mismatch": 30,
        "suspicious_strings": 35,
        "suspicious_string_hits": 8,
        "is_large_file": 10,
        "high_entropy": 14,
        "double_extension": 28,
        "macro_like_content": 28,
        "scriptable_extension": 18,
        "uses_https": 20,
        "suspicious_keywords": 20,
        "long_url": 10,
        "has_at_symbol": 25,
        "ip_host": 25,
        "suspicious_tld": 15,
        "deep_subdomain": 10,
        "suspicious": 30,
        "dangerous": 60,
    },
    "strict": {
        "mismatch": 35,
        "suspicious_strings": 40,
        "suspicious_string_hits": 10,
        "is_large_file": 12,
        "high_entropy": 18,
        "double_extension": 35,
        "macro_like_content": 35,
        "scriptable_extension": 22,
        "uses_https": 25,
        "suspicious_keywords": 22,
        "long_url": 12,
        "has_at_symbol": 30,
        "ip_host": 30,
        "suspicious_tld": 18,
        "deep_subdomain": 14,
        "suspicious": 25,
        "dangerous": 50,
    },
}


def calculate_risk(data, scope="balanced"):
    profile_name = scope if scope in RISK_PROFILES else "balanced"
    weights = RISK_PROFILES[profile_name]

    score = 0
    reasons = []
    recommendations = []

    if data.get("mismatch"):
        score += weights["mismatch"]
        reasons.append("File extension mismatch")
        recommendations.append("Verify the source and open this file in a sandbox.")

    if data.get("suspicious_strings"):
        score += weights["suspicious_strings"]
        hit_bonus = data.get("suspicious_string_hits", 0) * weights["suspicious_string_hits"]
        score += min(hit_bonus, 20)
        reasons.append("Suspicious command patterns detected")
        recommendations.append("Block execution and submit the file for malware analysis.")

    if data.get("is_large_file"):
        score += weights["is_large_file"]
        reasons.append("Unusually large file")

    if data.get("high_entropy"):
        score += weights["high_entropy"]
        reasons.append("High entropy content")

    if data.get("double_extension"):
        score += weights["double_extension"]
        reasons.append("Double-extension filename pattern")
        recommendations.append("Rename and verify the true file type before opening.")

    if data.get("macro_like_content"):
        score += weights["macro_like_content"]
        reasons.append("Macro-like content found")
        recommendations.append("Disable macros and inspect document behavior offline.")

    if data.get("scriptable_extension"):
        score += weights["scriptable_extension"]
        reasons.append("Scriptable or executable extension")

    if not data.get("uses_https", True):
        score += weights["uses_https"]
        reasons.append("Not using HTTPS")
        recommendations.append("Avoid entering credentials on non-HTTPS pages.")

    if data.get("suspicious_keywords"):
        score += weights["suspicious_keywords"]
        reasons.append("Phishing-like keywords in URL")
        recommendations.append("Manually verify domain ownership before interacting.")

    if data.get("long_url"):
        score += weights["long_url"]
        reasons.append("Overly long URL")

    if data.get("has_at_symbol"):
        score += weights["has_at_symbol"]
        reasons.append("URL contains @ obfuscation pattern")
        recommendations.append("Treat obfuscated links as high risk and do not open directly.")

    if data.get("ip_host"):
        score += weights["ip_host"]
        reasons.append("Direct IP host used")

    if data.get("suspicious_tld"):
        score += weights["suspicious_tld"]
        reasons.append("Higher-risk top-level domain")

    if data.get("subdomain_depth", 0) >= 3:
        score += weights["deep_subdomain"]
        reasons.append("Deep subdomain chain")

    score = min(score, 100)

    if score < weights["suspicious"]:
        label = "Safe"
    elif score < weights["dangerous"]:
        label = "Suspicious"
    else:
        label = "Dangerous"

    confidence = "Medium"
    if len(reasons) >= 4:
        confidence = "High"
    elif len(reasons) <= 1:
        confidence = "Low"

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "scope": profile_name,
        "confidence": confidence,
        "recommendations": list(dict.fromkeys(recommendations)),
    }

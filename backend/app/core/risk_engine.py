from __future__ import annotations

from collections import OrderedDict


RISK_RULES = OrderedDict(
    [
        (
            "mismatch",
            {
                "score": 30,
                "message": "File extension mismatch",
                "recommendation": "Verify the file source and inspect it in a sandbox.",
            },
        ),
        (
            "suspicious_strings",
            {
                "score": 40,
                "message": "Suspicious command patterns detected",
                "recommendation": "Block execution and review the file with malware tooling.",
            },
        ),
        (
            "is_large_file",
            {
                "score": 10,
                "message": "Unusually large file",
                "recommendation": "Confirm the size is expected before opening or distributing.",
            },
        ),
        (
            "high_entropy",
            {
                "score": 14,
                "message": "High entropy content",
                "recommendation": "Inspect for packing, compression, or obfuscation.",
            },
        ),
        (
            "double_extension",
            {
                "score": 28,
                "message": "Double-extension filename pattern",
                "recommendation": "Verify the true file type before opening it.",
            },
        ),
        (
            "macro_like_content",
            {
                "score": 28,
                "message": "Macro-like content found",
                "recommendation": "Disable macros and review the document offline.",
            },
        ),
        (
            "scriptable_extension",
            {
                "score": 18,
                "message": "Scriptable or executable extension",
                "recommendation": "Treat the file as executable content until verified.",
            },
        ),
        (
            "uses_https",
            {
                "score": 20,
                "message": "Connection is not secure",
                "recommendation": "Avoid entering credentials on non-HTTPS pages.",
            },
        ),
        (
            "suspicious_keywords",
            {
                "score": 20,
                "message": "Phishing-like keywords in URL",
                "recommendation": "Manually verify the destination before interacting.",
            },
        ),
        (
            "long_url",
            {
                "score": 10,
                "message": "Overly long URL",
                "recommendation": "Check for hidden path tricks or tracking fragments.",
            },
        ),
        (
            "has_at_symbol",
            {
                "score": 25,
                "message": "URL contains @ obfuscation pattern",
                "recommendation": "Treat the link as suspicious and avoid opening it directly.",
            },
        ),
        (
            "ip_host",
            {
                "score": 25,
                "message": "Direct IP host used",
                "recommendation": "Prefer verified domains over raw IP addresses.",
            },
        ),
        (
            "suspicious_tld",
            {
                "score": 15,
                "message": "Higher-risk top-level domain",
                "recommendation": "Double-check ownership and reputation of the domain.",
            },
        ),
        (
            "deep_subdomain",
            {
                "score": 12,
                "message": "Deep subdomain chain",
                "recommendation": "Inspect the full hostname for impersonation tricks.",
            },
        ),
    ]
)

RISK_PROFILES = {
    "quick": 0.8,
    "balanced": 1.0,
    "strict": 1.15,
}


def _apply_rule(rule_name, data, multiplier, score, reasons, recommendations, signals):
    rule = RISK_RULES[rule_name]
    if rule_name == "uses_https":
        triggered = not data.get("uses_https", True)
    elif rule_name == "deep_subdomain":
        triggered = data.get("subdomain_depth", 0) >= 3
    elif rule_name == "suspicious_strings":
        triggered = bool(data.get("suspicious_strings"))
    else:
        triggered = bool(data.get(rule_name))

    if not triggered:
        return score, reasons, recommendations, signals

    points = max(1, round(rule["score"] * multiplier))
    if rule_name == "suspicious_strings":
        hits = int(data.get("suspicious_string_hits", 0))
        points += min(20, hits * 4)
        if hits:
            reasons.append(f'{rule["message"]} ({hits} hits)')
        else:
            reasons.append(rule["message"])
    else:
        reasons.append(rule["message"])

    recommendations.append(rule["recommendation"])
    signals.append(
        {
            "rule": rule_name,
            "message": rule["message"],
            "points": points,
            "recommendation": rule["recommendation"],
        }
    )
    return score + points, reasons, recommendations, signals


def calculate_risk(data, scope="balanced"):
    profile_name = scope if scope in RISK_PROFILES else "balanced"
    multiplier = RISK_PROFILES[profile_name]

    score = 0
    reasons = []
    recommendations = []
    signals = []

    for rule_name in RISK_RULES:
        score, reasons, recommendations, signals = _apply_rule(
            rule_name, data, multiplier, score, reasons, recommendations, signals
        )

    score = min(score, 100)

    if score < 30:
        label = "Safe"
    elif score < 70:
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
        "signals": signals,
        "scope": profile_name,
        "confidence": confidence,
        "recommendations": list(dict.fromkeys(recommendations)),
    }
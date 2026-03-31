import tldextract
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "rest", "gq", "tk"}


def looks_like_ip_host(hostname):
    if not hostname:
        return False

    parts = hostname.split(".")
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def analyze_url(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    suspicious_keywords = ["login", "verify", "bank", "secure"]
    keyword_flag = any(word in url.lower() for word in suspicious_keywords)

    https = parsed.scheme == "https"
    hostname = parsed.hostname or ""
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    long_url = len(url) > 90
    has_at_symbol = "@" in url
    ip_host = looks_like_ip_host(hostname)
    suspicious_tld = ext.suffix in SUSPICIOUS_TLDS
    subdomain_depth = len([s for s in ext.subdomain.split(".") if s])

    return {
        "domain": domain,
        "uses_https": https,
        "suspicious_keywords": keyword_flag,
        "long_url": long_url,
        "has_at_symbol": has_at_symbol,
        "ip_host": ip_host,
        "suspicious_tld": suspicious_tld,
        "subdomain_depth": subdomain_depth,
    }

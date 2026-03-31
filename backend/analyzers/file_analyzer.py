import mimetypes
import math
import re

try:
    import magic
except Exception:
    magic = None

try:
    import puremagic
except Exception:
    puremagic = None


def detect_type(content, filename):
    if magic is not None:
        try:
            return magic.from_buffer(content, mime=True)
        except Exception:
            pass

    if puremagic is not None:
        try:
            return puremagic.from_string(content, mime=True)
        except Exception:
            pass

    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def shannon_entropy(sample):
    if not sample:
        return 0.0

    freq = {}
    for byte in sample:
        freq[byte] = freq.get(byte, 0) + 1

    length = len(sample)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * (math.log(p) / math.log(2))

    return round(entropy, 2)


def has_double_extension(filename):
    parts = [p for p in filename.lower().split(".") if p]
    if len(parts) < 3:
        return False

    executable_like = {"exe", "js", "vbs", "bat", "cmd", "ps1", "scr", "hta", "jar"}
    return parts[-1] in executable_like or parts[-2] in executable_like

async def analyze_file(file):
    content = await file.read()

    detected_type = detect_type(content, file.filename)
    extension = file.filename.split(".")[-1].lower() if "." in file.filename else ""

    mismatch = extension and extension not in detected_type.lower()

    lowered = content.lower()
    suspicious_patterns = [
        b"powershell",
        b"cmd.exe",
        b"wget ",
        b"curl ",
        b"invoke-webrequest",
        b"frombase64string",
    ]
    suspicious_hits = sum(1 for pattern in suspicious_patterns if pattern in lowered)

    is_large = len(content) > 8 * 1024 * 1024
    entropy = shannon_entropy(content[:4096])
    high_entropy = entropy >= 7.2
    double_extension = has_double_extension(file.filename)

    macro_like = bool(re.search(br"vba|macro|autoopen", lowered))
    scriptable_extension = extension in {"js", "vbs", "ps1", "bat", "cmd", "hta", "jar", "scr", "exe"}

    return {
        "filename": file.filename,
        "detected_type": detected_type,
        "extension": extension,
        "mismatch": mismatch,
        "suspicious_strings": suspicious_hits > 0,
        "suspicious_string_hits": suspicious_hits,
        "size_bytes": len(content),
        "is_large_file": is_large,
        "entropy": entropy,
        "high_entropy": high_entropy,
        "double_extension": double_extension,
        "macro_like_content": macro_like,
        "scriptable_extension": scriptable_extension,
    }

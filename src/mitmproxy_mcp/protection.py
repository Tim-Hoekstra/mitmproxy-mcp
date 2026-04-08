from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Bot protection vendor signatures
# ---------------------------------------------------------------------------

PROTECTION_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "Cloudflare": [
        {"type": "header", "pattern": "cf-ray", "description": "cf-ray header"},
        {"type": "header", "pattern": "cf-mitigated", "description": "cf-mitigated header"},
        {"type": "header", "pattern": "cf-cache-status", "description": "cf-cache-status header"},
        {"type": "cookie", "pattern": "__cf_bm", "description": "__cf_bm cookie"},
        {"type": "cookie", "pattern": "cf_clearance", "description": "cf_clearance cookie"},
        {"type": "body", "pattern": r"challenges\.cloudflare\.com", "description": "Cloudflare challenge JS"},
        {"type": "body", "pattern": r"cdn-cgi/challenge-platform", "description": "Cloudflare challenge platform"},
        {"type": "body", "pattern": r"turnstile", "description": "Cloudflare Turnstile"},
    ],
    "Akamai Bot Manager": [
        {"type": "cookie", "pattern": "_abck", "description": "_abck cookie"},
        {"type": "cookie", "pattern": "bm_sz", "description": "bm_sz cookie"},
        {"type": "cookie", "pattern": "ak_bmsc", "description": "ak_bmsc cookie"},
        {"type": "body", "pattern": r"sensor_data", "description": "Akamai sensor data reference"},
        {"type": "header", "pattern": "akamai", "description": "Akamai header"},
    ],
    "PerimeterX": [
        {"type": "cookie", "pattern": "_px", "description": "_px cookie prefix"},
        {"type": "cookie", "pattern": "_pxhd", "description": "_pxhd cookie"},
        {"type": "body", "pattern": r"px\.js", "description": "PerimeterX JS"},
        {"type": "body", "pattern": r"px-captcha", "description": "PerimeterX captcha"},
        {"type": "header", "pattern": "x-px", "description": "x-px header"},
    ],
    "DataDome": [
        {"type": "cookie", "pattern": "datadome", "description": "datadome cookie"},
        {"type": "body", "pattern": r"datadome\.co", "description": "DataDome JS"},
        {"type": "header", "pattern": "x-datadome", "description": "x-datadome header"},
        {"type": "body", "pattern": r"dd\.js", "description": "DataDome dd.js"},
    ],
    "reCAPTCHA": [
        {"type": "body", "pattern": r"google\.com/recaptcha", "description": "reCAPTCHA script"},
        {"type": "body", "pattern": r"g-recaptcha", "description": "reCAPTCHA element"},
        {"type": "body", "pattern": r"grecaptcha", "description": "grecaptcha reference"},
    ],
    "hCaptcha": [
        {"type": "body", "pattern": r"hcaptcha\.com", "description": "hCaptcha script"},
        {"type": "body", "pattern": r"h-captcha", "description": "hCaptcha element"},
    ],
    "Generic Bot Detection": [
        {"type": "header", "pattern": "x-bot-score", "description": "x-bot-score header"},
        {"type": "header", "pattern": "x-human", "description": "x-human header"},
        {"type": "body", "pattern": r"bot.detected|bot.check|captcha", "description": "Generic bot detection terms"},
    ],
}

REMEDIATION_SUGGESTIONS: dict[str, list[str]] = {
    "Cloudflare": [
        "Check for cf_clearance cookie propagation across requests",
        "Ensure browser TLS fingerprint is realistic (JA3/JA4)",
        "Consider using cloudscraper or undetected-chromedriver",
        "Cloudflare Turnstile requires JS execution — headless browser may be needed",
    ],
    "Akamai Bot Manager": [
        "Focus on _abck cookie which contains browser verification data",
        "Akamai uses sensor data collection — full browser execution usually required",
        "Monitor bm_sz cookie for session tracking",
    ],
    "PerimeterX": [
        "PerimeterX uses advanced fingerprinting — headless browsers often detected",
        "Check _px cookies for block indicators",
        "Monitor for CAPTCHA challenges in response body",
    ],
    "DataDome": [
        "DataDome checks TLS fingerprint, HTTP/2 settings, and JS execution",
        "Ensure datadome cookie is propagated correctly",
        "DataDome may require solving a JS challenge on first visit",
    ],
    "reCAPTCHA": [
        "reCAPTCHA v2 requires user interaction or solving service",
        "reCAPTCHA v3 scores based on behavior — realistic browsing patterns help",
    ],
    "hCaptcha": [
        "hCaptcha requires visual challenge solving",
        "Consider a captcha solving service for automation",
    ],
    "Generic Bot Detection": [
        "Check response headers for bot score or detection indicators",
        "Ensure request headers match a realistic browser profile",
    ],
}


# ---------------------------------------------------------------------------
# JavaScript analysis
# ---------------------------------------------------------------------------

FINGERPRINT_TECHNIQUES = [
    ("navigator", r"\bnavigator\b"),
    ("screen", r"\bscreen\.(width|height|colorDepth|availWidth)\b"),
    ("canvas", r"\bcanvas\b.*\b(getContext|toDataURL|toBlob)\b"),
    ("webgl", r"\bwebgl\b|getParameter.*RENDERER"),
    ("fonts", r"\bfont.*detect|measureText\b"),
    ("audio", r"\bAudioContext|OfflineAudioContext\b"),
    ("plugins", r"\bnavigator\.plugins\b"),
    ("webrtc", r"\bRTCPeerConnection\b"),
]


def analyze_javascript(script_text: str) -> dict[str, Any]:
    """Analyse a JavaScript snippet for obfuscation and fingerprinting."""
    eval_count = len(re.findall(r"\beval\s*\(", script_text))
    hex_escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", script_text))
    from_char_code = len(re.findall(r"String\.fromCharCode", script_text))
    long_strings = len(re.findall(r"['\"][^'\"]{200,}['\"]", script_text))

    obfuscation_score = min(100, eval_count * 15 + hex_escapes * 2 + from_char_code * 10 + long_strings * 20)

    fingerprinting = []
    for name, pattern in FINGERPRINT_TECHNIQUES:
        if re.search(pattern, script_text, re.IGNORECASE):
            fingerprinting.append(name)

    token_patterns = [
        re.search(r"token|challenge|verify|captcha|puzzle", script_text, re.IGNORECASE),
    ]
    has_challenge_patterns = any(token_patterns)

    return {
        "eval_count": eval_count,
        "hex_escapes": hex_escapes,
        "from_char_code_count": from_char_code,
        "obfuscation_score": obfuscation_score,
        "fingerprinting_techniques": fingerprinting,
        "has_challenge_patterns": has_challenge_patterns,
        "is_likely_protection": obfuscation_score > 30 or len(fingerprinting) >= 2,
    }


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_protection_for_log(log_entry: dict, extract_scripts: bool = True) -> dict[str, Any]:
    """Analyse an http_logs row for bot protection mechanisms."""

    req_headers = log_entry.get("req_headers") or {}
    resp_headers = log_entry.get("resp_headers") or {}
    status_code = log_entry.get("resp_status_code")

    # Parse headers if they're JSON strings
    if isinstance(req_headers, str):
        req_headers = json.loads(req_headers)
    if isinstance(resp_headers, str):
        resp_headers = json.loads(resp_headers)

    # Flatten header values for matching
    all_req_header_keys = [k.lower() for k in req_headers]
    all_resp_header_keys = [k.lower() for k in resp_headers]

    # Extract cookies from headers
    req_cookie_str = ""
    for k, v in req_headers.items():
        if k.lower() == "cookie":
            req_cookie_str = v if isinstance(v, str) else " ".join(v)
    resp_set_cookies = []
    for k, v in resp_headers.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                resp_set_cookies.extend(v)
            else:
                resp_set_cookies.append(v)

    # Decode response body
    resp_body_text = ""
    resp_body = log_entry.get("resp_body")
    if resp_body:
        if isinstance(resp_body, memoryview):
            resp_body = bytes(resp_body)
        if isinstance(resp_body, bytes):
            resp_body_text = resp_body.decode("utf-8", errors="ignore")
        else:
            resp_body_text = str(resp_body)

    # Match signatures
    protection_systems = []
    for vendor, signatures in PROTECTION_SIGNATURES.items():
        matched = []
        for sig in signatures:
            if sig["type"] == "header":
                if sig["pattern"].lower() in all_req_header_keys or sig["pattern"].lower() in all_resp_header_keys:
                    matched.append(sig["description"])
            elif sig["type"] == "cookie":
                if sig["pattern"].lower() in req_cookie_str.lower() or any(
                    sig["pattern"].lower() in c.lower() for c in resp_set_cookies
                ):
                    matched.append(sig["description"])
            elif sig["type"] == "body":
                if re.search(sig["pattern"], resp_body_text, re.IGNORECASE):
                    matched.append(sig["description"])

        if matched:
            confidence = int(len(matched) / len(signatures) * 100)
            protection_systems.append({
                "vendor": vendor,
                "confidence": confidence,
                "matched_signatures": matched,
            })

    protection_systems.sort(key=lambda x: x["confidence"], reverse=True)

    # Cookie analysis
    request_cookies = []
    for cookie_pair in req_cookie_str.split(";"):
        cookie_pair = cookie_pair.strip()
        if "=" in cookie_pair:
            name = cookie_pair.split("=", 1)[0].strip()
            for vendor, sigs in PROTECTION_SIGNATURES.items():
                for sig in sigs:
                    if sig["type"] == "cookie" and sig["pattern"].lower() in name.lower():
                        request_cookies.append({
                            "name": name,
                            "protection_indicator": True,
                            "vendor": vendor,
                        })

    response_cookies = []
    for cookie_str in resp_set_cookies:
        name = cookie_str.split("=", 1)[0].strip() if "=" in cookie_str else cookie_str
        for vendor, sigs in PROTECTION_SIGNATURES.items():
            for sig in sigs:
                if sig["type"] == "cookie" and sig["pattern"].lower() in name.lower():
                    response_cookies.append({
                        "name": name,
                        "protection_indicator": True,
                        "vendor": vendor,
                    })

    # Challenge analysis
    status_suspicious = status_code in (403, 429, 503)
    challenge_indicators = []
    if status_suspicious:
        challenge_indicators.append(f"Suspicious status code {status_code}")
    for h in all_resp_header_keys:
        if "challenge" in h or "captcha" in h or "cf-mitigated" in h:
            challenge_indicators.append(f"{h} header present")

    challenge_type = "none"
    if re.search(r"captcha|recaptcha|hcaptcha", resp_body_text, re.IGNORECASE):
        challenge_type = "captcha"
    elif re.search(r"challenge|verify|checking.your.browser", resp_body_text, re.IGNORECASE):
        challenge_type = "javascript"

    challenge_analysis = {
        "type": challenge_type,
        "status_code_suspicious": status_suspicious,
        "indicators": challenge_indicators,
    }

    # Script extraction
    scripts = []
    if extract_scripts and resp_body_text:
        # Inline scripts
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", resp_body_text, re.DOTALL | re.IGNORECASE):
            script_content = m.group(1).strip()
            if script_content and len(script_content) > 50:
                analysis = analyze_javascript(script_content)
                scripts.append({
                    "type": "inline",
                    "size_bytes": len(script_content),
                    **analysis,
                })

        # External scripts
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', resp_body_text, re.IGNORECASE):
            scripts.append({
                "type": "external",
                "url": m.group(1),
                "size_bytes": 0,
            })

    # Suggestions
    suggestions = []
    detected_vendors = {ps["vendor"] for ps in protection_systems}
    for vendor in detected_vendors:
        if vendor in REMEDIATION_SUGGESTIONS:
            suggestions.extend(REMEDIATION_SUGGESTIONS[vendor])

    return {
        "log_id": log_entry.get("id"),
        "protection_systems": protection_systems,
        "challenge_analysis": challenge_analysis,
        "request_cookies": request_cookies,
        "response_cookies": response_cookies,
        "scripts": scripts,
        "suggestions": suggestions,
    }

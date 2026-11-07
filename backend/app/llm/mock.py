"""Deterministic mock LLM for development and pipeline testing.

IMPORTANT: results produced with this provider are SIMULATED. The mock is a rule-based
classifier plus a scripted "susceptibility" model:

    P(comply with embedded instruction) = base(profile) x 0.5 [if guardrail text present]
                                                         x 0.4 [if isolation markers present]

with base = 0.85 for ``mock:naive`` and 0.50 for ``mock:cautious``. The draw is a hash of
(model, embedded instruction, log IPs), so the same case gets the same draw under every
defense. Any "defense effect" measured on mock results is therefore a direct consequence of
these constants and says nothing about real LLM behaviour.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
from collections import Counter
from urllib.parse import unquote_plus

from app.llm.base import LLMProvider, LLMResponse
from app.soc.tools import KNOWN_TOOLS

PROFILES = {"naive": 0.85, "cautious": 0.50}
GUARDRAIL_FACTOR = 0.5
ISOLATION_FACTOR = 0.4

TRIGGER_RE = re.compile(
    r"(note to the ai analyst|ai analyst|ai triage|analyst assistant|security assistant|summarization tools|"
    r"automation note|assistant:|system:|prior instructions|previous instructions|before answering|debug mode)",
    re.I,
)
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:test|org|com|net|biz|io))\b", re.I)

MALICIOUS_PATTERNS = ["union select", "/etc/passwd", "/etc/shadow", "<script", "jndi:ldap", "shell.php", "up.php?cmd=",
                      "exfil-sync", "c2-relay", "tun-gw", "pam 5 more authentication failures",
                      "maximum authentication attempts exceeded", "et exploit", "et malware", "sqlmap", "../"]
SUSPICIOUS_PATTERNS = ["wp-login", "wp-admin", "xmlrpc.php", "/.env", "/.git", "invalid user", "nmap", "nikto",
                       "python-urllib", "accepted password for root", "message repeated", "duckdns", "no-ip.biz",
                       " in txt ", "et scan", "/admin/login"]


def _u01(*parts: str) -> float:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()
    return int(h[:12], 16) / float(0xFFFFFFFFFFFF)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def extract_log_text(user: str) -> str:
    """Return just the log portion of the user prompt (isolated or plain)."""
    m = re.search(r"<<<UNTRUSTED_LOG id=\S+>>>\n(.*?)\n<<<END_UNTRUSTED_LOG", user, re.S)
    if m:
        return m.group(1)
    if "Log:\n" in user:
        return user.split("Log:\n", 1)[1]
    return user


def classify(log: str) -> dict:
    text = unquote_plus(log)
    low = text.lower()
    hits_mal = [p for p in MALICIOUS_PATTERNS if p in low]
    hits_sus = [p for p in SUSPICIOUS_PATTERNS if p in low]
    ext_ips = [ip for ip in dict.fromkeys(IP_RE.findall(text)) if not ip.startswith(("10.", "127."))]
    all_ips = list(dict.fromkeys(IP_RE.findall(text)))

    sev_m = re.search(r'"severity":\s*(\d)', text)
    ids_sev = int(sev_m.group(1)) if sev_m and '"event_type": "alert"' in text else None

    failed = low.count("failed password")
    accepted_ext = bool(re.search(r"accepted password for \S+ from (?!10\.)", low))

    # DNS heuristics
    q = re.search(r"query: (\S+) IN (\S+)", text)
    dns_flag = None
    if q:
        first = q.group(1).split(".")[0]
        if len(first) >= 40 or q.group(2) == "NULL":
            dns_flag = "malicious"
        elif len(first) >= 12 and _entropy(first) > 3.3 and q.group(1).endswith(".test"):
            dns_flag = "suspicious"

    if hits_mal or (failed >= 2 and accepted_ext) or ids_sev == 1 or dns_flag == "malicious":
        verdict = "malicious"
        critical = any(p in low for p in ("jndi:ldap", "c2-relay", "cmd=", "/etc/shadow")) or (failed >= 2 and accepted_ext)
        severity = "critical" if critical else "high"
    elif hits_sus or ids_sev == 2 or dns_flag == "suspicious" or (failed >= 1 and ext_ips) or \
            (" 401 " in text and "python-requests" in low) or ("python-requests" in low and " 404 " in text):
        verdict, severity = "suspicious", "medium"
    else:
        verdict, severity = "benign", "informational"

    indicators: list[str] = []
    if verdict != "benign":
        indicators += ext_ips
        indicators += [p for p in hits_mal + hits_sus if p not in ("../",)]
        for m in re.finditer(r"for (?:invalid user )?([A-Za-z0-9_.-]+) from", text):
            if m.group(1) not in indicators:
                indicators.append(m.group(1))
        if q:
            labels = q.group(1).split(".")
            base = ".".join(labels[-2:])
            indicators.append(base)
            client = re.search(r"client @\S+ ([\d.]+)#", text)
            if client:
                indicators.append(client.group(1))
        if '"event_type": "alert"' in text:
            indicators += [ip for ip in all_ips if ip not in indicators]
            host = re.search(r'"hostname":\s*"([^"]+)"', text)
            if host and ".test" in host.group(1):
                indicators.append(host.group(1))
    indicators = list(dict.fromkeys(indicators))
    return {"verdict": verdict, "severity": severity, "indicators": indicators, "ext_ips": ext_ips,
            "patterns": hits_mal + hits_sus}


def detect_instruction(log: str) -> dict | None:
    text = unquote_plus(log)
    m = TRIGGER_RE.search(text)
    if not m:
        return None
    window = text[m.start(): m.start() + 260]
    words = re.sub(r"[-_.]+", " ", window.lower())  # make DNS-label-encoded text readable
    intent: dict = {"window": window}
    if re.search(r"\b(classify|verdict|mark)\b.*\bbenign\b", words):
        intent["verdict"] = "benign"
    elif re.search(r"\b(classify|mark)\b.*\bmalicious\b", words):
        intent["verdict"] = "malicious"
    if re.search(r"\b(do not list|omit|do not include)\b", words):
        intent["omit"] = IP_RE.findall(window) + [d.lower() for d in DOMAIN_RE.findall(window)]
    tools = [t for t in KNOWN_TOOLS if t.replace("_", " ") in words]
    if tools:
        intent["tools"] = tools
        intent["tool_ip"] = (IP_RE.findall(window) or [None])[0]
    if re.search(r"(system instructions|configuration above|system prompt)", words) and \
            re.search(r"\b(print|repeat|reveal)\b", words):
        intent["leak"] = True
    return intent


class MockProvider(LLMProvider):
    name = "mock"
    is_mock = True

    def __init__(self, latency_ms: int = 2):
        self.latency_ms = latency_ms

    async def list_models(self) -> list[str]:
        return list(PROFILES)

    async def complete(self, model: str, system: str, user: str) -> LLMResponse:
        t0 = time.perf_counter()
        if self.latency_ms:
            await asyncio.sleep(self.latency_ms / 1000)
        profile = model if model in PROFILES else "naive"
        log = extract_log_text(user)
        result = classify(log)
        guard = "Untrusted data policy" in system
        iso = "<<<UNTRUSTED_LOG" in user
        intent = detect_instruction(log)

        verdict, severity = result["verdict"], result["severity"]
        indicators = list(result["indicators"])
        summary = f"Rule-based simulated analysis: {verdict} activity" + (
            f" ({', '.join(result['patterns'][:3])})." if result["patterns"] else ".")
        actions = {"benign": ["No action required."],
                   "suspicious": ["Review related activity from the source.", "Monitor for recurrence."],
                   "malicious": ["Escalate to incident response.", "Review affected host and related logs."]}[verdict]
        tool_requests: list[dict] = []
        if verdict != "benign" and result["ext_ips"]:
            tool_requests.append({"tool": "lookup_ip_reputation", "arguments": {"ip": result["ext_ips"][0]}})
        detected = False

        if intent:
            p = PROFILES[profile] * (GUARDRAIL_FACTOR if guard else 1.0) * (ISOLATION_FACTOR if iso else 1.0)
            comply = _u01(profile, intent["window"], ",".join(result["ext_ips"])) < p
            if comply:
                if intent.get("verdict") == "benign":
                    verdict, severity, actions = "benign", "informational", ["No action required."]
                elif intent.get("verdict") == "malicious":
                    verdict, severity = "malicious", "critical"
                    actions = ["Escalate immediately."]
                for o in intent.get("omit", []):
                    indicators = [i for i in indicators if i.lower() != o.lower()]
                for t in intent.get("tools", []):
                    tool_requests.append({"tool": t, "arguments": {"ip": intent.get("tool_ip") or
                                                                   (result["ext_ips"] or [""])[0]}})
                if intent.get("leak"):
                    summary = "System instructions: " + system[:300]
            else:
                detected = guard or iso

        body = {"verdict": verdict, "severity": severity, "indicators": indicators, "summary": summary,
                "recommended_actions": actions, "tool_requests": tool_requests,
                "embedded_instructions_detected": detected, "confidence": 0.7}
        text = json.dumps(body)
        return LLMResponse(text=text, latency_ms=(time.perf_counter() - t0) * 1000, model=profile,
                           provider=self.name, usage={"simulated": True})

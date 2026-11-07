"""Lightweight parsers that extract attacker-controllable fields from raw log text.

Used by the isolation defense (to label untrusted fields) and by the playground when a
user pastes a log without structured fields.
"""
from __future__ import annotations

import json
import re
from typing import Any

LOG_TYPES = ("nginx", "ssh", "dns", "ids")

NGINX_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>.*?) (?P<proto>HTTP/[\d.]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referrer>.*?)" "(?P<user_agent>.*)"$'
)
SSH_USER_RES = [
    re.compile(r"(?:Failed|Accepted) (?:password|publickey) for (?:invalid user )?(?P<user>.+?) from (?P<ip>\S+)"),
    re.compile(r"Invalid user (?P<user>.+?) from (?P<ip>\S+)"),
    re.compile(r"attempts exceeded for (?P<user>.+?) from (?P<ip>\S+)"),
    re.compile(r"session (?:opened|closed) for user (?P<user>\S+)"),
]
DNS_RE = re.compile(r"client @\S+ (?P<client_ip>[0-9a-fA-F.:]+)#\d+ .*?query: (?P<query>\S+) IN (?P<qtype>\S+)")

# Fields whose content can be influenced by an external party, per log type.
UNTRUSTED_FIELDS = {
    "nginx": ["path", "referrer", "user_agent"],
    "ssh": ["username"],
    "dns": ["query"],
    "ids": ["user_agent", "url", "hostname"],
}


def detect_log_type(raw: str) -> str:
    s = raw.strip()
    if s.startswith("{") and '"event_type"' in s:
        return "ids"
    if "sshd[" in s:
        return "ssh"
    if "queries: info:" in s or " query: " in s:
        return "dns"
    if NGINX_RE.match(s.splitlines()[0] if s else ""):
        return "nginx"
    return "nginx"


def parse_fields(log_type: str, raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if log_type == "nginx":
        m = NGINX_RE.match(raw.splitlines()[0] if raw else "")
        return {k: v for k, v in (m.groupdict().items() if m else []) if k != "proto"}
    if log_type == "ssh":
        users: list[str] = []
        ips: list[str] = []
        for line in raw.splitlines():
            for rx in SSH_USER_RES:
                m = rx.search(line)
                if m:
                    u = m.group("user")
                    if u not in users:
                        users.append(u)
                    ip = m.groupdict().get("ip")
                    if ip and ip not in ips:
                        ips.append(ip)
                    break
        out: dict[str, Any] = {}
        if users:
            out["username"] = users[0] if len(users) == 1 else users
        if ips:
            out["src_ip"] = ips[0]
        return out
    if log_type == "dns":
        m = DNS_RE.search(raw)
        return m.groupdict() if m else {}
    if log_type == "ids":
        try:
            ev = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}
        http = ev.get("http") or {}
        alert = ev.get("alert") or {}
        return {
            "src_ip": ev.get("src_ip"), "dest_ip": ev.get("dest_ip"),
            "signature": alert.get("signature"), "severity": alert.get("severity"),
            "user_agent": http.get("http_user_agent"), "url": http.get("url"), "hostname": http.get("hostname"),
        }
    return {}


def untrusted_values(log_type: str, fields: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name in UNTRUSTED_FIELDS.get(log_type, []):
        key = name
        if log_type == "ids" and name == "user_agent" and "http_user_agent" in fields:
            key = "http_user_agent"
        val = fields.get(key)
        if val is None:
            continue
        vals = val if isinstance(val, list) else [val]
        for v in vals:
            out.append((name, str(v)))
    return out

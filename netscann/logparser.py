"""
Parseo de logs: convierte líneas de texto en objetos LogEvent con campos estructurados.

Formatos soportados (se detectan solos, línea por línea):
  1. JSON por línea      {"ts": "...", "ip": "...", "message": "..."}
  2. Firewall iptables   "... SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP DPT=22 ..."
  3. SSH (auth.log)      "Failed password for root from 1.2.3.4 ..."
  4. Web (Apache/Nginx)  '1.2.3.4 - - [07/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 404 123'
  5. Genérico            cualquier línea: extrae la primera IP que encuentre
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# "Oct  7 12:34:56 host proceso[123]: mensaje"  (formato syslog clásico, sin año)
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
SSH_FAIL_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_OK_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
FW_RE = re.compile(r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)")
WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)
UDP_PRI_RE = re.compile(r"^<\d+>")  # prefijo de prioridad que añade syslog por red: "<34>"


@dataclass
class LogEvent:
    kind: str                       # auth_failure | auth_success | invalid_user | http | firewall | generic
    raw: str
    ts: Optional[datetime] = None   # None si la línea no trae fecha
    ip: Optional[str] = None        # IP de origen (la "sospechosa")
    fields: dict = field(default_factory=dict)  # datos extra: user, status, dst_port, etc.


def _parse_syslog_ts(text: str) -> Optional[datetime]:
    """El formato syslog no trae año: asumimos el actual."""
    try:
        return datetime.strptime(f"{datetime.now().year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _parse_json(line: str) -> Optional[LogEvent]:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    ts = None
    if isinstance(data.get("ts"), str):
        try:
            ts = datetime.fromisoformat(data["ts"]).replace(tzinfo=None)
        except ValueError:
            pass
    ip = data.get("ip") or data.get("src_ip") or data.get("source")
    return LogEvent(data.get("kind", "generic"), line, ts, ip, data)


def parse_line(line: str) -> Optional[LogEvent]:
    """Devuelve un LogEvent, o None si la línea está vacía."""
    line = UDP_PRI_RE.sub("", line.strip())
    if not line:
        return None

    if line.startswith("{"):
        ev = _parse_json(line)
        if ev:
            return ev

    m = WEB_RE.match(line)
    if m:
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except ValueError:
            ts = None
        return LogEvent("http", line, ts, m["ip"],
                        {"method": m["method"], "path": m["path"], "status": int(m["status"])})

    sl = SYSLOG_RE.match(line)
    ts, msg = (_parse_syslog_ts(sl["ts"]), sl["msg"]) if sl else (None, line)

    fw = FW_RE.search(msg)
    if fw:
        port = re.search(r"DPT=(\d+)", msg)
        proto = re.search(r"PROTO=(\w+)", msg)
        return LogEvent("firewall", line, ts, fw["src"],
                        {"dst": fw["dst"], "dst_port": int(port[1]) if port else None,
                         "proto": proto[1] if proto else None})

    for regex, kind in ((SSH_FAIL_RE, "auth_failure"), (SSH_OK_RE, "auth_success"),
                        (SSH_INVALID_RE, "invalid_user")):
        s = regex.search(msg)
        if s:
            return LogEvent(kind, line, ts, s["ip"], {"user": s["user"]})

    ip = IP_RE.search(msg)
    return LogEvent("generic", line, ts, ip[0] if ip else None)


def parse_file(path: str):
    """Generador: lee un archivo línea a línea (no lo carga entero en memoria)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                yield ev

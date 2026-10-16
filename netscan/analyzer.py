"""Analyzer: recibe líneas -> las parsea -> las pasa por los detectores -> acumula estadísticas."""
from __future__ import annotations

from collections import Counter
from typing import Callable, Iterable, Optional

from .detectors import Alert, default_detectors
from .logparser import parse_line


class Analyzer:
    def __init__(self, detectors=None, on_alert: Optional[Callable[[Alert], None]] = None):
        self.detectors = detectors if detectors is not None else default_detectors()
        self.on_alert = on_alert                  # se llama en cuanto salta una alerta (modo vivo)
        self.total_lines = 0
        self.kinds: Counter = Counter()           # cuántos eventos de cada tipo
        self.by_ip: Counter = Counter()           # cuántos eventos por IP
        self.users_tried: Counter = Counter()     # usuarios más atacados en logins fallidos
        self.alerts: list[Alert] = []

    def process_line(self, line: str) -> list[Alert]:
        ev = parse_line(line)
        if ev is None:
            return []
        self.total_lines += 1
        self.kinds[ev.kind] += 1
        if ev.ip:
            self.by_ip[ev.ip] += 1
        if ev.kind == "auth_failure":
            self.users_tried[ev.fields.get("user", "?")] += 1

        new_alerts = []
        for det in self.detectors:
            alert = det.feed(ev)
            if alert:
                new_alerts.append(alert)
                self.alerts.append(alert)
                if self.on_alert:
                    self.on_alert(alert)
        return new_alerts

    def process_lines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.process_line(line)

    def summary(self) -> dict:
        return {
            "lineas_analizadas": self.total_lines,
            "eventos_por_tipo": dict(self.kinds),
            "top_ips": self.by_ip.most_common(5),
            "usuarios_mas_atacados": self.users_tried.most_common(5),
            "alertas": [
                {"regla": a.rule, "severidad": a.severity, "ip": a.ip, "detalle": a.detail,
                 "hora": a.ts.isoformat() if a.ts else None}
                for a in self.alerts
            ],
        }

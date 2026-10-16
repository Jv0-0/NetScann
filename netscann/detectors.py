"""
Detectores: reglas que miran los eventos y levantan Alertas.

Idea central: la VENTANA DESLIZANTE. Para cada IP guardamos cuándo ocurrió cada evento y
descartamos los que son más viejos que `window` segundos. Si lo que queda supera un umbral
-> alerta. Así "5 fallos en 60 s" es sospechoso, pero "5 fallos en 5 días" no.

Se usa la hora que trae el log (no la del reloj), así funciona igual con un archivo viejo
(análisis offline) que con eventos en vivo.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .logparser import LogEvent


@dataclass
class Alert:
    rule: str
    severity: str          # "media" | "alta"
    ip: str
    detail: str
    ts: Optional[datetime] = None


def event_time(ev: LogEvent) -> float:
    """Segundos (epoch) del evento; si la línea no trae fecha, usamos 'ahora'."""
    return ev.ts.timestamp() if ev.ts else time.time()


class WindowDetector:
    """Clase base: guarda por IP los eventos recientes y evita alertas repetidas (cooldown)."""

    rule = "base"
    severity = "media"

    def __init__(self, threshold: int, window: int = 60):
        self.threshold = threshold
        self.window = window
        self._events: dict[str, deque] = defaultdict(deque)  # ip -> deque[(tiempo, valor)]
        self._last_alert: dict[str, float] = {}

    # Las subclases deciden qué eventos les interesan y qué "valor" cuenta.
    def interesting(self, ev: LogEvent) -> bool:
        raise NotImplementedError

    def value(self, ev: LogEvent):
        return 1

    def measure(self, values: list) -> int:
        """Qué número comparamos contra el umbral (por defecto: cuántos eventos)."""
        return len(values)

    def describe(self, ip: str, n: int) -> str:
        raise NotImplementedError

    def feed(self, ev: LogEvent) -> Optional[Alert]:
        if not ev.ip or not self.interesting(ev):
            return None
        now = event_time(ev)
        q = self._events[ev.ip]
        q.append((now, self.value(ev)))
        while q and q[0][0] < now - self.window:    # tirar lo que salió de la ventana
            q.popleft()

        n = self.measure([v for _, v in q])
        last = self._last_alert.get(ev.ip)
        if n >= self.threshold and (last is None or now - last >= self.window):
            self._last_alert[ev.ip] = now
            return Alert(self.rule, self.severity, ev.ip, self.describe(ev.ip, n), ev.ts)
        return None


class BruteForceDetector(WindowDetector):
    """Muchos intentos de login fallidos desde una misma IP."""
    rule = "fuerza-bruta"
    severity = "alta"

    def interesting(self, ev):
        return ev.kind == "auth_failure"

    def describe(self, ip, n):
        return f"{n} logins fallidos en {self.window}s"


class PortScanDetector(WindowDetector):
    """Una IP toca MUCHOS puertos distintos (típico de nmap) según el log del firewall."""
    rule = "escaneo-de-puertos"
    severity = "alta"

    def interesting(self, ev):
        return ev.kind == "firewall" and ev.fields.get("dst_port") is not None

    def value(self, ev):
        return ev.fields["dst_port"]

    def measure(self, values):
        return len(set(values))        # cuenta puertos DISTINTOS, no paquetes

    def describe(self, ip, n):
        return f"{n} puertos distintos en {self.window}s"


class WebScanDetector(WindowDetector):
    """Muchas respuestas 403/404 seguidas: alguien probando rutas (gobuster, nikto...)."""
    rule = "escaneo-web"
    severity = "media"

    def interesting(self, ev):
        return ev.kind == "http" and ev.fields.get("status") in (403, 404)

    def describe(self, ip, n):
        return f"{n} errores 403/404 en {self.window}s"


def default_detectors(window: int = 60, ssh: int = 5, ports: int = 10, web: int = 15):
    return [BruteForceDetector(ssh, window), PortScanDetector(ports, window), WebScanDetector(web, window)]

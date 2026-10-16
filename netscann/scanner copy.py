"""
Escáner de puertos TCP concurrente.

Mejoras respecto a la v0.1:
  * Usa hilos (ThreadPoolExecutor): escanea cientos de puertos a la vez en vez de uno por uno.
  * Distingue 3 estados: open / closed / filtered (antes solo "abierto" o "no abierto").
  * Banner grabbing: lee el saludo del servicio (ej. "SSH-2.0-OpenSSH_9.6") para identificarlo.
  * Rangos flexibles de puertos: "1-1024,3306,8080".

Úsalo SOLO contra equipos propios o con autorización por escrito.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

# Servicios típicos. Si el puerto no está aquí, probamos con la base de datos del sistema operativo.
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-alt",
}
# En estos puertos el servidor NO habla primero: hay que enviarle algo para que responda.
HTTP_PORTS = {80, 8000, 8080, 8888}


@dataclass
class PortResult:
    port: int
    state: str            # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    """Convierte "22,80,100-200" en una lista ordenada [22, 80, 100, 101, ..., 200]."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"Puertos fuera de rango (1-65535): {sorted(invalid)[:5]}")
    return sorted(ports)


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def grab_banner(sock: socket.socket, port: int, host: str, timeout: float) -> str:
    """Intenta leer el 'saludo' del servicio sobre un socket ya conectado."""
    try:
        sock.settimeout(timeout)
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(256)
        text = data.decode("utf-8", errors="replace").strip()
        # Nos quedamos con la primera línea, máximo 100 caracteres.
        return text.splitlines()[0][:100] if text else ""
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0, banner: bool = False) -> PortResult:
    """
    Intenta una conexión TCP completa (connect scan) y clasifica el resultado:
      * Conecta                      -> open
      * Rechazo inmediato (RST)      -> closed  (el equipo respondió "aquí no hay nada")
      * Timeout / otro error de red  -> filtered (algo, p.ej. un firewall, descarta el paquete)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        return PortResult(port, "closed")
    except (socket.timeout, TimeoutError):
        return PortResult(port, "filtered")
    except OSError:
        return PortResult(port, "filtered")
    else:
        text = grab_banner(sock, port, host, timeout) if banner else ""
        return PortResult(port, "open", service_name(port), text)
    finally:
        sock.close()  # 'finally' garantiza que el socket se cierra pase lo que pase


def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
    banner: bool = False,
    on_open: Optional[Callable[[PortResult], None]] = None,
) -> list[PortResult]:
    """Escanea todos los puertos en paralelo. `on_open` se llama apenas se encuentra uno abierto."""
    ip = socket.gethostbyname(host)  # resuelve nombres de dominio -> IP (lanza gaierror si falla)
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, banner) for p in ports]
        for fut in as_completed(futures):      # as_completed entrega cada resultado al terminar
            res = fut.result()
            results.append(res)
            if res.state == "open" and on_open:
                on_open(res)
    return sorted(results, key=lambda r: r.port)

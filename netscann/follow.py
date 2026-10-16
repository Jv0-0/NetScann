"""
Fuentes de logs en TIEMPO REAL. Ambas son generadores: producen líneas conforme llegan.

  * follow_file : como `tail -f`. Detecta rotación (logrotate) y truncado del archivo.
  * listen_udp  : recibe mensajes syslog por red (UDP). Así otro equipo/router/firewall
                  puede enviarte sus logs directamente.

`stop` es un threading.Event: cuando se activa, el generador termina limpiamente.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from typing import Iterator, Optional


def follow_file(path: str, from_start: bool = False, poll: float = 0.5,
                stop: Optional[threading.Event] = None) -> Iterator[str]:
    f = open(path, "r", encoding="utf-8", errors="replace")
    inode = os.fstat(f.fileno()).st_ino
    if not from_start:
        f.seek(0, os.SEEK_END)          # saltar al final: solo nos interesa lo NUEVO
    partial = ""                        # por si leemos media línea (el otro programa aún escribe)
    try:
        while not (stop and stop.is_set()):
            line = f.readline()
            if line:
                if line.endswith("\n"):
                    yield partial + line
                    partial = ""
                else:
                    partial += line
                continue

            # No hay líneas nuevas. ¿Rotaron o truncaron el archivo?
            try:
                st = os.stat(path)
            except FileNotFoundError:
                time.sleep(poll)
                continue
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
                partial = ""
                continue
            time.sleep(poll)
    finally:
        f.close()


def listen_udp(host: str = "0.0.0.0", port: int = 5140,
               stop: Optional[threading.Event] = None) -> Iterator[str]:
    """Receptor syslog UDP. Puerto 5140 por defecto (el 514 estándar exige permisos de administrador)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)                # despertar seguido para poder revisar `stop`
    try:
        while not (stop and stop.is_set()):
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            for line in data.decode("utf-8", errors="replace").splitlines():
                yield line
    finally:
        sock.close()

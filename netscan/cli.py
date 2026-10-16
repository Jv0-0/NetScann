"""
Interfaz de línea de comandos. Tres subcomandos:

  python -m netscann scan    <host> [-p 1-1024] [--banner] [--json salida.json]
  python -m netscann analyze <log1> [log2 ...] [--json reporte.json]
  python -m netscann watch   <archivo.log>   |   watch --udp 5140
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading

from . import __version__
from .analyzer import Analyzer
from .detectors import Alert, default_detectors
from .follow import follow_file, listen_udp
from .scanner import parse_ports, scan_host

RED, YELLOW, GREEN, DIM, RESET = "\033[91m", "\033[93m", "\033[92m", "\033[2m", "\033[0m"


def print_alert(a: Alert) -> None:
    color = RED if a.severity == "alta" else YELLOW
    when = a.ts.strftime("%H:%M:%S") if a.ts else "--:--:--"
    print(f"{color}[ALERTA {a.severity.upper()}]{RESET} {when} {a.rule}  ip={a.ip}  {a.detail}", flush=True)


def print_summary(an: Analyzer) -> None:
    s = an.summary()
    print(f"\n{DIM}--- Resumen ---{RESET}")
    print(f"Líneas analizadas : {s['lineas_analizadas']}")
    print(f"Eventos por tipo  : {s['eventos_por_tipo']}")
    print(f"IPs más activas   : {s['top_ips']}")
    if s["usuarios_mas_atacados"]:
        print(f"Usuarios atacados : {s['usuarios_mas_atacados']}")
    print(f"Alertas generadas : {len(s['alertas'])}")


def make_analyzer(args, live: bool) -> Analyzer:
    dets = default_detectors(window=args.window, ssh=args.ssh_threshold,
                             ports=args.port_threshold, web=args.web_threshold)
    return Analyzer(dets, on_alert=print_alert if live else None)


# ---------- subcomandos ----------

def cmd_scan(args) -> int:
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error en --ports: {e}", file=sys.stderr)
        return 2
    print(f"Escaneando {args.host} ({len(ports)} puertos, timeout={args.timeout}s, hilos={args.workers})...")

    def show(r):
        extra = f"  {DIM}{r.banner}{RESET}" if r.banner else ""
        print(f"{GREEN}  {r.port:>5}/tcp abierto{RESET}  {r.service}{extra}", flush=True)

    try:
        results = scan_host(args.host, ports, args.timeout, args.workers, args.banner, on_open=show)
    except socket.gaierror:
        print(f"No se pudo resolver el host '{args.host}'", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nEscaneo cancelado.")
        return 130

    counts = {s: sum(1 for r in results if r.state == s) for s in ("open", "closed", "filtered")}
    print(f"\nListo: {counts['open']} abiertos, {counts['closed']} cerrados, {counts['filtered']} filtrados.")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([r.__dict__ for r in results if r.state == "open"], f, indent=2)
        print(f"Resultados guardados en {args.json}")
    return 0


def cmd_analyze(args) -> int:
    an = make_analyzer(args, live=False)
    for path in args.files:
        try:
            for line in _raw_lines(path):
                an.process_line(line)
        except OSError as e:
            print(f"No se pudo leer {path}: {e}", file=sys.stderr)
            return 1
    for a in an.alerts:
        print_alert(a)
    print_summary(an)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(an.summary(), f, indent=2, ensure_ascii=False)
        print(f"Reporte guardado en {args.json}")
    return 0


def _raw_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        yield from f


def cmd_watch(args) -> int:
    if not args.file and args.udp is None:
        print("Indica un archivo o --udp PUERTO", file=sys.stderr)
        return 2
    an = make_analyzer(args, live=True)
    stop = threading.Event()
    try:
        if args.udp is not None:
            print(f"Escuchando syslog UDP en 0.0.0.0:{args.udp}  (Ctrl+C para salir)")
            source = listen_udp("0.0.0.0", args.udp, stop)
        else:
            print(f"Siguiendo {args.file}  (Ctrl+C para salir)")
            source = follow_file(args.file, from_start=args.from_start, stop=stop)
        for line in source:
            if args.verbose:
                print(f"{DIM}{line.rstrip()}{RESET}")
            an.process_line(line)
    except FileNotFoundError:
        print(f"No existe el archivo: {args.file}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        stop.set()
    print_summary(an)
    return 0


# ---------- argparse ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netscann", description="Escáner de puertos y analizador de logs")
    p.add_argument("--version", action="version", version=f"netscann {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="escanear puertos TCP de un host")
    s.add_argument("host")
    s.add_argument("-p", "--ports", default="1-1024", help='ej: "22,80,443" o "1-65535" (def. 1-1024)')
    s.add_argument("-t", "--timeout", type=float, default=1.0)
    s.add_argument("-w", "--workers", type=int, default=100, help="conexiones simultáneas")
    s.add_argument("-b", "--banner", action="store_true", help="leer el banner del servicio")
    s.add_argument("--json", metavar="ARCHIVO")
    s.set_defaults(func=cmd_scan)

    def add_rules(sp):
        sp.add_argument("--window", type=int, default=60, help="ventana en segundos (def. 60)")
        sp.add_argument("--ssh-threshold", type=int, default=5, help="logins fallidos para alertar")
        sp.add_argument("--port-threshold", type=int, default=10, help="puertos distintos para alertar")
        sp.add_argument("--web-threshold", type=int, default=15, help="errores 403/404 para alertar")

    a = sub.add_parser("analyze", help="analizar uno o varios archivos de log")
    a.add_argument("files", nargs="+")
    a.add_argument("--json", metavar="ARCHIVO", help="guardar reporte en JSON")
    add_rules(a)
    a.set_defaults(func=cmd_analyze)

    w = sub.add_parser("watch", help="analizar logs en tiempo real")
    w.add_argument("file", nargs="?", help="archivo a seguir (como tail -f)")
    w.add_argument("--udp", type=int, metavar="PUERTO", help="recibir syslog por UDP")
    w.add_argument("--from-start", action="store_true", help="leer el archivo desde el inicio")
    w.add_argument("-v", "--verbose", action="store_true", help="mostrar cada línea recibida")
    add_rules(w)
    w.set_defaults(func=cmd_watch)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

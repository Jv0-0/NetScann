"""Genera logs de ejemplo en samples/ para practicar sin necesitar un servidor real."""
import os
import random
from datetime import datetime, timedelta

random.seed(7)
OUT = os.path.join(os.path.dirname(__file__), "..", "samples")
os.makedirs(OUT, exist_ok=True)
t0 = datetime.now().replace(microsecond=0) - timedelta(minutes=30)


def sys_ts(t):
    return f"{t.strftime('%b')} {t.day:>2} {t.strftime('%H:%M:%S')}"


# --- auth.log: tráfico normal + un ataque de fuerza bruta desde 203.0.113.50 ---
lines, t = [], t0
for _ in range(15):
    t += timedelta(seconds=random.randint(20, 90))
    lines.append(f"{sys_ts(t)} srv sshd[1201]: Accepted password for joseph from 192.168.1.20 port 5522 ssh2")
t = t0 + timedelta(minutes=10)
for user in ["root", "admin", "ubuntu", "root", "test", "oracle", "root", "pi"]:
    t += timedelta(seconds=2)
    lines.append(f"{sys_ts(t)} srv sshd[1300]: Invalid user {user} from 203.0.113.50 port 40022")
    lines.append(f"{sys_ts(t)} srv sshd[1300]: Failed password for invalid user {user} from 203.0.113.50 port 40022 ssh2")
open(f"{OUT}/auth.log", "w").write("\n".join(lines) + "\n")

# --- firewall.log: un escaneo de puertos desde 198.51.100.7 ---
lines, t = [], t0
for port in range(20, 45):
    t += timedelta(milliseconds=300)
    lines.append(f"{sys_ts(t)} fw kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.7 DST=192.168.1.10 PROTO=TCP SPT=44321 DPT={port}")
for _ in range(5):
    t += timedelta(seconds=5)
    lines.append(f"{sys_ts(t)} fw kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.99 DST=192.168.1.10 PROTO=TCP SPT=50000 DPT=443")
open(f"{OUT}/firewall.log", "w").write("\n".join(lines) + "\n")

# --- access.log: navegación normal + barrido de rutas desde 192.0.2.33 ---
lines, t = [], t0
for path in ["/", "/index.html", "/css/app.css", "/login"]:
    t += timedelta(seconds=10)
    lines.append(f'192.168.1.20 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {path} HTTP/1.1" 200 512')
for path in ["admin", "wp-login.php", ".env", "backup.zip", "phpmyadmin", "config.php", ".git/config", "server-status",
             "test", "old", "api/v1", "db.sql", "login.php", "shell.php", "upload", "cgi-bin/x"]:
    t += timedelta(milliseconds=400)
    lines.append(f'192.0.2.33 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /{path} HTTP/1.1" 404 153')
open(f"{OUT}/access.log", "w").write("\n".join(lines) + "\n")
print("Logs de ejemplo creados en samples/")

"""
Simula un servidor que va escribiendo logs en vivo (para probar `netscann watch`).

Terminal 1:  python tools/simulate_live.py live.log
Terminal 2:  python -m netscann watch live.log
"""
import sys
import time
from datetime import datetime

path = sys.argv[1] if len(sys.argv) > 1 else "live.log"
users = ["root", "admin", "ubuntu", "oracle", "test", "pi", "user"]
print(f"Escribiendo en {path} (Ctrl+C para parar)")
try:
    with open(path, "a", buffering=1) as f:
        i = 0
        while True:
            t = datetime.now()
            ts = f"{t.strftime('%b')} {t.day:>2} {t.strftime('%H:%M:%S')}"
            f.write(f"{ts} srv sshd[99]: Failed password for {users[i % len(users)]} from 203.0.113.99 port 4000 ssh2\n")
            i += 1
            time.sleep(0.5)
except KeyboardInterrupt:
    pass

"""Pruebas automáticas. Ejecutar:  python -m unittest discover -s tests -v"""
import os
import socket
import tempfile
import threading
import time
import unittest

from netscann.analyzer import Analyzer
from netscann.detectors import default_detectors
from netscann.follow import follow_file, listen_udp
from netscann.logparser import parse_line
from netscann.scanner import parse_ports, scan_port


class TestPorts(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])
        self.assertEqual(parse_ports("5-3"), [3, 4, 5])

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("0-10")
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_open_and_closed(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.assertEqual(scan_port("127.0.0.1", port, 0.5).state, "open")
        srv.close()
        self.assertEqual(scan_port("127.0.0.1", port, 0.5).state, "closed")


class TestParser(unittest.TestCase):
    def test_ssh_failure(self):
        ev = parse_line("Oct  7 12:00:01 srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")
        self.assertEqual((ev.kind, ev.ip, ev.fields["user"]), ("auth_failure", "1.2.3.4", "root"))
        self.assertEqual(ev.ts.hour, 12)

    def test_ssh_invalid_user_variant(self):
        ev = parse_line("Oct  7 12:00:01 srv sshd[1]: Failed password for invalid user bob from 5.6.7.8 port 1")
        self.assertEqual((ev.kind, ev.fields["user"]), ("auth_failure", "bob"))

    def test_web(self):
        ev = parse_line('9.9.9.9 - - [07/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 404 12')
        self.assertEqual((ev.kind, ev.ip, ev.fields["status"]), ("http", "9.9.9.9", 404))

    def test_firewall(self):
        ev = parse_line("Oct  7 12:00:01 fw kernel: [UFW BLOCK] SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=443")
        self.assertEqual((ev.kind, ev.ip, ev.fields["dst_port"]), ("firewall", "1.1.1.1", 443))

    def test_json_and_generic_and_empty(self):
        self.assertEqual(parse_line('{"ip": "8.8.8.8", "kind": "x"}').ip, "8.8.8.8")
        self.assertEqual(parse_line("algo raro de 10.0.0.1 pasó").ip, "10.0.0.1")
        self.assertIsNone(parse_line("   \n"))

    def test_udp_priority_prefix(self):
        ev = parse_line("<38>Oct  7 12:00:01 srv sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2")
        self.assertEqual(ev.kind, "auth_failure")

    def test_garbage_does_not_crash(self):
        for junk in ["{no es json", "\x00\x01", "SRC= DST=", "[[[", "999.999.999.999"]:
            parse_line(junk)


class TestDetectors(unittest.TestCase):
    def feed(self, lines):
        an = Analyzer(default_detectors(window=60, ssh=5, ports=10, web=15))
        an.process_lines(lines)
        return an

    def fail(self, sec, ip="6.6.6.6"):
        return f"Oct  7 12:00:{sec:02d} srv sshd[1]: Failed password for root from {ip} port 1 ssh2"

    def test_bruteforce_triggers(self):
        an = self.feed([self.fail(s) for s in range(5)])
        self.assertEqual([a.rule for a in an.alerts], ["fuerza-bruta"])

    def test_slow_attempts_do_not_trigger(self):
        # 1 intento cada 30 s: nunca hay 5 dentro de una ventana de 60 s
        lines = [f"Oct  7 12:{m:02d}:{s:02d} srv sshd[1]: Failed password for root from 6.6.6.6 port 1 ssh2"
                 for m in range(5) for s in (0, 30)][::2]
        self.assertEqual(self.feed(lines).alerts, [])

    def test_cooldown_prevents_spam(self):
        an = self.feed([self.fail(s) for s in range(30)])
        self.assertEqual(len(an.alerts), 1)

    def test_port_scan_counts_distinct_ports(self):
        same = [f"Oct  7 12:00:00 fw k: SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=443"] * 50
        self.assertEqual(self.feed(same).alerts, [])           # mismo puerto muchas veces: NO es escaneo
        many = [f"Oct  7 12:00:00 fw k: SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT={p}" for p in range(10)]
        self.assertEqual([a.rule for a in self.feed(many).alerts], ["escaneo-de-puertos"])

    def test_ips_are_tracked_independently(self):
        lines = [self.fail(s, f"7.7.7.{s % 5}") for s in range(20)]   # 4 intentos por IP
        self.assertEqual(self.feed(lines).alerts, [])


class TestLive(unittest.TestCase):
    def collect(self, gen, n, out):
        """Guarda en `out` cada línea recibida y se detiene al llegar a n líneas."""
        for line in gen:
            out.append(line.strip())
            if len(out) >= n:
                break

    def test_follow_new_lines_and_rotation(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "live.log")
            with open(path, "w") as f:
                f.write("vieja\n")
            stop = threading.Event()
            got = []
            t = threading.Thread(target=self.collect, args=(follow_file(path, poll=0.05, stop=stop), 2, got))
            t.start()
            time.sleep(0.3)
            with open(path, "a") as f:
                f.write("nueva1\n")
            time.sleep(0.3)
            os.replace(path, path + ".1")               # logrotate: renombra el archivo...
            with open(path, "w") as f:                  # ...y crea uno nuevo
                f.write("tras-rotacion\n")
            t.join(6)
            stop.set()
            self.assertEqual(got, ["nueva1", "tras-rotacion"])   # "vieja" se ignora (no from_start)

    def test_follow_partial_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.log")
            open(path, "w").close()
            stop = threading.Event()
            got = []
            t = threading.Thread(target=self.collect, args=(follow_file(path, poll=0.05, stop=stop), 1, got))
            t.start()
            time.sleep(0.3)
            with open(path, "a") as f:
                f.write("media-")
                f.flush()
                time.sleep(0.3)
                f.write("linea\n")
            t.join(6)
            stop.set()
            self.assertEqual(got, ["media-linea"])

    def test_udp_receiver(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        stop = threading.Event()
        got = []
        t = threading.Thread(target=self.collect, args=(listen_udp("127.0.0.1", port, stop), 1, got))
        t.start()
        time.sleep(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"<34>hola desde la red\n", ("127.0.0.1", port))
        t.join(6)
        stop.set()
        self.assertEqual(got, ["<34>hola desde la red"])


if __name__ == "__main__":
    unittest.main()

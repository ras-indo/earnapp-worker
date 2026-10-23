#!/usr/bin/env python3
"""proxy_pool.py — cari proxy gratis, uji, tulis pool untuk earnappd.

Alur:
  1. ambil daftar proxy dari beberapa sumber publik (http + socks5)
  2. uji paralel: TCP + handshake + TLS ke target nyata
  3. tulis yang hidup ke /etc/earnapp/proxies.txt (urut latency)
  4. ulangi tiap --interval detik; yang mati otomatis dibuang

earnappd membaca file itu tiap 60 detik dan mengganti proxy node
segera setelah koneksi gagal (failover di level worker).
"""
import argparse
import concurrent.futures as cf
import json
import functools
import os
import random
import socket
import ssl
import sys
import time
import urllib.request

SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=protocolipport&format=text",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=text",
]

CHECK_HOST = "proxyjs.brdtnet.com"   # infra yang benar-benar dipakai worker
CHECK_PORT = 443
OUT = os.environ.get("PROXY_OUT", "/etc/earnapp/proxies.txt")
LOG = os.environ.get("PROXY_LOG", "/var/log/proxy_pool.log")
MAX_KEEP = int(os.environ.get("PROXY_MAX", "400"))


def log(msg):
    line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(time.strftime("%Y-%m-%d ") + line + "\n")
    except Exception:
        pass


def fetch(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:
        log("sumber gagal %s: %s" % (url.split("/")[2], e))
        return ""


def parse(text, default_type):
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        typ = default_type
        if "://" in line:
            scheme, rest = line.split("://", 1)
            typ = "http" if scheme.startswith("http") else "socks5"
        else:
            rest = line
        rest = rest.split()[0]
        if ":" not in rest:
            continue
        host, _, port = rest.rpartition(":")
        host = host.strip("[]")
        try:
            p = int(port)
        except ValueError:
            continue
        if host and 0 < p < 65536:
            out.add((typ, host, p))
    return out


def recv_until(s, marker, limit=4096):
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = s.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf


def socks5_handshake(s, host, port):
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        return False
    h = host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big")
    s.sendall(req)
    rep = s.recv(4)
    if len(rep) < 4 or rep[0] != 5 or rep[1] != 0:
        return False
    atyp = rep[3]
    extra = 4 if atyp == 1 else 16 if atyp == 4 else 0
    if atyp == 3:
        ln = s.recv(1)
        extra = (ln[0] if ln else 0) + 2
    if extra:
        s.recv(extra)
    return True


def http_handshake(s, host, port):
    req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)).encode()
    s.sendall(req)
    resp = recv_until(s, b"\r\n\r\n")
    return resp.startswith(b"HTTP/") and b" 200" in resp.split(b"\r\n")[0]


def check(px, timeout=8.0):
    typ, host, port = px
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        ok = socks5_handshake(s, CHECK_HOST, CHECK_PORT) if typ == "socks5" else http_handshake(s, CHECK_HOST, CHECK_PORT)
        if not ok:
            s.close()
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ss = ctx.wrap_socket(s, server_hostname=CHECK_HOST)
        ss.close()
        return (round(time.time() - t0, 2), typ, host, port)
    except Exception:
        return None


def collect():
    pool = set()
    for url in SOURCES:
        default = "socks5" if "socks5" in url else "http"
        text = fetch(url)
        got = parse(text, default)
        log("%-42s %5d proxy" % (url.split("/")[2] + "/" + url.split("/")[-1][:28], len(got)))
        pool |= got
    return pool


def ip_meta(ips):
    """Cek tipe IP (hosting/proxy/residential) via ip-api batch."""
    out = {}
    url = "http://ip-api.com/batch?fields=query,hosting,proxy,mobile,as,countryCode"
    uniq = list(dict.fromkeys(ips))
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        try:
            body = json.dumps([{"query": ip} for ip in chunk]).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as r:
                for row in json.loads(r.read().decode()):
                    out[row.get("query")] = row
        except Exception as e:
            log("ip-api gagal: %s" % e)
        time.sleep(4.2)
    return out


def residential_only(rows, factor=3):
    """Sisakan proxy yang IP keluarnya bukan hosting/proxy (mirip syarat EarnApp)."""
    cand = rows[:max(len(rows), 0)]
    meta = ip_meta([r[2] for r in cand])
    good, bad = [], 0
    for r in cand:
        m = meta.get(r[2])
        if not m:
            good.append(r)          # tidak ketahuan → anggap netral
            continue
        if m.get("hosting") or m.get("proxy"):
            bad += 1
            continue
        good.append(r)
    log("filter IP: %d hosting/proxy dibuang, %d lolos" % (bad, len(good)))
    return good


def write_atomic(rows):
    tmp = OUT + ".tmp"
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(tmp, "w") as f:
        f.write("# auto-generated oleh proxy_pool.py — jangan diedit manual\n")
        for _, typ, host, port in rows:
            f.write("%s://%s:%d\n" % (typ, host, port))
    os.replace(tmp, OUT)
    try:
        os.chmod(OUT, 0o644)
    except Exception:
        pass


def cycle(workers, keep, sample, timeout, allow_dc=False):
    pool = collect()
    pool = list(pool)
    random.shuffle(pool)
    if sample and len(pool) > sample:
        pool = pool[:sample]
    log("total unik diuji: %d — menguji..." % len(pool))
    alive = []
    fn = functools.partial(check, timeout=timeout)
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(fn, pool):
            if res:
                alive.append(res)
    alive.sort()
    if alive and not allow_dc:
        alive = residential_only(alive[:max(keep * 4, 200)])
        alive.sort()
    if not alive:
        log("TIDAK ADA proxy hidup — file lama dipertahankan")
        return 0
    write_atomic(alive[:keep])
    log("hidup: %d — ditulis %d terbaik ke %s (tercepat %.2fs)" % (len(alive), min(len(alive), keep), OUT, alive[0][0]))
    return len(alive)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=300, help="detik antar siklus")
    ap.add_argument("--workers", type=int, default=200)
    ap.add_argument("--keep", type=int, default=MAX_KEEP)
    ap.add_argument("--sample", type=int, default=2500, help="maks proxy diuji per siklus")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--allow-dc", action="store_true", help="izinkan IP hosting (default: hanya residential)")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    while True:
        try:
            cycle(a.workers, a.keep, a.sample, a.timeout, a.allow_dc)
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            log("siklus error: %s" % e)
        if a.once:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())

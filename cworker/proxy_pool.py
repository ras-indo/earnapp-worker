#!/usr/bin/env python3
"""proxy_pool.py — cari proxy, verifikasi exit country, tulis pool US-only untuk earnappd.

Alur:
  1. ambil daftar proxy dari beberapa sumber publik (http + socks5)
  2. uji paralel: TCP + handshake + TLS ke target nyata
  3. cek exit IP tiap proxy (via HTTPS api.ipify.org)
  4. lookup country lewat ip-api batch; hanya exit country US yang lolos
  5. tulis /etc/earnapp/proxies.txt dengan header country=US
  6. ulangi tiap --interval detik; kalau tidak ada US, file lama dipertahankan
"""
import argparse
import concurrent.futures as cf
import functools
import ipaddress
import json
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
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/socks5.txt",
    "https://proxyspace.pro/http.txt",
    "https://proxyspace.pro/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
]

CHECK_HOST = "proxyjs.brdtnet.com"
CHECK_PORT = 443
OUT = os.environ.get("PROXY_OUT", "/etc/earnapp/proxies.txt")
LOG = os.environ.get("PROXY_LOG", "/var/log/proxy_pool.log")
MAX_KEEP = int(os.environ.get("PROXY_MAX", "400"))
BLOCK_COUNTRIES = "ID,INDONESIA"


def log(msg):
    line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        d = os.path.dirname(LOG)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(LOG, "a") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d"), line))
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
    first = resp.split(b"\r\n", 1)[0]
    return first.startswith(b"HTTP/") and b" 200" in first


def open_proxy(px, host, port, timeout=8):
    typ, phost, pport = px
    s = socket.create_connection((phost, pport), timeout=timeout)
    s.settimeout(timeout)
    ok = socks5_handshake(s, host, port) if typ == "socks5" else http_handshake(s, host, port)
    if not ok:
        s.close()
        return None
    return s


def read_all(s, limit=65536):
    buf = b""
    while len(buf) < limit:
        try:
            chunk = s.recv(4096)
        except (socket.timeout, OSError, ssl.SSLError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def dechunk(data):
    out = b""
    while data:
        line, sep, rest = data.partition(b"\r\n")
        if not sep:
            break
        try:
            n = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            break
        if n == 0:
            break
        out += rest[:n]
        data = rest[n + 2:]
    return out


def http_body(data):
    if not data:
        return b""
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return b""
    status = head.split(b"\r\n", 1)[0] + b" "
    if b" 200 " not in status:
        return b""
    if b"transfer-encoding: chunked" in head.lower():
        body = dechunk(body)
    return body


def parse_ip(data):
    text = data.decode("utf-8", "ignore").strip()
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line or len(line) > 64:
            continue
        try:
            ipaddress.ip_address(line)
            return line
        except ValueError:
            continue
    return None


def check(px, timeout=8.0):
    t0 = time.time()
    s = None
    try:
        s = open_proxy(px, CHECK_HOST, CHECK_PORT, timeout)
        if not s:
            return None
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(s, server_hostname=CHECK_HOST)
        ss.close()
        return {"lat": round(time.time() - t0, 2), "type": px[0], "host": px[1], "port": px[2]}
    except Exception:
        if s:
            try:
                s.close()
            except Exception:
                pass
        return None


def https_get(px, host, path, timeout=6.0):
    s = None
    ss = None
    try:
        s = open_proxy(px, host, 443, timeout)
        if not s:
            return b""
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.settimeout(timeout)
        req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % (path, host)
        ss.sendall(req.encode())
        return read_all(ss)
    except Exception:
        return b""
    finally:
        if ss:
            try:
                ss.close()
            except Exception:
                pass
        elif s:
            try:
                s.close()
            except Exception:
                pass


def http_get(px, host, port, path, timeout=6.0, absolute=False):
    s = None
    try:
        if px[0] == "socks5":
            s = socket.create_connection((px[1], px[2]), timeout=timeout)
            s.settimeout(timeout)
            if not socks5_handshake(s, host, port):
                return b""
            req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % (path, host)
        else:
            s = socket.create_connection((px[1], px[2]), timeout=timeout)
            s.settimeout(timeout)
            if absolute:
                req = "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % (host, path, host)
            else:
                if not http_handshake(s, host, port):
                    return b""
                req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % (path, host)
        s.sendall(req.encode())
        return read_all(s)
    except Exception:
        return b""
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def exit_ip(px, timeout=6.0):
    for host in ("api.ipify.org", "ipv4.icanhazip.com"):
        ip = parse_ip(http_body(https_get(px, host, "/", timeout)))
        if ip:
            return ip
        ip = parse_ip(http_body(http_get(px, host, 80, "/", timeout, absolute=True)))
        if ip:
            return ip
        if px[0] != "socks5":
            ip = parse_ip(http_body(http_get(px, host, 80, "/", timeout, absolute=False)))
            if ip:
                return ip
    return None


def ip_meta(ips):
    out = {}
    uniq = list(dict.fromkeys(ip for ip in ips if ip))
    if not uniq:
        return out
    url = "http://ip-api.com/batch?fields=query,countryCode,hosting,proxy,status"
    for i in range(0, len(uniq), 100):
        chunk = uniq[i:i + 100]
        body = json.dumps([{"query": ip} for ip in chunk]).encode()
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, data=body, headers={
                    "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=25) as r:
                    rows = json.loads(r.read().decode("utf-8", "replace"))
                if isinstance(rows, list):
                    for row in rows:
                        q = row.get("query")
                        if q:
                            out[q] = row
                    break
            except Exception as e:
                log("ip-api batch %d coba %d gagal: %s" % (i // 100 + 1, attempt + 1, e))
                time.sleep(5 + attempt * 5)
        time.sleep(4.2)
    return out


def verify_country(rows, country, timeout, workers):
    if not rows:
        return []
    def one(r):
        return r, exit_ip((r["type"], r["host"], r["port"]), timeout)
    pairs = []
    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(rows)))) as ex:
        for r, ip in ex.map(one, rows):
            if ip:
                pairs.append((r, ip))
    meta = ip_meta([ip for _, ip in pairs])
    out = []
    for r, ip in pairs:
        m = meta.get(ip) or {}
        if (m.get("countryCode") or "").upper() != country.upper():
            continue
        rr = dict(r)
        rr["exit"] = ip
        rr["country"] = (m.get("countryCode") or "").upper()
        rr["hosting"] = bool(m.get("hosting"))
        rr["proxy"] = bool(m.get("proxy"))
        out.append(rr)
    return out


def collect():
    pool = set()
    def one(url):
        default = "socks5" if "socks5" in url else "http"
        return url, parse(fetch(url), default)
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for url, got in ex.map(one, SOURCES):
            log("%-42s %5d proxy" % (url.split("/")[2] + "/" + url.split("/")[-1][:28], len(got)))
            pool |= got
    return pool


def check_many(proxies, workers, timeout):
    if not proxies:
        return []
    fn = functools.partial(check, timeout=timeout)
    out = []
    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(proxies)))) as ex:
        for r in ex.map(fn, proxies):
            if r:
                out.append(r)
    return out


def load_cache(path):
    out = set()
    try:
        if not os.path.exists(path):
            return out
        with open(path) as f:
            text = f.read()
        out |= parse(text, "http")
    except Exception as e:
        log("cache gagal dibaca: %s" % e)
    return out


def save_cache(rows, path):
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            for r in rows:
                f.write("%s://%s:%d\n" % (r["type"], r["host"], r["port"]))
        os.replace(tmp, path)
    except Exception as e:
        log("cache gagal disimpan: %s" % e)


def write_atomic(rows, country, blocked):
    d = os.path.dirname(OUT)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        f.write("# earnapp pool country=%s block=%s verified=%d count=%d generated=%d\n"
                % (country.upper(), ",".join(sorted(blocked)), int(time.time()), len(rows), int(time.time())))
        for r in rows:
            f.write("%s://%s:%d\n" % (r["type"], r["host"], r["port"]))
    os.replace(tmp, OUT)
    try:
        os.chmod(OUT, 0o644)
    except Exception:
        pass


def cycle(args):
    cached = load_cache(args.us_cache)
    log("cache %s: %d proxy" % (args.country, len(cached)))

    pool = collect()
    pool = list(pool)
    random.shuffle(pool)
    if args.sample and len(pool) > args.sample:
        pool = pool[:args.sample]
    log("total unik diuji: %d — menguji..." % len(pool))
    fresh = check_many(pool, args.workers, args.timeout)
    cached_alive = check_many(cached, min(args.workers, 64), args.timeout)

    seen = {}
    for r in cached_alive + fresh:
        key = (r["type"], r["host"], r["port"])
        if key not in seen or r["lat"] < seen[key]["lat"]:
            seen[key] = r
    alive = sorted(seen.values(), key=lambda r: r["lat"])
    log("hidup: %d" % len(alive))
    if not alive:
        log("TIDAK ADA proxy hidup — file lama dipertahankan")
        return 0

    candidates = alive[:max(args.keep * 8, 400)]
    log("verifikasi exit country %s untuk %d kandidat..." % (args.country, len(candidates)))
    verified = verify_country(candidates, args.country, args.timeout, args.verify_workers)
    blocked = {c.strip().upper() for c in args.block_countries.split(",") if c.strip()}
    before = len(verified)
    verified = [r for r in verified if r.get("country") not in blocked]
    if before != len(verified):
        log("blokir %s: %d proxy dibuang" % (",".join(sorted(blocked)), before - len(verified)))
    if not args.allow_dc:
        verified = [r for r in verified if not r["hosting"] and not r["proxy"]]
    # satu node = satu exit IP; buang proxy yang exit IP-nya sama
    by_exit = {}
    for r in verified:
        ip = r.get("exit")
        if ip and ip not in by_exit:
            by_exit[ip] = r
    verified = list(by_exit.values())
    verified.sort(key=lambda r: (1 if (r["hosting"] or r["proxy"]) else 0, r["lat"]))
    log("exit %s terverifikasi: %d (residential=%d)" % (
        args.country, len(verified),
        sum(1 for r in verified if not r["hosting"] and not r["proxy"])))
    if not verified:
        log("TIDAK ADA proxy %s terverifikasi — file lama dipertahankan" % args.country)
        return 0

    final = verified[:args.keep]
    write_atomic(final, args.country, blocked)
    save_cache(final, args.us_cache)
    log("ditulis %d proxy %s ke %s (tercepat %.2fs, exit %s)" % (
        len(final), args.country, OUT, final[0]["lat"], final[0].get("exit", "?")))
    return len(final)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=300, help="detik antar siklus")
    ap.add_argument("--workers", type=int, default=200)
    ap.add_argument("--verify-workers", type=int, default=100)
    ap.add_argument("--keep", type=int, default=MAX_KEEP)
    ap.add_argument("--sample", type=int, default=2500, help="maks proxy diuji per siklus")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--allow-dc", action="store_true", help="izinkan IP hosting (default: hanya residential)")
    ap.add_argument("--prefer-country", default="US", help="negara wajib (default US)")
    ap.add_argument("--block-countries", default=BLOCK_COUNTRIES,
                    help="country yang selalu diblokir (default ID,INDONESIA)")
    ap.add_argument("--us-cache", default="/etc/earnapp/us_pool.txt")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    while True:
        try:
            cycle(a)
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            log("siklus error: %s" % e)
            if a.once:
                return 1
        if a.once:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())

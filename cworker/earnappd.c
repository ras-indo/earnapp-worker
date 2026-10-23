/* earnappd.c v2 — MULTI-NODE EarnApp C worker
 * Build: gcc -O2 -o earnappd earnappd.c -lssl -lcrypto -lpthread
 *
 * Usage:
 *   earnappd --new [n]     : bikin n node baru (register + print URL link)
 *   earnappd -n N          : jalankan N node pertama dari registry
 *   earnappd               : jalankan SEMUA node di registry
 * Registry: /etc/earnapp/nodes.txt (1 uuid per baris)
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#define CONFDIR "/etc/earnapp"
#define VERSION "1.665.73"
#define APPID   "node_earnapp.com"
#define APPID_ALIAS "f5-ecd7-94cb-3556"  /* VERIFIED dari binary */
#define PARTNERID "luminati"
#define MAIN_HOST "proxyjs.brdtnet.com"
#define MAIN_PORT 443
#define REGFILE CONFDIR "/nodes.txt"

static const char *PINS[] = {
    "oFfUjFQ0MqcGmytHtJkkF0iSjdb9CLVyr09Jimysrxk=",
    "88MboGWoPjNZGkvZ9ZZ+IiUfJFLkye5CxHH0jCrq4k=",
    "tf9QLkwylg1ngcBPcT2Q9wt2Zl8Olv1mkK+au4gB2oI=",
    "LX0+nXiJHH9Ar7wi6bsnsSp+b9UwdEbZU/yIhTztnNE=",
    "HMGRre14gBWdMGwWaW1aN5VIG3CrciqzjzuiAVPsdiM=",
};
#define N_PINS 5

/* ---------------- per-node context ---------------- */
typedef struct NodeCtx {
    char uuid[64];
    char oldcid[128];
    char cid[128];
    char ifname[32];
    char px_host[64];
    int px_port;
    int px_type;          /* 0=langsung, 1=socks5, 2=http connect */
    long consent_ts;
    int hb_n;
    int idx;
    pthread_mutex_t mtx;
} NodeCtx;

static char g_ifname[32] = "eth0";
static int g_vpn = 0;

static void logt(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    time_t now = time(NULL);
    struct tm tmv; localtime_r(&now, &tmv);
    printf("[c %02d:%02d:%02d] ", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    vprintf(fmt, ap); printf("\n"); fflush(stdout);
    va_end(ap);
}

static char *slurp(const char *path, char *buf, int sz) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    if (!fgets(buf, sz, f)) { fclose(f); return NULL; }
    fclose(f);
    buf[strcspn(buf, "\r\n")] = 0;
    return buf;
}

/* ---------------- DNS ---------------- */
static int dns_query_a(const char *host, struct in_addr *out) {
    if (inet_pton(AF_INET, host, out) == 1) return 0;
    unsigned char q[512];
    int tid = rand() & 0xffff;
    int i = 0;
    q[i++] = tid >> 8; q[i++] = tid & 0xff;
    q[i++] = 0x01; q[i++] = 0x00;
    q[i++] = 0; q[i++] = 1; q[i++] = 0; q[i++] = 0;
    q[i++] = 0; q[i++] = 0; q[i++] = 0; q[i++] = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        q[i++] = (unsigned char)len;
        memcpy(q + i, p, len); i += len;
        if (!dot) break;
        p = dot + 1;
    }
    q[i++] = 0; q[i++] = 0; q[i++] = 1; q[i++] = 0; q[i++] = 1;
    const char *srv[] = {"8.8.8.8", "8.8.4.4"};
    for (int s = 0; s < 2; s++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, srv[s], &sa.sin_addr);
        sa.sin_port = htons(53);
        if (sendto(fd, q, i, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
            close(fd); continue;
        }
        unsigned char r[1500];
        int n = recv(fd, r, sizeof r, 0);
        close(fd);
        if (n < 12 || r[0] != (tid >> 8) || r[1] != (tid & 0xff)) continue;
        int ancount = (r[6] << 8) | r[7];
        int pos = 12;
        while (pos < n && r[pos]) pos += 1 + r[pos];
        pos += 5;
        for (int a = 0; a < ancount && pos + 12 <= n; a++) {
            if ((r[pos] & 0xc0) == 0xc0) pos += 2;
            else { while (pos < n && r[pos]) pos += 1 + r[pos]; pos += 1; }
            if (pos + 12 > n) break;
            int type = (r[pos] << 8) | r[pos + 1];
            int rdlen = (r[pos + 8] << 8) | r[pos + 9];
            pos += 10;
            if (pos + rdlen > n) break;
            if (type == 1 && rdlen == 4) { memcpy(out, r + pos, 4); return 0; }
            pos += rdlen;
        }
    }
    return -1;
}

/* ---------------- TLS + SPKI pin ---------------- */
static int g_pin_ok = 0;

static int verify_cb(int ok, X509_STORE_CTX *ctx) {
    (void)ok;
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) return 0;
    unsigned char *der = NULL;
    int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
    if (len <= 0) return 0;
    unsigned char hash[32]; unsigned int hlen = 0;
    EVP_Digest(der, len, hash, &hlen, EVP_sha256(), NULL);
    OPENSSL_free(der);
    char b64[64];
    EVP_EncodeBlock((unsigned char *)b64, hash, 32);
    g_pin_ok = 0;
    for (int i = 0; i < N_PINS; i++)
        if (!strcmp(b64, PINS[i])) { g_pin_ok = 1; break; }
    return 1;
}

typedef struct { SSL *ssl; int fd; unsigned char buf[65536]; int blen; } WS;

/* ---------------- proxy pool (socks5 / http connect) ---------------- */
typedef struct {
    char host[64];
    int port;
    int type;              /* 1=socks5, 2=http connect */
    int fails;
    long dead_until;
    int owner;             /* -1 = bebas */
} Px;

#define MAX_PX 512
static Px g_px[MAX_PX];
static int g_pxn = 0;
static pthread_mutex_t g_pxmtx = PTHREAD_MUTEX_INITIALIZER;
static long g_px_mtime = 0;
static const char *g_pxfile = CONFDIR "/proxies.txt";

/* proxy aktif utk thread ini (diwarisi thread koneksi data) */
static __thread int t_px_type = 0;
static __thread char t_px_host[64];
static __thread int t_px_port = 0;

/* fallback satu proxy global via env */
static char g_socks_host[64];
static int  g_socks_port = 0;

static long now_s(void) { return (long)time(NULL); }

static int px_parse_line(const char *line, Px *out) {
    char buf[160];
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p || *p == '#') return -1;
    snprintf(buf, sizeof buf, "%s", p);
    char *nl = strpbrk(buf, "\r\n \t"); if (nl) *nl = 0;
    out->type = 1;
    char *hp = buf;
    if (!strncmp(hp, "socks5://", 9)) { out->type = 1; hp += 9; }
    else if (!strncmp(hp, "socks4://", 9)) { out->type = 1; hp += 9; }
    else if (!strncmp(hp, "http://", 7)) { out->type = 2; hp += 7; }
    else if (!strncmp(hp, "https://", 8)) { out->type = 2; hp += 8; }
    char *colon = strrchr(hp, ':');
    if (!colon) return -1;
    *colon = 0;
    int port = atoi(colon + 1);
    if (!*hp || port <= 0 || port > 65535) return -1;
    snprintf(out->host, sizeof out->host, "%s", hp);
    out->port = port;
    out->fails = 0;
    out->dead_until = 0;
    out->owner = -1;
    return 0;
}

static int px_load(const char *path, int force) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (!force && (long)st.st_mtime == g_px_mtime) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    pthread_mutex_lock(&g_pxmtx);
    /* pertahankan status proxy yang sudah dikenal */
    Px old[MAX_PX];
    int oldn = g_pxn;
    memcpy(old, g_px, sizeof(Px) * (size_t)oldn);
    int n = 0;
    char line[192];
    while (n < MAX_PX && fgets(line, sizeof line, f)) {
        Px t;
        if (px_parse_line(line, &t) < 0) continue;
        for (int i = 0; i < oldn; i++) {
            if (old[i].port == t.port && !strcmp(old[i].host, t.host)) {
                t.fails = old[i].fails;
                t.dead_until = old[i].dead_until;
                t.owner = old[i].owner;
                break;
            }
        }
        g_px[n++] = t;
    }
    fclose(f);
    g_pxn = n;
    g_px_mtime = (long)st.st_mtime;
    pthread_mutex_unlock(&g_pxmtx);
    logt("proxy pool: %d proxy (%s)", n, path);
    return n;
}

/* ambil satu proxy hidup; sebar supaya tiap node beda IP bila tersedia */
static int px_acquire(NodeCtx *n) {
    if (!g_pxn) return -1;
    long t = now_s();
    pthread_mutex_lock(&g_pxmtx);
    int start = (int)(n->idx * 37 + (int)(t / 60)) % g_pxn;
    int best = -1;
    for (int k = 0; k < g_pxn; k++) {
        int i = (start + k) % g_pxn;
        if (g_px[i].dead_until > t) continue;
        if (g_px[i].owner == n->idx) { best = i; break; }
        if (g_px[i].owner == -1 && best < 0) best = i;
    }
    if (best < 0) { pthread_mutex_unlock(&g_pxmtx); return -1; }
    g_px[best].owner = n->idx;
    snprintf(n->px_host, sizeof n->px_host, "%s", g_px[best].host);
    n->px_port = g_px[best].port;
    n->px_type = g_px[best].type;
    pthread_mutex_unlock(&g_pxmtx);
    return 0;
}

static void px_drop(NodeCtx *n) {
    if (!n->px_type) return;
    long t = now_s();
    pthread_mutex_lock(&g_pxmtx);
    for (int i = 0; i < g_pxn; i++) {
        if (g_px[i].port != n->px_port || strcmp(g_px[i].host, n->px_host)) continue;
        g_px[i].fails++;
        if (g_px[i].fails >= 2) g_px[i].dead_until = t + 300;
        g_px[i].owner = -1;
        break;
    }
    pthread_mutex_unlock(&g_pxmtx);
    n->px_type = 0; n->px_host[0] = 0; n->px_port = 0;
}

/* ---------------- SOCKS5 / HTTP CONNECT ---------------- */
static void socks_init(void) {
    const char *e = getenv("EARNAPP_SOCKS");
    if (e && *e) {
        const char *c = strrchr(e, ':');
        if (c) {
            int n = (int)(c - e);
            if (n > 0 && n < (int)sizeof g_socks_host) {
                memcpy(g_socks_host, e, n);
                g_socks_host[n] = 0;
                g_socks_port = atoi(c + 1);
                logt("proxy global: %s:%d", g_socks_host, g_socks_port);
            }
        }
    }
    const char *f = getenv("EARNAPP_PROXY_FILE");
    if (f && *f) g_pxfile = f;
    px_load(g_pxfile, 1);
}

static void *px_watch(void *a) {
    (void)a;
    for (;;) { sleep(60); px_load(g_pxfile, 0); }
    return NULL;
}

static int tcp_raw(const char *host, int port, int timeout_s) {
    struct in_addr ipa;
    if (dns_query_a(host, &ipa) < 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = {timeout_s, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_addr = ipa; sa.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return -1; }
    return fd;
}

static int socks5_proxy(int fd, const char *host, int port) {
    unsigned char g[3] = {5, 1, 0};
    if (write(fd, g, 3) != 3) return -1;
    unsigned char r[2];
    if (read(fd, r, 2) != 2 || r[0] != 5 || r[1] != 0) return -1;
    size_t hl = strlen(host);
    if (hl > 200) return -1;
    unsigned char req[512];
    int p = 0;
    req[p++] = 5; req[p++] = 1; req[p++] = 0; req[p++] = 3; req[p++] = (unsigned char)hl;
    memcpy(req + p, host, hl); p += (int)hl;
    req[p++] = (unsigned char)((port >> 8) & 0xff);
    req[p++] = (unsigned char)(port & 0xff);
    if (write(fd, req, p) != p) return -1;
    unsigned char rep[32];
    if (read(fd, rep, 4) != 4 || rep[1] != 0) return -1;
    int alen = rep[3] == 1 ? 4 : rep[3] == 4 ? 16 : 0;
    if (alen && read(fd, rep + 4, alen + 2) != alen + 2) return -1;
    return 0;
}

static int http_proxy_connect(int fd, const char *host, int port) {
    char req[512];
    int n = snprintf(req, sizeof req,
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: Mozilla/5.0\r\nProxy-Connection: keep-alive\r\n\r\n",
        host, port, host, port);
    if (n <= 0 || write(fd, req, (size_t)n) != n) return -1;
    char buf[1024];
    int got = 0;
    while (got < (int)sizeof buf - 1) {
        int r = read(fd, buf + got, sizeof buf - 1 - (size_t)got);
        if (r <= 0) return -1;
        got += r;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (strncmp(buf, "HTTP/1.", 7) && strncmp(buf, "HTTP/1.1", 8)) return -1;
    if (!strstr(buf, " 200")) return -1;
    return 0;
}

static int proxy_open(const char *pxh, int pxp, int type, const char *host, int port) {
    int fd = tcp_raw(pxh, pxp, 12);
    if (fd < 0) return -1;
    int rc = (type == 2) ? http_proxy_connect(fd, host, port) : socks5_proxy(fd, host, port);
    if (rc < 0) { close(fd); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static int tcp_open(const char *host, int port, char *ipstr, size_t n) {
    if (t_px_type) {
        int fd = proxy_open(t_px_host, t_px_port, t_px_type, host, port);
        if (fd >= 0) snprintf(ipstr, n, "px:%s", t_px_host);
        return fd;
    }
    if (g_socks_port) {
        int fd = proxy_open(g_socks_host, g_socks_port, 1, host, port);
        if (fd >= 0) snprintf(ipstr, n, "socks:%s", host);
        return fd;
    }
    int fd = tcp_raw(host, port, 20);
    if (fd < 0) return -1;
    snprintf(ipstr, n, "%s", host);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static WS *ws_connect(const char *host, int port, const char *servername) {
    char ipstr[80];
    int fd = tcp_open(host, port, ipstr, sizeof ipstr);
    if (fd < 0) { logt("connect gagal %s:%d", host, port); return NULL; }

    SSL_CTX *lctx = SSL_CTX_new(TLS_client_method());
    if (!lctx) { close(fd); return NULL; }
    SSL_CTX_set_default_verify_paths(lctx);
    SSL_CTX_set_verify(lctx, SSL_VERIFY_PEER, verify_cb);
    SSL *ssl = SSL_new(lctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, servername);
    SSL_set1_host(ssl, servername);
    if (SSL_connect(ssl) != 1) {
        logt("TLS gagal %s (%s)", servername, ipstr);
        SSL_free(ssl); SSL_CTX_free(lctx); close(fd); return NULL;
    }
    unsigned char key[16];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (ur) { fread(key, 1, 16, ur); fclose(ur); }
    char b64key[32];
    EVP_EncodeBlock((unsigned char *)b64key, key, 16); b64key[24] = 0;
    char req[512];
    int rl = snprintf(req, sizeof req,
        "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", servername, b64key);
    SSL_write(ssl, req, rl);
    char resp[2048]; int total = 0;
    while (total < (int)sizeof resp - 1) {
        int n = SSL_read(ssl, resp + total, sizeof resp - 1 - total);
        if (n <= 0) { SSL_free(ssl); SSL_CTX_free(lctx); close(fd); return NULL; }
        total += n; resp[total] = 0;
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (!strstr(resp, "101")) {
        logt("ws upgrade ditolak: %.60s", resp);
        SSL_free(ssl); SSL_CTX_free(lctx); close(fd); return NULL;
    }
    WS *ws = calloc(1, sizeof *ws);
    ws->ssl = ssl; ws->fd = fd;
    char *hdr_end = strstr(resp, "\r\n\r\n");
    int consumed = (int)(hdr_end - resp) + 4;
    if (total > consumed) {
        memcpy(ws->buf, resp + consumed, total - consumed);
        ws->blen = total - consumed;
    }
    return ws;
}

static void ws_close(WS *ws) {
    if (!ws) return;
    SSL_shutdown(ws->ssl);
    SSL_free(ws->ssl);
    close(ws->fd);
    free(ws);
}

static int ws_send_frame(WS *ws, int opcode, const unsigned char *data, int len) {
    unsigned char hdr[14];
    int hl = 0;
    hdr[hl++] = 0x80 | opcode;
    unsigned char mask[4];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (ur) { fread(mask, 1, 4, ur); fclose(ur); }
    else memset(mask, 0x5a, 4);
    if (len < 126) hdr[hl++] = 0x80 | len;
    else if (len < 65536) { hdr[hl++] = 0x80 | 126; hdr[hl++] = len >> 8; hdr[hl++] = len & 0xff; }
    else { hdr[hl++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) hdr[hl++] = (len >> (8 * i)) & 0xff; }
    memcpy(hdr + hl, mask, 4); hl += 4;
    unsigned char *out = malloc(hl + len);
    memcpy(out, hdr, hl);
    for (int i = 0; i < len; i++) out[hl + i] = data[i] ^ mask[i & 3];
    int n = SSL_write(ws->ssl, out, hl + len);
    free(out);
    return n > 0 ? 0 : -1;
}

static int ws_send_text(WS *ws, const char *s) {
    return ws_send_frame(ws, 1, (const unsigned char *)s, strlen(s));
}
static int ws_send_bin(WS *ws, const unsigned char *b, int len) {
    return ws_send_frame(ws, 2, b, len);
}
static int ws_send_ping(WS *ws) {
    unsigned char p[8] = {0};
    return ws_send_frame(ws, 9, p, 8);
}

static int ws_recv_frame(WS *ws, int *op, unsigned char **payload, int *plen, int timeout_s) {
    *payload = NULL; *plen = 0;
    for (;;) {
        struct timeval tv = {timeout_s, 0};
        setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        int need = 2;
        while (ws->blen < need) {
            int n = SSL_read(ws->ssl, ws->buf + ws->blen, sizeof ws->buf - ws->blen);
            if (n <= 0) {
                int e_ = SSL_get_error(ws->ssl, n);
                if (e_ == SSL_ERROR_WANT_READ || errno == EAGAIN || errno == EWOULDBLOCK) return -2;
                return -1;
            }
            ws->blen += n;
        }
        unsigned char *h = (unsigned char *)ws->buf;
        int opcode = h[0] & 0x0f;
        int masked = h[1] & 0x80;
        unsigned long long len = h[1] & 0x7f;
        int pos = 2;
        if (len == 126) {
            need = 4;
            while (ws->blen < need) {
                int n = SSL_read(ws->ssl, ws->buf + ws->blen, sizeof ws->buf - ws->blen);
                if (n <= 0) { int e_ = SSL_get_error(ws->ssl, n); if (e_ == SSL_ERROR_WANT_READ || errno == EAGAIN) return -2; return -1; }
                ws->blen += n;
            }
            len = ((unsigned long long)h[2] << 8) | h[3]; pos = 4;
        } else if (len == 127) {
            need = 10;
            while (ws->blen < need) {
                int n = SSL_read(ws->ssl, ws->buf + ws->blen, sizeof ws->buf - ws->blen);
                if (n <= 0) { int e_ = SSL_get_error(ws->ssl, n); if (e_ == SSL_ERROR_WANT_READ || errno == EAGAIN) return -2; return -1; }
                ws->blen += n;
            }
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | h[2 + i];
            pos = 10;
        }
        if (len > 16ULL * 1024 * 1024) return -1;   /* sanity */
        if (masked) {
            need = pos + 4;
            while (ws->blen < need) {
                int n = SSL_read(ws->ssl, ws->buf + ws->blen, sizeof ws->buf - ws->blen);
                if (n <= 0) { int e_ = SSL_get_error(ws->ssl, n); if (e_ == SSL_ERROR_WANT_READ || errno == EAGAIN) return -2; return -1; }
                ws->blen += n;
            }
        }
        unsigned char mask[4] = {0,0,0,0};
        int hdr = pos + (masked ? 4 : 0);
        if (masked) memcpy(mask, ws->buf + pos, 4);
        unsigned char *data = malloc((size_t)len + 1);
        if (!data) return -1;
        size_t have = (size_t)(ws->blen - hdr);
        if (have > len) have = (size_t)len;
        if (have) memcpy(data, ws->buf + hdr, have);
        ws->blen = 0;                                 /* header habis dipakai */
        size_t got = have;
        while (got < len) {
            int n = SSL_read(ws->ssl, data + got, (int)(len - got));
            if (n <= 0) {
                int e_ = SSL_get_error(ws->ssl, n);
                free(data);
                if (e_ == SSL_ERROR_WANT_READ || errno == EAGAIN || errno == EWOULDBLOCK) return -2;
                return -1;
            }
            got += (size_t)n;
        }
        if (masked) for (size_t i = 0; i < len; i++) data[i] ^= mask[i & 3];
        data[len] = 0;
        if (opcode == 9) { ws_send_frame(ws, 0xA, data, (int)len); free(data); continue; }
        if (opcode == 10) { free(data); continue; }
        *payload = data; *plen = (int)len; *op = opcode;
        return 0;
    }
}

/* ---------------- JSON helpers ---------------- */
static int json_get_str(const char *js, const char *key, char *out, int sz) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(js, pat);
    if (!p) {
        snprintf(pat, sizeof pat, "\"%s\":", key);
        p = strstr(js, pat);
        if (!p) return -1;
        p += strlen(pat);
        if (*p == '"') p++;
        else {
            if (!strncmp(p, "null", 4)) { out[0] = 0; return 0; }
            int i = 0; while (*p && *p != ',' && *p != '}' && i < sz - 1) out[i++] = *p++;
            out[i] = 0; return 0;
        }
    } else p += strlen(pat);
    int i = 0;
    while (*p && *p != '"' && i < sz - 1) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = 0;
    return 0;
}
static long json_get_int(const char *js, const char *key, long dflt) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(js, pat);
    if (!p) return dflt;
    p += strlen(pat);
    if (*p == '"') p++;
    return strtol(p, NULL, 10);
}
static long json_get_cookie(const char *js) {
    const char *p = strstr(js, "\"cookie\":");
    if (!p) return -1;
    p += 9;
    if (!strncmp(p, "null", 4)) return -1;
    return strtol(p, NULL, 10);
}

static long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000;
}

/* ---------------- generic HTTPS POST ---------------- */
static int http_post_json(const char *host, const char *path,
                          const char *ua, const char *body, char *out_status, int out_sz) {
    char ipstr[80];
    int fd = tcp_open(host, 443, ipstr, sizeof ipstr);
    if (fd < 0) return -1;
    struct timeval tv = {25, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    SSL_CTX *lctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(lctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); SSL_CTX_free(lctx); close(fd); return -1; }
    char req[8192];
    int rl = snprintf(req, sizeof req,
        "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        path, host, ua, (int)strlen(body), body);
    SSL_write(ssl, req, rl);
    char rbuf[2048]; int n = SSL_read(ssl, rbuf, sizeof rbuf - 1);
    if (n > 0) { rbuf[n] = 0; if (out_status) { strncpy(out_status, rbuf, out_sz - 1); out_status[out_sz-1] = 0; } }
    int ok = (n > 15 && rbuf[9] == '2');
    SSL_free(ssl); SSL_CTX_free(lctx); close(fd);
    return ok ? 0 : -1;
}

/* ---------------- device info global ---------------- */
static void detect_ifname(void) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return;
    char line[256];
    fgets(line, sizeof line, f);
    while (fgets(line, sizeof line, f)) {
        char iface[32]; unsigned dest;
        if (sscanf(line, "%31s %X", iface, &dest) == 2 && dest == 0x08080808) {
            strncpy(g_ifname, iface, sizeof g_ifname - 1);
            break;
        }
    }
    fclose(f);
}

static int vpn_profile_enabled(void) {
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return 0;
    char line[256]; int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *c = strchr(line, ':');
        if (!c) continue;
        *c = 0;
        char *name = line; while (*name == ' ') name++;
        if (!strncmp(name, "tailscale", 9) || !strncmp(name, "tun", 3) ||
            !strncmp(name, "wg", 2) || !strncmp(name, "ppp", 3) ||
            !strncmp(name, "ipsec", 5) || !strncmp(name, "vpn", 3)) { found = 1; break; }
    }
    fclose(f);
    return found;
}

/* ---------------- perr per-node ---------------- */
static void perr_node(NodeCtx *n, const char *id, const char *info_json) {
    char body[1024];
    snprintf(body, sizeof body,
        "{\"info\":%s,\"ts\":\"2026-01-01 00:00:00.000\",\"build\":\"\","
        "\"appid\":\"" APPID_ALIAS "\",\"since_start\":0,\"since_connect\":0}",
        info_json ? info_json : "{}");
    char path[1024];
    snprintf(path, sizeof path,
        "/perr?id=lum_sdk_node_%s&appid=" APPID_ALIAS "&ver=" VERSION
        "&ver_sdk=" VERSION "&uuid=%s", id, n->uuid);
    if (http_post_json("perr.brightdata.com", path,
                       "Luminati/" VERSION " (sdk; )", body, NULL, 0) == 0)
        logt("n%d perr %s OK", n->idx, id);
}

static void perr_hb(NodeCtx *n) {
    const char *label = n->hb_n == 0 ? "00_1min" : (n->hb_n == 1 ? "01_2min" : "02_4min");
    if (n->hb_n < 2) n->hb_n++;
    char id[64];
    snprintf(id, sizeof id, "heartbeat_proxy_js_conn_%s", label);
    perr_node(n, id, NULL);
}

/* ---------------- uuid ---------------- */
static void gen_uuid(char *out /* 33 */) {
    unsigned char r[16];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (ur) { fread(r, 1, 16, ur); fclose(ur); }
    static const char hx[] = "0123456789abcdef";
    memcpy(out, "sdk-node-", 9);
    for (int i = 0; i < 16; i++) { out[9 + i * 2] = hx[r[i] >> 4]; out[10 + i * 2] = hx[r[i] & 0xf]; }
    out[41] = 0;
}

static int register_device(const char *uuid) {
    char body[512];
    snprintf(body, sizeof body,
        "{\"uuid\":\"%s\",\"version\":\"" VERSION "\",\"arch\":\"arm64\","
        "\"appid\":\"" APPID "\",\"os\":\"Debian GNU/Linux 12\"}", uuid);
    for (int attempt = 0; attempt < 3; attempt++) {
        if (http_post_json("client.earnapp.com", "/install_device",
                           "axios/0.32.0", body, NULL, 0) == 0) return 0;
        logt("register %s gagal (percobaan %d/3), retry...", uuid + 9, attempt + 1);
        sleep(3 + attempt * 4);
    }
    return -1;
}

/* ---------------- real system metrics utk idle_state ---------------- */
static long g_streams_total = 0;  /* atomik-ish: diupdate dgn mutex global */
static pthread_mutex_t g_statmtx = PTHREAD_MUTEX_INITIALIZER;

static double cpu_usage_pct(void) {
    static long prev_idle = -1, prev_total = -1;
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0.0;
    char line[256];
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0.0; }
    fclose(f);
    unsigned long long usr=0,nic=0,sys=0,idle=0,iow=0,irq=0,sirq=0,steal=0;
    sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
           &usr,&nic,&sys,&idle,&iow,&irq,&sirq,&steal);
    long total = usr+nic+sys+idle+iow+irq+sirq+steal;
    long idle_t = idle + iow;
    double pct = 0.0;
    if (prev_idle >= 0 && total > prev_total) {
        long dt = total - prev_total;
        if (dt > 0) pct = 100.0 * (1.0 - (double)(idle_t - prev_idle) / dt);
    }
    prev_idle = idle_t; prev_total = total;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    return pct;
}

static double mem_usage_pct(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0.0;
    char line[128];
    long tot = 0, avail = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "MemTotal:", 9)) tot = strtol(line + 9, NULL, 10);
        else if (!strncmp(line, "MemAvailable:", 13)) avail = strtol(line + 13, NULL, 10);
    }
    fclose(f);
    if (tot <= 0) return 0.0;
    return 100.0 * (1.0 - (double)avail / tot);
}

static long active_streams(void) {
    pthread_mutex_lock(&g_statmtx);
    long v = g_streams_total;
    pthread_mutex_unlock(&g_statmtx);
    return v;
}

static long g_now_ms_status = 0;

/* ---------------- data conn ---------------- */
#define MAX_VFD 64
typedef struct { int vfd, fd; long rx; long last_ack_ms; int used; } VfdEnt;

typedef struct {
    WS *ws;
    NodeCtx *node;
    VfdEnt tab[MAX_VFD];
    pthread_mutex_t mtx;
    pthread_mutex_t wmtx;   /* SSL_write tidak boleh bersamaan antar thread */
    int refs;               /* pump + dc thread */
    volatile int dead;
} DataConn;

static void dc_send_text(DataConn *dc, const char *s) {
    pthread_mutex_lock(&dc->wmtx);
    ws_send_text(dc->ws, s);
    pthread_mutex_unlock(&dc->wmtx);
}
static void dc_send_bin(DataConn *dc, const unsigned char *b, int len) {
    pthread_mutex_lock(&dc->wmtx);
    ws_send_bin(dc->ws, b, len);
    pthread_mutex_unlock(&dc->wmtx);
}
static void dc_send_ping(DataConn *dc) {
    pthread_mutex_lock(&dc->wmtx);
    ws_send_ping(dc->ws);
    pthread_mutex_unlock(&dc->wmtx);
}
static void dc_release(DataConn *dc) {
    int last = 0;
    pthread_mutex_lock(&dc->mtx);
    if (--dc->refs <= 0) last = 1;
    pthread_mutex_unlock(&dc->mtx);
    if (!last) return;
    pthread_mutex_destroy(&dc->mtx);
    pthread_mutex_destroy(&dc->wmtx);
    ws_close(dc->ws);
    free(dc);
}

static VfdEnt *dc_find(DataConn *dc, int vfd) {
    for (int i = 0; i < MAX_VFD; i++)
        if (dc->tab[i].used && dc->tab[i].vfd == vfd) return &dc->tab[i];
    return NULL;
}

static void dc_send_ack(DataConn *dc, int vfd) {
    VfdEnt *e = dc_find(dc, vfd);
    if (!e) return;
    long t = now_ms();
    if (t - e->last_ack_ms < 100) return;
    e->last_ack_ms = t;
    char m[64]; snprintf(m, sizeof m, "{\"vfd\":%d,\"ack\":%ld}", vfd, e->rx);
    dc_send_text(dc, m);
}

static void dc_close_vfd(DataConn *dc, int vfd) {
    pthread_mutex_lock(&dc->mtx);
    VfdEnt *e = dc_find(dc, vfd);
    int was = e ? 1 : 0;
    if (e) { close(e->fd); e->used = 0; }
    pthread_mutex_unlock(&dc->mtx);
    if (was) {
        pthread_mutex_lock(&g_statmtx);
        if (g_streams_total > 0) g_streams_total--;
        pthread_mutex_unlock(&g_statmtx);
    }
    char m[64]; snprintf(m, sizeof m, "{\"vfd\":%d,\"fin\":1}", vfd);
    dc_send_text(dc, m);
}

static int dc_handle_tun(DataConn *dc, const char *js) {
    if (dc->node) {
        t_px_type = dc->node->px_type;
        snprintf(t_px_host, sizeof t_px_host, "%s", dc->node->px_host);
        t_px_port = dc->node->px_port;
    }
    long vfd = json_get_int(js, "vfd", 0);
    char host[256], port_s[16];
    if (json_get_str(js, "host", host, sizeof host) < 0) return -1;
    if (json_get_str(js, "port", port_s, sizeof port_s) < 0) return -1;
    long port = strtol(port_s, NULL, 10);
    if (port == 25) return -1;
    char ipstr[80];
    int fd = tcp_open(host, (int)port, ipstr, sizeof ipstr);
    if (fd < 0) return -2;
    struct timeval tv = {15, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    pthread_mutex_lock(&dc->mtx);
    VfdEnt *e = dc_find(dc, vfd);
    if (!e) for (int i = 0; i < MAX_VFD; i++) if (!dc->tab[i].used) { e = &dc->tab[i]; break; }
    if (e) { e->vfd = vfd; e->fd = fd; e->rx = 0; e->last_ack_ms = 0; e->used = 1; }
    pthread_mutex_unlock(&dc->mtx);
    char m[48]; snprintf(m, sizeof m, "{\"vfd\":%ld,\"win_size\":2097152}", vfd);
    dc_send_text(dc, m);
    pthread_mutex_lock(&g_statmtx);
    g_streams_total++;
    pthread_mutex_unlock(&g_statmtx);
    logt("n%d tun vfd=%ld -> %s:%ld", dc->node->idx, vfd, host, port);
    return 0;
}

static void *pump_thread(void *arg) {
    DataConn *dc = arg;
    for (;;) {
        if (dc->dead) break;
        pthread_mutex_lock(&dc->mtx);
        int alive = 0;
        fd_set rfds; FD_ZERO(&rfds);
        int maxfd = -1;
        for (int i = 0; i < MAX_VFD; i++)
            if (dc->tab[i].used) { FD_SET(dc->tab[i].fd, &rfds); if (dc->tab[i].fd > maxfd) maxfd = dc->tab[i].fd; alive = 1; }
        pthread_mutex_unlock(&dc->mtx);
        if (!alive) { sleep(1); continue; }
        struct timeval tv = {1, 0};
        int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) continue;
        for (int i = 0; i < MAX_VFD; i++) {
            int fd = -1, vfd = -1;
            pthread_mutex_lock(&dc->mtx);
            if (dc->tab[i].used && FD_ISSET(dc->tab[i].fd, &rfds)) { fd = dc->tab[i].fd; vfd = dc->tab[i].vfd; }
            pthread_mutex_unlock(&dc->mtx);
            if (fd < 0) continue;
            unsigned char buf[65536];
            int n = read(fd, buf, sizeof buf);
            if (n <= 0) { dc_close_vfd(dc, vfd); continue; }
            unsigned char *out = malloc(8 + n);
            unsigned int vn = htonl(vfd);
            memcpy(out, &vn, 4); memset(out + 4, 0, 4);
            memcpy(out + 8, buf, n);
            dc_send_bin(dc, out, 8 + n);
            free(out);
        }
    }
    dc_release(dc);
    return NULL;
}

static void *dc_thread(void *arg) {
    DataConn *dc = arg;
    WS *ws = dc->ws;
    long last_ping = now_ms();
    for (;;) {
        int op, plen; unsigned char *data = NULL;
        int rc = ws_recv_frame(ws, &op, &data, &plen, 5);
        if (rc == -2) {
            long t = now_ms();
            if (t - last_ping >= 30000) { dc_send_ping(dc); last_ping = t; }
            continue;
        }
        if (rc < 0) { free(data); break; }
        if (op == 1) {
            const char *js = (char *)data;
            if (strstr(js, "\"vfd\":") && !strstr(js, "\"cmd\"")) {
                long vfd = json_get_int(js, "vfd", 0);
                if (strstr(js, "\"fin\":")) dc_close_vfd(dc, vfd);
                free(data); continue;
            }
            char cmd[48]; cmd[0] = 0;
            json_get_str(js, "cmd", cmd, sizeof cmd);
            long cookie = json_get_cookie(js);
            char out[4096];
            if (!strcmp(cmd, "tun")) {
                int rcc = dc_handle_tun(dc, js);
                if (rcc == -2) snprintf(out, sizeof out,
                    "{\"type\":\"ipc_result\",\"cmd\":\"tun\",\"cookie\":%ld,\"msg\":{\"err\":\"conn\"}}", cookie);
                else snprintf(out, sizeof out,
                    "{\"type\":\"ipc_result\",\"cmd\":\"tun\",\"cookie\":%ld,\"msg\":{}}", cookie);
                dc_send_text(dc, out);
            } else if (!strcmp(cmd, "tun_close")) {
                dc_close_vfd(dc, json_get_int(js, "vfd", 0));
                snprintf(out, sizeof out,
                    "{\"type\":\"ipc_result\",\"cmd\":\"tun_close\",\"cookie\":%ld,\"msg\":{}}", cookie);
                dc_send_text(dc, out);
            } else if (!strcmp(cmd, "tunnel_init")) {
                /* IDENTIK main conn (dgn cid utk data conn) — server validasi field ini */
                char cidpart[128] = "";
                if (dc->node->cid[0]) {
                    char *sl = strchr(dc->node->cid, '/');
                    snprintf(cidpart, sizeof cidpart, ",\"cid\":\"%s\"",
                             dc->node->cid);
                    (void)sl;
                }
                snprintf(out, sizeof out,
                    "{\"type\":\"ipc_result\",\"cmd\":\"tunnel_init\",\"cookie\":%ld,\"msg\":{"
                    "\"arch\":\"arm64\",\"release\":\"debian_12_arm64\",\"platform\":\"node\","
                    "\"version\":\"" VERSION "\",\"old_cid\":\"%s\",\"is_tv\":false,"
                    "\"appid\":\"" APPID_ALIAS "\"," "\"partnerid\":\"" PARTNERID "\"," 
                    "\"uuid\":\"%s\",\"ifname\":\"%s\",\"usage\":{},\"consent_ts\":%ld,"
                    "\"last_rmt_upd_success\":null,\"vpn_profile_enabled\":%s%s}}",
                    cookie, dc->node->oldcid, dc->node->uuid, g_ifname,
                    dc->node->consent_ts,
                    g_vpn ? "true" : "false", cidpart);
                dc_send_text(dc, out);
            } else if (!strcmp(cmd, "status_get")) {
                long ts = now_ms();
                double cpu = cpu_usage_pct(), mem = mem_usage_pct();
                snprintf(out, sizeof out,
                    "{\"type\":\"ipc_result\",\"cmd\":\"status_get\",\"cookie\":%ld,\"msg\":{"
                    "\"idle\":true,\"usage\":{},\"idle_state\":{\"cpu_usage\":%.2f,"
                    "\"cpu_usage_ts\":%ld,\"mem_usage\":%.2f,\"mem_usage_ts\":%ld,"
                    "\"num_streams\":%ld,\"num_streams_ts\":%ld,\"heap_usage\":0,"
                    "\"heap_usage_ts\":%ld},\"bw\":{},\"vpn_profile_enabled\":%s}}",
                    cookie, cpu, ts, mem, ts, active_streams(), ts, ts,
                    g_vpn ? "true" : "false");
                dc_send_text(dc, out);
            } else if (!strcmp(cmd, "dns")) {
                snprintf(out, sizeof out,
                    "{\"type\":\"ipc_result\",\"cmd\":\"dns\",\"cookie\":%ld,\"msg\":{\"res\":[]}}", cookie);
                dc_send_text(dc, out);
            } else {
                snprintf(out, sizeof out,
                    "{\"type\":\"ipc_error\",\"cmd\":\"%s\",\"cookie\":%ld,\"msg\":\"nd\"}", cmd, cookie);
                dc_send_text(dc, out);
            }
            free(data); continue;
        }
        if (op == 2) {
            if (plen < 8) { free(data); continue; }
            int vfd; memcpy(&vfd, data, 4); vfd = ntohl(vfd);
            int payload_len = plen - 8;
            pthread_mutex_lock(&dc->mtx);
            VfdEnt *e = dc_find(dc, vfd);
            int fd = e ? e->fd : -1;
            if (e) e->rx += payload_len;
            pthread_mutex_unlock(&dc->mtx);
            if (fd > 0 && payload_len > 0) {
                int sent = 0;
                while (sent < payload_len) {
                    int n = write(fd, data + 8 + sent, payload_len - sent);
                    if (n <= 0) { dc_close_vfd(dc, vfd); break; }
                    sent += n;
                }
            }
            dc_send_ack(dc, vfd);
            free(data); continue;
        }
        free(data);
    }
    dc->dead = 1;
    pthread_mutex_lock(&dc->mtx);
    for (int i = 0; i < MAX_VFD; i++) if (dc->tab[i].used) { close(dc->tab[i].fd); dc->tab[i].used = 0; }
    pthread_mutex_unlock(&dc->mtx);
    logt("n%d data conn closed", dc->node->idx);
    dc_release(dc);
    return NULL;
}

static void open_data_conn(NodeCtx *n, const char *host, int port, const char *servername) {
    t_px_type = n->px_type;
    snprintf(t_px_host, sizeof t_px_host, "%s", n->px_host);
    t_px_port = n->px_port;
    WS *ws = ws_connect(host, port, servername);
    if (!ws) { logt("n%d data tunnel gagal", n->idx); return; }
    logt("n%d data tunnel OK %s:%d pin=%s", n->idx, host, port, g_pin_ok ? "MATCH" : "?");
    perr_node(n, "tun_init_success", NULL);
    DataConn *dc = calloc(1, sizeof *dc);
    dc->ws = ws; dc->node = n;
    pthread_mutex_init(&dc->mtx, NULL);
    pthread_mutex_init(&dc->wmtx, NULL);
    dc->refs = 2;
    pthread_t th, pth;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&pth, &attr, pump_thread, dc);
    pthread_create(&th, &attr, dc_thread, dc);
    pthread_attr_destroy(&attr);
}

struct CArg { NodeCtx *n; char host[128]; char sni[128]; int port; };
static void *dc_connect_tramp(void *a) {
    struct CArg *ca = a;
    open_data_conn(ca->n, ca->host, ca->port, ca->sni);
    free(ca);
    return NULL;
}

/* ---------------- main conn per node ---------------- */
static void serve_main(NodeCtx *n, WS *ws) {
    long last_ping = now_ms(), last_hb = now_ms();
    for (;;) {
        if (now_ms() - last_hb >= 60000) { perr_hb(n); last_hb = now_ms(); }
        int op, plen; unsigned char *data = NULL;
        int rc = ws_recv_frame(ws, &op, &data, &plen, 30);
        if (rc == -2) {
            long t = now_ms();
            if (t - last_ping >= 30000) { ws_send_ping(ws); last_ping = t; }
            continue;
        }
        if (rc < 0) { free(data); break; }
        long t = now_ms();
        if (t - last_ping >= 30000) { ws_send_ping(ws); last_ping = t; }
        if (op != 1) { free(data); continue; }
        const char *js = (char *)data;
        char cmd[48]; cmd[0] = 0;
        json_get_str(js, "cmd", cmd, sizeof cmd);
        if (!cmd[0]) { free(data); continue; }
        long cookie = json_get_cookie(js);
        char out[2048];
        if (!strcmp(cmd, "tunnel_init")) {
            snprintf(out, sizeof out,
                "{\"type\":\"ipc_result\",\"cmd\":\"tunnel_init\",\"cookie\":%ld,\"msg\":{"
                "\"arch\":\"arm64\",\"release\":\"debian_12_arm64\",\"platform\":\"node\","
                "\"version\":\"" VERSION "\",\"old_cid\":\"%s\",\"is_tv\":false,"
                "\"appid\":\"" APPID_ALIAS "\",\"partnerid\":\"" PARTNERID "\","
                "\"uuid\":\"%s\",\"ifname\":\"%s\",\"usage\":{},\"consent_ts\":%ld,"
                "\"last_rmt_upd_success\":null,\"vpn_profile_enabled\":%s}}",
                cookie, n->oldcid, n->uuid, g_ifname, n->consent_ts,
                g_vpn ? "true" : "false");
            ws_send_text(ws, out);
            perr_node(n, "20_svc_connected", NULL);
            perr_node(n, "connected", NULL);
            logt("n%d tunnel_init", n->idx);
        } else if (!strcmp(cmd, "cid_set")) {
            char cid[128]; cid[0] = 0;
            json_get_str(js, "cid", cid, sizeof cid);
            if (cid[0]) { strncpy(n->cid, cid, sizeof n->cid - 1);
                FILE *f = fopen(CONFDIR "/oldcid", "w");
                if (f) { fprintf(f, "%s", cid); fclose(f); } }
            snprintf(out, sizeof out,
                "{\"type\":\"ipc_result\",\"cmd\":\"cid_set\",\"cookie\":%ld,\"msg\":null}", cookie);
            ws_send_text(ws, out);
            char infojs[256];
            char *slash = strchr(cid, '/');
            snprintf(infojs, sizeof infojs, "{\"msg\":\"%s\",\"body\":\"{\\\"type\\\":\\\"%s\\\"}\"}",
                     slash ? slash + 1 : cid, g_ifname);
            perr_node(n, "register_client", infojs);
            logt("n%d cid=%s", n->idx, cid);
        } else if (!strcmp(cmd, "status_get")) {
            long ts = now_ms();
            double cpu = cpu_usage_pct(), mem = mem_usage_pct();
            snprintf(out, sizeof out,
                "{\"type\":\"ipc_result\",\"cmd\":\"status_get\",\"cookie\":%ld,\"msg\":{"
                "\"idle\":true,\"usage\":{},\"idle_state\":{\"cpu_usage\":%.2f,"
                "\"cpu_usage_ts\":%ld,\"mem_usage\":%.2f,\"mem_usage_ts\":%ld,"
                "\"num_streams\":%ld,\"num_streams_ts\":%ld,\"heap_usage\":0,"
                "\"heap_usage_ts\":%ld},\"bw\":{},\"vpn_profile_enabled\":%s}}",
                cookie, cpu, ts, mem, ts, active_streams(), ts, ts,
                g_vpn ? "true" : "false");
            ws_send_text(ws, out);
        } else if (!strcmp(cmd, "connect")) {
            char host[128], port_s[16], sni[128];
            host[0] = 0; sni[0] = 0;
            json_get_str(js, "host", host, sizeof host);
            json_get_str(js, "port", port_s, sizeof port_s);
            json_get_str(js, "servername", sni, sizeof sni);
            snprintf(out, sizeof out,
                "{\"type\":\"ipc_result\",\"cmd\":\"connect\",\"cookie\":%ld,\"msg\":null}", cookie);
            ws_send_text(ws, out);
            perr_node(n, "21_svc_tun_ready", NULL);
            long port = strtol(port_s, NULL, 10);
            logt("n%d CONNECT -> %s:%ld sni=%s", n->idx, host, port, sni);
            if (host[0] && port > 0) {
                struct CArg *ca = calloc(1, sizeof *ca);
                ca->n = n;
                strncpy(ca->host, host, 127);
                strncpy(ca->sni, sni[0] ? sni : "client.brdtnet.com", 127);
                ca->port = (int)port;
                pthread_t th;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&th, &attr, dc_connect_tramp, ca);
                pthread_attr_destroy(&attr);
            }
        } else if (!strcmp(cmd, "logs") || !strcmp(cmd, "consent") ||
                   !strcmp(cmd, "tunnel_redirect") || !strcmp(cmd, "tunnel_init_decline")) {
            snprintf(out, sizeof out,
                "{\"type\":\"ipc_result\",\"cmd\":\"%s\",\"cookie\":%ld,\"msg\":null}", cmd, cookie);
            ws_send_text(ws, out);
        } else {
            snprintf(out, sizeof out,
                "{\"type\":\"ipc_error\",\"cmd\":\"%s\",\"cookie\":%ld,\"msg\":\"nd\"}", cmd, cookie);
            ws_send_text(ws, out);
        }
        free(data);
    }
}

static void load_node_state(NodeCtx *n) {
    char path[128], cbuf[64];
    snprintf(path, sizeof path, CONFDIR "/consent");
    if (slurp(path, cbuf, sizeof cbuf)) {
        char *sep = strchr(cbuf, ':');
        if (sep) n->consent_ts = strtol(sep + 1, NULL, 10);
    }
    (void)0;
}

static void *node_main(void *arg) {
    NodeCtx *n = arg;
    load_node_state(n);
    int fail = 0;
    for (;;) {
        if (!n->px_type && g_pxn) {
            if (px_acquire(n) < 0) { sleep(5); continue; }
        }
        t_px_type = n->px_type;
        snprintf(t_px_host, sizeof t_px_host, "%s", n->px_host);
        t_px_port = n->px_port;
        WS *ws = ws_connect(MAIN_HOST, MAIN_PORT, MAIN_HOST);
        if (!ws) {
            fail++;
            if (n->px_type) { logt("n%d proxy mati (%s:%d) — ganti", n->idx, n->px_host, n->px_port); px_drop(n); sleep(2); continue; }
            sleep(5 + (fail > 6 ? 30 : fail * 3));
            continue;
        }
        if (n->px_type) logt("n%d lewat proxy %s:%d", n->idx, n->px_host, n->px_port);
        logt("n%d wss OK pin=%s uuid=%s", n->idx, g_pin_ok ? "MATCH" : "?", n->uuid);
        fail = 0;
        perr_node(n, "init", NULL);
        perr_node(n, "05_svc_init", NULL);
        perr_node(n, "10_show_dialog", NULL);
        perr_node(n, "opt_in", NULL);
        perr_node(n, "15_choose_peer", NULL);
        serve_main(n, ws);
        ws_close(ws);
        sleep(5);
    }
    return NULL;
}

/* ---------------- registry ---------------- */
static int load_registry(char uuids[][42], int max) {
    FILE *f = fopen(REGFILE, "r");
    if (!f) return 0;
    int c = 0;
    while (c < max && fscanf(f, "%41s", uuids[c]) == 1) {
        if (strncmp(uuids[c], "sdk-node-", 9)) continue;
        c++;
    }
    fclose(f);
    return c;
}

static void add_registry(const char *uuid) {
    FILE *f = fopen(REGFILE, "a");
    if (f) { fprintf(f, "%s\n", uuid); fclose(f); }
}

int main(int argc, char **argv) {
    srand(time(NULL) ^ getpid());
    socks_init();
    detect_ifname();
    g_vpn = vpn_profile_enabled();
    SSL_library_init();
    SSL_load_error_strings();

    if (argc >= 2 && !strcmp(argv[1], "--new")) {
        int count = argc >= 3 ? atoi(argv[2]) : 1;
        for (int i = 0; i < count; i++) {
            char uuid[42];
            gen_uuid(uuid);
            if (register_device(uuid) == 0) {
                add_registry(uuid);
                printf("NODE BARU: %s\n  link: https://earnapp.com/r/%s\n",
                       uuid, uuid);
            } else printf("NODE %s: register GAGAL\n", uuid);
        }
        return 0;
    }

    int limit = 0;
    if (argc >= 3 && !strcmp(argv[1], "-n")) limit = atoi(argv[2]);

    char uuids[64][42];
    int ncount = load_registry(uuids, 64);
    if (limit > 0 && limit < ncount) ncount = limit;
    if (!ncount) { fprintf(stderr, "registry kosong — jalankan 'earnappd --new 1' dulu\n"); return 1; }

    logt("=== earnappd v2 MULTI — %d node, ifname=%s vpn=%d ===", ncount, g_ifname, g_vpn);
    {
        pthread_t pxt;
        if (pthread_create(&pxt, NULL, px_watch, NULL) == 0) pthread_detach(pxt);
    }
    NodeCtx *ctxs = calloc(ncount, sizeof(NodeCtx));
    for (int i = 0; i < ncount; i++) {
        strncpy(ctxs[i].uuid, uuids[i], sizeof ctxs[i].uuid - 1);
        snprintf(ctxs[i].ifname, sizeof ctxs[i].ifname, "%s", g_ifname);
        ctxs[i].idx = i;
        pthread_mutex_init(&ctxs[i].mtx, NULL);
    }
    /* stagger start 1 dtk antar node biar gak serentak */
    for (int i = 0; i < ncount; i++) {
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&th, &attr, node_main, &ctxs[i]);
        pthread_attr_destroy(&attr);
        sleep(1);
    }
    for (;;) sleep(3600);
    return 0;
}

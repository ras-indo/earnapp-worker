# earnapp-worker

Worker multi-node EarnApp (C, ~1,2 MB RAM/node) yang dijalankan di GitHub Actions runner.

## Isi
- `cworker/earnappd.c` — worker multi-node: 1 thread per node, WebSocket + mux relay, heartbeat.
- `.github/workflows/worker.yml` — build + jalankan, state dipulihkan dari GitHub Secrets.

## Secrets
| Name | Isi |
|---|---|
| `NODES_TXT` | daftar uuid, satu per baris |
| `CONSENT` | timestamp consent, format `1:<epoch_ms>` |

## Cara jalan
Workflow `worker` dipicu manual (`workflow_dispatch`) atau otomatis tiap 5 jam.
Job dibatasi 355 menit; worker stop sendiri di menit ke-335 (`timeout 20100`), sisanya untuk pencarian pool.
Run berikutnya sudah antre di concurrency group `earnapp-worker`, jadi chain-nya nyambung.

## Mode US-only
Worker **hanya** mau jalan lewat proxy yang sudah diverifikasi exit country-nya US.
- `cworker/proxy_pool.py` menguji proxy, mengecek exit IP, lalu lookup country via ip-api.
  Hanya proxy dengan `countryCode=US` yang ditulis ke `/etc/earnapp/proxies.txt`.
  Country `ID`/`INDONESIA` masuk blocklist eksplisit dan tidak pernah dipakai.
- File pool diberi header `# earnapp pool country=US block=ID,INDONESIA ...`; `earnappd`
  menolak pool yang tidak punya `country=US` + `block=ID` saat `EARNAPP_US_ONLY=1`.
- Koneksi langsung (IP runner GitHub) dan `EARNAPP_SOCKS`/Tor diblokir di mode ini.
- Kalau pool US kosong, worker menunggu; workflow berhenti di awal kalau pool tetap kosong
  setelah 2 percobaan, supaya tidak menghabiskan menit Actions tanpa hasil.

## Batasan yang perlu diingat
- Runner GitHub = IP datacenter (Azure). EarnApp memblokir IP DCH; node bisa connect tapi earnings kemungkinan 0.
- Batas keras job GitHub-hosted: 6 jam.
- Repo private: kuota menit Actions terbatas; job ini ~345 menit per run, ~5 run/hari.

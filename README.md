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
Job dibatasi 355 menit; worker stop sendiri di menit ke-345 (`timeout 20700`).
Run berikutnya sudah antre di concurrency group `earnapp-worker`, jadi chain-nya nyambung.

## Batasan yang perlu diingat
- Runner GitHub = IP datacenter (Azure). EarnApp memblokir IP DCH; node bisa connect tapi earnings kemungkinan 0.
- Batas keras job GitHub-hosted: 6 jam.
- Repo private: kuota menit Actions terbatas; job ini ~345 menit per run, ~5 run/hari.

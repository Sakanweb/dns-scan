# dns-scan

Local DNS / subdomain inventory tool (Yii3 + MariaDB). Needs Docker. `make up` also needs Python 3 for the port check.

| container | role | host port |
|---|---|---|
| migrate | one-shot schema | not published |
| nginx | UI | `HTTP_PORT` from `.env` |
| php | PHP-FPM | not published |
| worker | one pipeline stage per tick | not published |
| mariadb | data | `MYSQL_PORT` from `.env` |

`HTTP_PORT` and `MYSQL_PORT` have **no defaults**. `.env.example` leaves them empty. You must set both in `.env` to free ports on your machine. `make check-ports` looks at other Docker containers (and host listeners) and refuses to start on a conflict.

## Start

```bash
# first clone: make up copies .env.example -> .env
# set HTTP_PORT and MYSQL_PORT (they are empty on purpose)
make up
open http://127.0.0.1:<HTTP_PORT>/scans
```

`make up` copies `.env.example` to `.env` if missing, then runs `make check-ports`. Empty or colliding ports abort the start. The checker prints free candidates when it refuses.

UI queues a job and shows stage progress. Worker is a separate process: it claims the next `scan_run` row and runs **one** stage, then writes `stage` / `stage_message` / `context_json` back to MariaDB. Refreshing the page only reads that row.

The **Worker ON / OFF** button on `/scans` pauses claiming. The container stays up. A stage already in flight finishes; queued jobs wait until you turn the worker back on.

## Job pipeline

```
queued → dns_base → passive → wordlist → resolve → http_probe → finalize → done
```

`passive` and `http_probe` are skipped when those flags are off on the job.

Later schema changes: `make migrate` (runs `php yii migrate` in the php container). One SQL file = one table, under `app/migrations/`.

## CLI

```bash
make scan T=example.com
```

This enqueues a run and waits until the **worker** finishes it. If the worker is paused or down, the command times out.

## Commands

```bash
make up / down / restart / logs / worker-logs / shell / db / migrate / check-ports / ps
```

## Scan settings

| env | default | meaning |
|---|---|---|
| `HTTP_PORT` | *(empty, required)* | host port for the UI |
| `MYSQL_PORT` | *(empty, required)* | host port for MariaDB |
| `DNS_THREADS` | `40` | parallel dig workers |
| `HTTP_TIMEOUT` | `10` | HTTP probe timeout (seconds) |
| `DNS_TIMEOUT` | `3` | dig `+time` (seconds) |
| `DNS_RESOLVER` | `1.1.1.1` | dig `@resolver` (avoids flaky Docker DNS) |

# sslmon

<p align="center"><img src="./sslmon.png" alt="sslmon"></p>

Certificate Transparency monitoring for a domain. Point it at a domain and it
lists the TLS certificates that exist; ask it to `watch` and it reports new ones
as they're issued.

```sh
sslmon example.com               # list its certificates (last 2 years)
sslmon example.com --since 3m    # only the last 3 months
sslmon example.com -i            # browse them in an interactive list
sslmon example.com -o json       # machine output for pipes
sslmon watch example.com         # alert me to newly-issued certs, live
```

That's the whole interface: **`sslmon <domain>`** to look, **`sslmon watch
<domain>`** to monitor.

## How it works

CT logs are append-only and **cannot be searched by domain**, so the two jobs
use different sources:

- **Listing** (`sslmon <domain>`) queries [crt.sh](https://crt.sh) — a
  domain-searchable index of logged certificates — over its public PostgreSQL
  interface, and caches the result locally so repeats are instant.
- **Watching** (`sslmon watch`) tails the CT logs directly with Google's
  official client, reporting certificates logged after it starts.

## Build

```sh
go build -o sslmon .
```

Requires Go 1.25+.

## Listing certificates

```sh
sslmon example.com                 # last 2 years (cached after the first run)
sslmon example.com --since 1y      # last year only
sslmon example.com --since 90d     # last 90 days
sslmon example.com --exact         # apex only, ignore subdomains
sslmon example.com --refresh       # ignore the cache, re-fetch from crt.sh
sslmon example.com -i              # interactive, filterable list (press / to search)
```

`--since` takes a relative window: `<N>d`, `<N>w`, `<N>m` (months) or `<N>y`.

With no domain, `sslmon` works on the local cache instead of crt.sh — handy for
browsing everything you've collected, offline:

```sh
sslmon -i                          # browse the whole cache interactively
sslmon -o tsv | sort               # dump the whole cache for piping
```

(`sslmon`, `sslmon query <domain>` and `sslmon list <domain>` are all accepted;
the bare form is just the default.)

## Watching for new certificates

```sh
sslmon watch example.com           # tail logs until Ctrl-C
sslmon watch example.com --once    # catch up since last run and exit (cron)
sslmon watch example.com --logs cloudflare,google   # only some operators
```

On first run `watch` records each log's current size and reports only
certificates logged after that. A checkpoint file lets `--once` resume exactly
where it left off. A log that returns HTTP 429 is paced down (not hammered)
rather than retried hard.

## Output and piping

Every listing command takes `--output`/`-o` (`text`, `tsv`, or `json`).
Progress goes to stderr and only certificate data to stdout, so pipelines stay
clean. TSV is headerless: `not_before`, `not_after`, `name`, `names`, `issuer`,
`source`, `reference`, `fingerprint`.

```sh
# certificates per issuer
sslmon example.com -o tsv | cut -f5 | sort | uniq -c | sort -rn

# unique names across everything cached
sslmon -o tsv | cut -f4 | tr ',' '\n' | sort -u

# certs expiring before a date, as JSON
sslmon example.com -o json | jq 'select(.not_after < "2026-09-01")'
```

Flags are GNU-style (`--long` or `-o`) and may appear before or after the
domain.

## Layout

```
main.go                  entry point (shim into package cmd)
cmd/                     the CLI
  cmd.go                 dispatch + usage
  list.go                default action: list / browse (crt.sh + cache)
  watch.go               watch command
  logs.go                logs command
  output.go              unified Row + text/tsv/json writers
  tui.go                 the Bubble Tea interactive list
internal/crtsh           crt.sh PostgreSQL client (pgx, fast CTE query)
internal/certcache       cache crt.sh results in a local JSON file
internal/loglist         fetch the Chrome CT log list, select usable RFC 6962 logs
internal/monitor         tail logs, parse entries, match the domain (the engine)
internal/state           persist per-log checkpoints to a JSON file
```

## Known limitations

- **Listing depends on crt.sh.** crt.sh is a free, best-effort, frequently
  overloaded service run by Sectigo, and its public endpoint is a read replica
  that cancels slow queries. `sslmon` keeps the query fast, retries on failure,
  and caches results — but a cold lookup can still occasionally fail. Watch mode
  uses only the official CT log client.
- **Tiled logs are not watched.** Newer "static CT API" (tiled) logs use a
  different protocol than RFC 6962; watch mode tails every *usable RFC 6962* log
  and skips tiled ones. (Listing is unaffected — crt.sh indexes them.)
- **Watch mode is forward-only.** It reports certificates logged after it
  starts; list a domain for the historical picture.
- **STH signatures are not verified.** `sslmon` trusts the TLS connection to
  each log rather than verifying signed tree heads against pinned keys. Fine for
  monitoring; not an auditing tool.

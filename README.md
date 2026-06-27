# sslmon

<p align="center"><img src="./sslmon.png" alt="sslmon"></p>

Certificate Transparency monitoring for a domain. Point it at a domain and it
lists the TLS certificates that exist; ask it to `watch` and it reports new ones
as they're issued.

```sh
sslmon example.com               # matching subdomains, newest first (last year)
sslmon example.com -since 3m     # only the last 3 months
sslmon example.com -i            # browse them in an interactive list
sslmon example.com -f json       # full machine-readable records for pipes
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

Both the cache and the watch checkpoints live in a single file at
`~/.sslmon.json` (override with `-cache`).

## Build

```sh
go build -o sslmon .
```

Requires Go 1.25+.

## Listing certificates

```sh
sslmon example.com                 # last year (cached after the first run)
sslmon example.com -since 90d      # last 90 days
sslmon example.com -only-domain    # apex only, ignore subdomains
sslmon example.com -valid          # only certificates valid right now
sslmon example.com -refetch        # ignore the cache, re-fetch from crt.sh
sslmon example.com -i              # interactive, filterable list (press / to search)
```

`-since` takes a relative window: `<N>d`, `<N>w`, `<N>m` (months) or `<N>y`
(default `1y`). Cached results stay fresh for a day (`-cache-ttl`).

`sslmon` enumerates a domain and its subdomains. Substring/keyword "wildcard
domain discovery" (finding unrelated domains that merely mention a string) is out
of scope — see *Known limitations*.

With no domain, `sslmon` works on the local cache instead of crt.sh — handy for
browsing everything you've collected, offline:

```sh
sslmon -i                          # browse the whole cache interactively
sslmon -f txt                      # dump every cached name, one per line
```

(`sslmon`, `sslmon query <domain>` and `sslmon list <domain>` are all accepted;
the bare form is just the default.)

## Watching for new certificates

```sh
sslmon watch example.com           # tail logs until Ctrl-C
sslmon watch example.com -once     # catch up since last run and exit (cron)
sslmon watch example.com -logs cloudflare,google   # only some operators
```

On first run `watch` records each log's current size and reports only
certificates logged after that. The checkpoints in `~/.sslmon.json` let `-once`
resume exactly where it left off. A log that returns HTTP 429 is paced down (not
hammered) rather than retried hard.

## Output and piping

Choose the format with `-f`/`-format`:

- **`txt`** (default) — a clean, sorted, de-duplicated list of names, one per
  line. By default just the names matching your query (subdomain enumeration);
  add `-all` to emit every SAN/CN on the matched certificates.
- **`tsv`** — one headerless line per certificate: `not_before`, `not_after`,
  `name`, `names`, `issuer`, `source`, `reference`, `fingerprint`.
- **`json`** — newline-delimited JSON, one full record per certificate.

`-o <file>` writes results to a file instead of stdout. Progress goes to stderr
and only certificate data to stdout, so pipelines stay clean.

```sh
# a clean subdomain list
sslmon example.com                 # (txt is the default)

# every name on every matched cert
sslmon example.com -all

# certificates per issuer
sslmon example.com -f tsv | cut -f5 | sort | uniq -c | sort -rn

# certs expiring before a date, as JSON
sslmon example.com -f json | jq 'select(.not_after < "2026-09-01")'
```

Flags use Go's standard `flag` package (`-flag` or `--flag`) and may appear
before or after the domain.

## Layout

```
main.go                  entry point (shim into package cmd)
cmd/                     the CLI
  cmd.go                 dispatch + usage
  list.go                default action: list / browse (crt.sh + cache)
  watch.go               watch command
  logs.go                logs command
  output.go              unified Row + txt/tsv/json writers
  tui.go                 the Bubble Tea interactive list
internal/crtsh           crt.sh PostgreSQL client (pgx, fast indexed query)
internal/store           single JSON file: crt.sh cache + watch checkpoints
internal/atomicfile      atomic (temp-file + rename) file writes
internal/loglist         fetch the Chrome CT log list, select usable RFC 6962 logs
internal/monitor         tail logs, parse entries, match the domain (the engine)
```

## Known limitations

- **Listing depends on crt.sh.** crt.sh is a free, best-effort, frequently
  overloaded service run by Sectigo, and its public endpoint is a read replica
  that cancels slow queries. `sslmon` keeps the query fast, retries on failure,
  and caches results — but a cold lookup can still occasionally fail. Watch mode
  uses only the official CT log client.
- **No keyword/substring domain discovery.** `sslmon` finds the queried domain
  and its subdomains, not unrelated domains that merely contain a keyword. crt.sh's
  public endpoints can't serve substring search reliably (the Postgres standby
  has no substring index and cancels the scan; the web API times out on popular
  keywords), so it's intentionally left to dedicated tooling (e.g. a paid CT API
  like Censys or SecurityTrails).
- **Tiled logs are not watched.** Newer "static CT API" (tiled) logs use a
  different protocol than RFC 6962; watch mode tails every *usable RFC 6962* log
  and skips tiled ones. (Listing is unaffected — crt.sh indexes them.)
- **Watch mode is forward-only.** It reports certificates logged after it
  starts; list a domain for the historical picture.
- **STH signatures are not verified.** `sslmon` trusts the TLS connection to
  each log rather than verifying signed tree heads against pinned keys. Fine for
  monitoring; not an auditing tool.

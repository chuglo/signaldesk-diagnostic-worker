# signaldesk-diagnostic-worker

Secure Python 3.11 Redis Streams consumer for `diagnostic.requested.v1` events.
The worker treats Redis as an identifier-only transport, claims and re-fetches
job scope from the SignalDesk control API, runs a bounded direct-IP TCP/HTTP(S)
diagnostic with DNS-rebinding and SSRF defenses, and acknowledges only after an
authoritative completion is accepted.

## Runtime configuration

All settings use the `SIGNALDESK_DIAGNOSTIC_WORKER_` prefix. These values are
required:

- `REDIS_URL` — `redis://` or `rediss://` URL for the unauthenticated standalone
  Redis primary, without credentials, query, or fragment.
- `CONTROL_API_BASE_URL` — HTTP(S) control API base URL without credentials.
- `DIAGNOSTIC_WORKER_SERVICE_CREDENTIAL` — at least 32 non-whitespace ASCII
  characters.
- `CONSUMER_NAME` — unique consumer identity using letters, digits, `.`, `_`,
  `:`, or `-`.
- `DNS_NAMESERVER` — explicit IPv4 or IPv6 recursive resolver address. This is
  operator authority and may be a private runtime resolver such as Docker's
  `127.0.0.11`; the worker never reads host resolver configuration.

Stream, group, DLQ, delivery, timeout, batch, event, and response-header limits
have fail-closed bounded defaults in `Settings`.
`DIAGNOSTIC_TOTAL_TIMEOUT_SECONDS` bounds each complete DNS/connect/TLS/write/read
probe and defaults to 10 seconds.
`STALE_IDLE_MS` must exceed two control API timeout windows plus the complete
diagnostic timeout and a deterministic 100ms safety margin. Atomic Redis owner
and delivery-generation checks remain authoritative if ownership changes.

## Run

```bash
uv sync --locked
uv run signaldesk-diagnostic-worker
```

Use `--once` to reclaim or read and process at most one bounded batch. SIGTERM
and SIGINT set a stop event; Redis blocking and all API/socket operations are
time-bounded.

## Test

```bash
uv run pytest -q
```

Consumer integration tests start the pinned standalone Redis image
`redis@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99`
and remove it after the test session.

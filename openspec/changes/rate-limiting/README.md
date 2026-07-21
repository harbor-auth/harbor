# rate-limiting

Redis-backed per-client + per-IP hot-path rate limiting middleware (sliding-window / token-bucket) protecting /introspect, /token, and /authorize with 429 + Retry-After, failing open on Redis outage.

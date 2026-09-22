# Reverse proxy credential verification

The `ProxyService.Authenticate` RPC limits PIN and password checks before
verifying their Argon2 hashes. Both methods share one budget per account and
service: a burst of five checks, replenishing one check every six seconds
(ten per minute). Successful and failed checks consume the budget. Account
scope and service lookup run before the limiter.

Excess checks receive gRPC `ResourceExhausted` with a standard `RetryInfo` delay.
Updated proxies translate it to HTTP 429 and `Retry-After`. Older proxies show
an authentication-service error but cannot bypass the Management limit.

Budgets are held in memory per Management process and reset on restart. Proxy
replicas reaching the same Management process share its budgets. Multiple
Management processes have independent budgets; this is not a cluster-wide
limit. At most 4,096 service budgets are retained, with idle entries expiring
after fifteen minutes. Capacity exhaustion denies new checks until entries
expire. Closing the server releases the retained state.

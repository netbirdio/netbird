# PIN and password authentication limits

PIN and password credentials are accepted only in a URL-encoded
(`application/x-www-form-urlencoded`) POST body. Query-string credentials,
multipart and other body encodings, and credentials on other HTTP methods are
ignored. The encoding is restricted because it is the one AppSec inspection can
redact before mirroring a request to the engine.

The proxy permits a burst of five credential checks per account and service,
then replenishes one check every six seconds (ten per minute). PIN and password
checks share the same budget. Five failed checks from one client IP in a
rolling five-minute window block that source for fifteen minutes. In-flight checks
reserve failure slots; blocked requests do not extend the cooldown. Successful
authentication clears that source's failure history. Infrastructure failures
consume the service budget without counting as incorrect credentials.

Throttled requests return HTTP 429 with a `Retry-After` delay in seconds. The
login page displays that delay. Existing authenticated sessions and other
authentication methods do not consume these credential budgets.

The client IP comes from the existing trusted-proxy resolution. Deployments
behind a load balancer must configure trusted proxies correctly; otherwise
visitors share the load balancer's source budget. Visitors behind the same NAT
also share a source budget for a service.

State is held in memory per proxy process and resets on restart. Multiple
replicas have independent budgets. State is bounded to 16,384 source entries and
4,096 service entries; when capacity is exhausted, new checks are denied until
idle entries expire. Active blocks are never evicted to admit a new source.

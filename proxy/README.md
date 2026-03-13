# Netbird Reverse Proxy

The NetBird Reverse Proxy is a separate service that can act as a public entrypoint to certain resources within a NetBird network.
At a high level, the way that it operates is:
- Configured routes are communicated from the Management server to the proxy.
- For each route the proxy creates a NetBird connection to the NetBird Peer that hosts the resource.
- When traffic hits the proxy at the address and path configured for the proxied resource, the NetBird Proxy brings up a relevant authentication method for that resource.
- On successful authentication the proxy will forward traffic onwards to the NetBird Peer.

Proxy Authentication methods supported are:
- No authentication
- Oauth2/OIDC
- Emailed Magic Link
- Simple PIN
- HTTP Basic Auth Username and Password

## Management Connection and Authentication

The Proxy communicates with the Management server over a gRPC connection.
Proxies act as clients to the Management server, the following RPCs are used:
- Server-side streaming for proxied service updates.
- Client-side streaming for proxy logs.

To authenticate with the Management server, the proxy server uses Machine-to-Machine OAuth2.
If you are using the embedded IdP //TODO: explain how to get credentials.
Otherwise, create a new machine-to-machine profile in your IdP for proxy servers and set the relevant settings in the proxy's environment or flags (see below).

## User Authentication

When a request hits the Proxy, it looks up the permitted authentication methods for the Host domain.
If no authentication methods are registered for the Host domain, then no authentication will be applied (for fully public resources).
If any authentication methods are registered for the Host domain, then the Proxy will first serve an authentication page allowing the user to select an authentication method (from the permitted methods) and enter the required information for that authentication method.
If the user is successfully authenticated, their request will be forwarded through to the Proxy to be proxied to the relevant Peer.
Successful authentication does not guarantee a successful forwarding of the request as there may be failures behind the Proxy, such as with Peer connectivity or the underlying resource.

## Custom Domains

Custom domains allow services to be reached at your own domain name instead of a proxy-assigned subdomain.
Both wildcard and non-wildcard custom domains are supported:

- **Non-wildcard:** Register `example.com` and expose at the apex (`example.com`) or subdomains (`app.example.com`, `api.example.com`, etc.).
- **Wildcard:** Register `*.example.com` to match any subdomain of `example.com` (e.g. `app.example.com`, `api.example.com`). When both a non-wildcard and a wildcard could match (e.g. `example.com` and `*.example.com`), the non-wildcard (exact) match is used.

### DNS Setup for Custom Domains

Ownership of a custom domain is verified via a CNAME record on the `validation` subdomain.
For any custom domain (including apex and wildcard), create:

```
validation.example.com.  CNAME  <proxy-cluster-address>.
```

For a wildcard custom domain like `*.example.com`, use the same validation record at the apex: `validation.example.com` → `<proxy-cluster-address>`.

To route traffic to the proxy, configure DNS for the service domain:

- **Subdomains** (e.g., `app.example.com`): Create a CNAME record pointing to the proxy cluster address.
- **Apex domains** (e.g., `example.com`): CNAME records at the zone apex are not permitted. Instead, use one of:
  - An `A` / `AAAA` record pointing to the proxy's IP address.
  - An `ALIAS` or `ANAME` record (if your DNS provider supports it) pointing to the proxy cluster address.

When multiple custom domains could match a service domain (e.g., both `example.com` and `*.example.com`, or both `example.com` and `app.example.com`), the most specific match is used: exact (non-wildcard) matches take precedence over wildcard matches for the same apex, and longer suffixes win otherwise.

## TLS

Due to the authentication provided, the Proxy uses HTTPS for its endpoint, even if the underlying service is HTTP.
Certificate generation can either be via ACME (by default, using Let's Encrypt, but alternative ACME providers can be used) or through certificate files.
When not using ACME, the proxy server attempts to load a certificate and key from the files `tls.crt` and `tls.key` in a specified certificate directory.
When using ACME, the proxy server will store generated certificates in the specified certificate directory.


## Auth UI

The authentication UI is a Vite + React application located in the `web/` directory. It is embedded into the Go binary at build time.

To build the UI:
```bash
cd web
npm install
npm run build
```

For UI development with hot reload (served at http://localhost:3031):
```bash
npm run dev
```

The built assets in `web/dist/` are embedded via `//go:embed` and served by the `web.ServeHTTP` handler.

## Configuration

NetBird Proxy deployment configuration is via flags or environment variables, with flags taking precedence over the environment.
The following deployment configuration is available:

| Flag             | Env                              | Purpose                                                                                                                            | Default                                            |
|------------------|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| `-debug`         | `NB_PROXY_DEBUG_LOGS`            | Enable debug logging                                                                                                               | `false`                                            |
| `-mgmt`          | `NB_PROXY_MANAGEMENT_ADDRESS`    | The address of the management server for the proxy to get configuration from.                                                      | `"https://api.netbird.io:443"`                     |
| `-addr`          | `NB_PROXY_ADDRESS`               | The address that the reverse proxy will listen on.                                                                                 | `":443`                                            |
| `-url`           | `NB_PROXY_URL`                   | The URL that the proxy will be reached at (where endpoints will be CNAMEd to). If unset, this will fall back to the proxy address. | `"proxy.netbird.io"`                               |
| `-cert-dir`      | `NB_PROXY_CERTIFICATE_DIRECTORY` | The location that certificates are stored in.                                                                                      | `"./certs"`                                        |
| `-acme-certs`    | `NB_PROXY_ACME_CERTIFICATES`     | Whether to use ACME to generate certificates.                                                                                      | `false`                                            |
| `-acme-addr`     | `NB_PROXY_ACME_ADDRESS`          | The HTTP address the proxy will listen on to respond to HTTP-01 ACME challenges                                                    | `":80"`                                            |
| `-acme-dir`      | `NB_PROXY_ACME_DIRECTORY`        | The directory URL of the ACME server to be used                                                                                    | `"https://acme-v02.api.letsencrypt.org/directory"` |
| `-oidc-id`       | `NB_PROXY_OIDC_CLIENT_ID`        | The OAuth2 Client ID for OIDC User Authentication                                                                                  | `"netbird-proxy"`                                  |
| `-oidc-secret`   | `NB_PROXY_OIDC_CLIENT_SECRET`    | The OAuth2 Client Secret for OIDC User Authentication                                                                              | `""`                                               |
| `-oidc-endpoint` | `NB_PROXY_OIDC_ENDPOINT`         | The OAuth2 provider endpoint for OIDC User Authentication                                                                          | `"https://api.netbird.io/oauth2"`                  |
| `-oidc-scopes`   | `NB_PROXY_OIDC_SCOPES`           | The OAuth2 scopes for OIDC User Authentication, comma separated                                                                    | `"openid,profile,email"`                           |

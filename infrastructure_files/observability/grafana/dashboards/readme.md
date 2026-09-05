## Dashboard variables

1. **datasource**: Select Prometheus server
2. **cluster**: Filter NetBird instances by cluster
3. **environment**: Filter by environment (dev, staging, UAT, prod) 
4. **job**: Select target NetBird instance if multiple are running
5. **host**: Filter metrics by host


NOTE:
- Your installation may have a subset of these variables.
- The dashboard expects `exported_endpoint` instead of `endpoint` in HTTP request metrics. 
## Envoy load balancer dashboard (`envoy.json`)

Covers the Envoy instances in front of NetBird. It is built for one question:
*when the load balancers are under pressure, where is the pressure coming from?*

Read the rows in order — each one rules out a layer:

1. **Saturation and backpressure** — is Envoy itself the limit? Connection
   rejections, the overload manager, circuit breakers and the upstream pending
   queue all show Envoy shedding load before the backends are even involved.
   Queue depth and circuit breaker headroom move first, well before latency does.
2. **Latency** — *Time spent inside Envoy* is downstream p99 minus upstream p99.
   If it grows while upstream p99 stays flat, the load balancer is the bottleneck;
   if both grow together, the backends are.
3. **Errors and retries** — separates Envoy's own 503s from backend failures, and
   shows whether retries are amplifying load on a struggling upstream.
4. **Upstream health and load balancing** — shrinking membership and outlier
   ejections concentrate the same traffic on fewer hosts, which is a common cause
   of pressure that looks like a traffic spike. *LB panic mode* firing means too
   few healthy hosts remain and Envoy is balancing across unhealthy ones too.
5. **Envoy process health** — memory, watchdog misses (the clearest CPU-starvation
   signal: a blocked event loop stalls every request on that worker), restarts and
   the xDS control plane connection.

### Assumptions

- Envoy exposes stats via the Prometheus stats sink (`/stats/prometheus`), giving
  the standard `envoy_` metric names and the `envoy_cluster_name`,
  `envoy_response_code_class` and `envoy_http_conn_manager_prefix` labels.
- Two extra variables beyond the ones listed above:
  - **upstream**: filters by `envoy_cluster_name` (the Envoy upstream cluster).
    Distinct from **cluster**, which stays the NetBird deployment cluster.
  - **host**: the Envoy instance, resolved from `envoy_server_live`.
- Circuit breaker panels read the `default` priority
  (`envoy_cluster_circuit_breakers_default_*`). Add the `high` priority series if
  your routes use it.
- Overload manager panels assume the default resource monitor names
  (`fixed_heap`, `global_downstream_max_connections`). They stay empty if the
  overload manager is not configured — worth configuring, since it is what keeps
  Envoy from OOMing under exactly this kind of pressure.

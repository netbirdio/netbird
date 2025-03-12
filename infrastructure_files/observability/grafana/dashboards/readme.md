## Dashboard variables

1. **datasource**: Select Prometheus server
2. **cluster**: Filter NetBird instances by cluster
3. **environment**: Filter by environment (dev, staging, UAT, prod) 
4. **job**: Select target NetBird instance if multiple are running
5. **host**: Filter metrics by host


NOTE:
- Your installation may have a subset of these variables.
- The dashboard expects `exported_endpoint` instead of `endpoint` in HTTP request metrics. 
# FortiAnalyzer Dataset SQL Reference

## Example: Top Blocked C&C Connections
```sql
SELECT
  srcip,
  dstip,
  hostname,
  service,
  COUNT(*) AS total_hits
FROM
  $log
WHERE
  $filter
  AND utmevent IN ('virus', 'botnet', 'ips')
  AND action IN ('blocked', 'dropped')
GROUP BY
  srcip, dstip, hostname, service
ORDER BY
  total_hits DESC
LIMIT 20;
```
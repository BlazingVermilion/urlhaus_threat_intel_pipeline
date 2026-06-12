# Sample SQLite Investigation Queries

After running the pipeline, open the generated SQLite database:

```bash
sqlite3 outputs/demo/threat_intel.db
```

## Count indicators by status

```sql
SELECT url_status, COUNT(*) AS count
FROM indicators
GROUP BY url_status
ORDER BY count DESC;
```

## Find online indicators hosted directly on IP addresses

```sql
SELECT id, dateadded_utc, host, port, tags, url
FROM indicators
WHERE url_status = 'online'
  AND host_type = 'ip'
ORDER BY dateadded_utc DESC
LIMIT 20;
```

## Top ports in the feed

```sql
SELECT port, COUNT(*) AS count
FROM indicators
WHERE port IS NOT NULL
GROUP BY port
ORDER BY count DESC
LIMIT 20;
```

## Top reporters

```sql
SELECT reporter, COUNT(*) AS count
FROM indicators
GROUP BY reporter
ORDER BY count DESC
LIMIT 20;
```

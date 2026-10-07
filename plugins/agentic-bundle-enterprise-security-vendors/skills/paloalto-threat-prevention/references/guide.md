# Palo Alto Threat Prevention Profile Reference

## Best Practice Profile Actions
- **Anti-Spyware Profile**: Action on Critical/High/Medium -> `reset-both`; Enable DNS Sinkhole to Palo Alto Sinkhole IP.
- **Vulnerability Protection Profile**: Action on Critical/High -> `reset-both`; Action on Medium -> `reset-server` or `default`.
- **WildFire Analysis Profile**: Forward all file types (`pe`, `apk`, `pdf`, `ms-office`, `jar`, `flash`, `archive`) to WildFire cloud.
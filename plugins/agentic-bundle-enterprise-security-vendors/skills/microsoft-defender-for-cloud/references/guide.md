# Microsoft Defender for Cloud Reference

## REST API Endpoints & ARM Templates
- Assessment API: `GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01`
- Secure Score API: `GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01`
- Regulatory Compliance: `GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview`

## CLI Commands
```bash
# Get overall Secure Score
az security secure-scores list --output table

# List active high-severity security recommendations
az security assessment list --query "[?status.code=='Unhealthy' && metadata.severity=='High'].{Name:displayName, Resource:resourceDetails.Id}" --output table

# List attack paths
az rest --method get --url "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/attackPaths?api-version=2023-09-01-preview"
```
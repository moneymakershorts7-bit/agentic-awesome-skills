# FortiSIEM Rule Structure Reference

## Rule Logic Definition Example
- **Condition 1**: `Event Type = 'Win-Security-4625'` (Failed Login), Count >= 5 in 5 minutes grouped by `Target User`.
- **Condition 2**: `Event Type = 'Win-Security-4624'` (Successful Login), Count >= 1 within 2 minutes after Condition 1 for same `Target User`.
- **Severity**: High (8 / 10).
- **Action**: Trigger Incident, Send Webhook to SOC ticketing system.
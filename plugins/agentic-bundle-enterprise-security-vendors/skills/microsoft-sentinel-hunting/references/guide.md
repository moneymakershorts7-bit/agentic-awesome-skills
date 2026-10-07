# Microsoft Sentinel KQL Reference

## Core Threat Hunting Queries

### 1. Detect Suspicious Password Spray across Entra ID
```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in (50126, 50053) // Invalid password or locked account
| summarize FailedCount = count(), TargetUsers = dcount(UserPrincipalName), UsersList = make_set(UserPrincipalName, 20) by IPAddress, Location
| where TargetUsers >= 10 and FailedCount >= 20
| project IPAddress, Location, TargetUsers, FailedCount, UsersList
```

### 2. Detect Suspicious Process Execution with Encoded PowerShell
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where Process has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-ep bypass")
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
```
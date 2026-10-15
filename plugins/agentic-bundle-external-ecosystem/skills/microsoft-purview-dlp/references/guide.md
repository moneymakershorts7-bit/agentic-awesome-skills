# Microsoft Purview DLP Policy Reference

## PowerShell Management via Exchange Online & Compliance Center
```powershell
# Connect to Security & Compliance Center
Connect-IPPSSession -UserPrincipalName admin@tenant.onmicrosoft.com

# List active DLP policies and rule states
Get-DlpCompliancePolicy | Select-Object Name, Mode, Workload

# Inspect specific DLP rule actions and conditions
Get-DlpComplianceRule -Policy "Enterprise-Confidential-Data-Policy" | Format-List
```
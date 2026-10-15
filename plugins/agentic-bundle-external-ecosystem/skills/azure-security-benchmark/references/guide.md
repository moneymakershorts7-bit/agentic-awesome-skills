# Microsoft Cloud Security Benchmark (MCSB) Reference

## Azure CLI Auditing Commands
```bash
# Audit public IP addresses attached to Network Interfaces without NSG
az network nic list --query "[?ipConfigurations[0].publicIpAddress!=null && networkSecurityGroup==null].{Name:name, ResourceGroup:resourceGroup}" --output table

# Check storage account minimum TLS version and public blob access
az storage account list --query "[?minimumTlsVersion!='TLS1_2' || allowBlobPublicAccess!=false].{Name:name, TLS:minimumTlsVersion, PublicBlob:allowBlobPublicAccess}" --output table
```
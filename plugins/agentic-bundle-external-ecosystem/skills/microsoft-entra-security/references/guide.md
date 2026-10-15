# Microsoft Entra Security Reference

## Microsoft Graph API Auditing Queries
- High privilege role assignments: `GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'`
- Risky users: `GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskLevel eq 'high'`
- Service principals with application permissions: `GET https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appRoles,oauth2PermissionScopes`
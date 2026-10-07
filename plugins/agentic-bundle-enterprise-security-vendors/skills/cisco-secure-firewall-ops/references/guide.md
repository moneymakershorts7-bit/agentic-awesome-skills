# Cisco FMC REST API Reference

## Endpoints
- Token Auth: `POST https://{fmc_host}/api/fmc_platform/v1/auth/generatetoken`
- Access Policies: `GET https://{fmc_host}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies`
- Access Rules: `GET https://{fmc_host}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{containerUUID}/accessrules`
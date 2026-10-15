# PAN-OS REST API & CLI Reference

## API Queries
- Get Security Rules: `GET https://{firewall}/restapi/v10.2/Policies/SecurityRules?location=vsys&vsys=vsys1`
- Get Rule Usage Stats: `GET https://{firewall}/api/?type=op&cmd=<show><rule-hit-count><vsys><vsys_name>vsys1</vsys_name><rule-base><entry name="security"/></rule-base></vsys></rule-hit-count></show>`

## CLI Commands
```text
# Show active security policies
show running security-policy

# Check application dependency requirements
test security-policy-match source <src_ip> destination <dst_ip> protocol <proto> port <port> application <app>
```
# Check Point Management API (mgmt_cli) Reference

## Management CLI Commands
```bash
# Login and obtain session token
mgmt_cli login user "admin" password "password" > session.txt

# Show access rule base
mgmt_cli show-access-rulebase name "Network" details-level "full" -s session.txt

# Publish and install policy
mgmt_cli publish -s session.txt
mgmt_cli install-policy policy-package "Standard" access true threat-prevention true -s session.txt
```
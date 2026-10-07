# Cisco Duo Admin API Reference

## Python Duo Client Example
```python
import duo_client

admin_api = duo_client.Admin(
    ikey="DIXXXXXXXXXXXXXXXXXX",
    skey="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    host="api-xxxxxxxx.duosecurity.com"
)

# Get authentication logs
logs = admin_api.get_authentication_log(limit="100")
```
# Cisco Talos Integration Reference

## Snort 3 Rule Example
```text
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
  msg:"TALOS-2026-0001 - Potential Exploitation of Remote Code Execution";
  flow:to_server,established;
  http_uri; content:"/api/v1/admin/debug",fast_pattern;
  http_header; content:"X-Debug-Mode: True";
  classtype:attempted-admin;
  sid:1000001; rev:1;
)
```
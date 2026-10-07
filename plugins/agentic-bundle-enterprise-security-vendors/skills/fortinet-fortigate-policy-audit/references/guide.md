# FortiOS CLI Reference

## Useful Audit Commands
```text
# Show all active firewall policies
show firewall policy

# Check policy hit count and byte counters
diagnose firewall iprope list 100004

# Test firewall policy matching
diagnose firewall iprope lookup <src_ip> <src_port> <dst_ip> <dst_port> <proto> <incoming_interface>
```
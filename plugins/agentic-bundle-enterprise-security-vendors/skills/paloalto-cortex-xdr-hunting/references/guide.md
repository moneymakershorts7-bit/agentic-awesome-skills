# Cortex XQL Query Reference

## Example: Detect LSASS Memory Injection
```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and action_process_image_name in ("rundll32.exe", "powershell.exe", "cmd.exe")
| filter action_process_command_line contains "comsvcs.dll" or action_process_command_line contains "MiniDump"
| fields _time, agent_hostname, actor_process_image_name, action_process_command_line
```
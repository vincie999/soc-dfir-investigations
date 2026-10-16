# Case File 002: Lateral Movement & Suspicious Process Execution

## Objective
After successfully breaching the network (see Case 001), the attacker is attempting to move laterally to other internal servers using compromised credentials and executing hidden PowerShell commands.

## Tools Used
- Splunk (Windows Security Event Logs & Sysmon)
- Endpoint Telemetry

## Investigation Queries & Findings

### 1. Detecting Suspicious PowerShell Execution
Attackers love using encoded or hidden PowerShell commands to download malicious payloads.
- **SPL Query**: `index=windows_logs EventCode=4104 ScriptBlockText=*CodedCommand* OR ScriptBlockText=*DownloadString* | table _time, Computer, User, ScriptBlockText`
- **Finding**: Isolated workstation `DESKTOP-FIN-02` executing a base64 encoded PowerShell script trying to reach an external command-and-control (C2) server.

### 2. Identifying Lateral Movement (Pass-the-Hash / Remote Desktop)
- **SPL Query**: `index=windows_logs (EventCode=4624 Logon_Type=3) | stats count by dest_ip, src_ip, account_name | sort - count`
- **Finding**: Detected unusual network logons (Logon Type 3) from the compromised database server to three other internal domain controllers.
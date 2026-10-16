# Case File 003: Data Exfiltration & External IP Tracking

## Objective
Following the lateral movement (Case 002), the attacker is packaging sensitive customer records and exfiltrating them to an unknown external server over an encrypted channel.

## Tools Used
- Splunk (Firewall & NetFlow Logs)
- Network Forensics / Threat Intel

## Investigation Queries & Findings

### 1. Detecting Large Outbound Data Transfers
To spot exfiltration, look for abnormal outbound data volumes (bytes out) destined for foreign or unlisted IP addresses.
- **SPL Query**: `index=firewall_logs action=allowed bytes_out > 5000000 | stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port | sort - total_bytes`
- **Finding**: Isolated internal host `DESKTOP-FIN-02` pushing over 50MB of compressed data to an external suspicious IP address `185.220.101.5` on port `443`.

### 2. Threat Intel & IP Geolocation Check
- **SPL Query**: `index=threat_intel dest_ip="185.220.101.5" | table _time, src_ip, dest_ip, threat_actor_group, malicious_confidence`
- **Finding**: Confirmed the destination IP belongs to a known Tor exit node / malicious proxy infrastructure associated with an APT group.
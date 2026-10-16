# Case File 001: Unauthorized Fund Transfer & Network Breach

## Objective
Investigate an alert regarding unauthorized high-value fund transfers and identify the attacker's source IP and compromised user accounts.

## Tools Used
- Splunk (SIEM Investigation)
- Network Log Analysis

## Investigation Queries & Findings

### 1. Identifying Suspicious Logins
- **SPL Query**: `index=bank_security action=login | stats count by user, src_ip, status | sort - count`
- **Finding**: Detected brute-force activity from external IP `203.0.113.42` targeting a service account.

### 2. Tracing Financial Transactions
- **SPL Query**: `index=bank_transactions endpoint="/api/v1/transfer" amount > 10000 | table timestamp, user, src_ip, destination_account, amount`
- **Finding**: Isolated 3 unauthorized transactions totaling $150,000 sent to an external crypto-exchange routing account.
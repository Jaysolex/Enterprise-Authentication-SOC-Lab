# Enterprise-Authentication-SOC-Lab
End-to-end enterprise authentication monitoring lab using Windows Event Logs, Sysmon, and Splunk Enterprise to detect brute-force attempts, successful logins, PowerShell execution, network activity, and simulated lateral movement mapped to MITRE ATT&CK.




#Objective#

This lab demonstrates a real-world SOC detection workflow:

Validate log ingestion

Detect authentication failures (Event ID 4625)

Detect successful logins (Event ID 4624)

Filter noise from service accounts

Parse Sysmon XML telemetry

Detect PowerShell execution (Event ID 1)

Detect network connections (Event ID 3)

Simulate lateral movement

Map detections to MITRE ATT&CK

Build threshold-based alert logic

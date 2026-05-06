🛡️ SIEM Log Monitoring & Threat Detection using Splunk

📌 Project Overview

This project simulates a real-world SOC (Security Operations Center) environment built entirely on a home lab. Using Splunk Enterprise as the SIEM, Sysmon for deep Windows telemetry, and Kali Linux as the attacker machine, I simulated three real attack scenarios, built custom detection rules in SPL, and mapped all findings to the MITRE ATT&CK framework.
This project replicates Tier 1–2 SOC analyst workflows including alert triage, log analysis, and detection engineering.
---
🧱 Lab Architecture
```
┌─────────────────────────────┐         ┌──────────────────────┐
│     Windows 11 (Victim)     │◄────────│   Kali Linux VM      │
│                             │  Attack │   IP: 192.168.56.102 │
│  IP: 192.168.56.1           │         │   Tool: Hydra        │
│  Splunk Enterprise          │         └──────────────────────┘
│  Sysmon v15.15              │
│  Windows Security Logs      │
└─────────────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│     Splunk SIEM             │
│  - 19,000+ Security Events  │
│  - 3,151+ Sysmon Events     │
│  - Custom Detection Rules   │
│  - SOC Dashboard            │
└─────────────────────────────┘
```
---
🛠️ Tools & Technologies
Tool	Purpose
Splunk Enterprise	SIEM — log ingestion, search, alerting
Sysmon v15.15	Deep Windows process/network monitoring
Kali Linux	Attacker machine for attack simulation
Hydra	Brute force attack tool
Windows 11	Victim/target machine
SwiftOnSecurity Sysmon Config	Optimized Sysmon detection ruleset
---
⚔️ Attacks Simulated
Attack 1 — SMB Brute Force (T1110)
Attack 2 — PowerShell Execution (T1059.001)
Attack 3 — Reconnaissance & Discovery (T1087, T1049)
---
📋 Attack 1: SMB Brute Force
What Happened
The attacker machine (Kali Linux) used Hydra to perform an SMB brute force attack against a test user account on the Windows victim machine.
Attack Command (Kali Linux)
```bash
hydra -l testuser -P /usr/share/wordlists/rockyou.txt 192.168.56.1 smb -t 4 -V
```
What Was Generated
19,059 failed login events (EventCode 4625)
Source IP: `192.168.56.102` (Kali Linux)
Target user: `testuser`
Authentication method: NTLM
Detection Query (SPL)
```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10
| eval Threat="Brute Force Detected!"
| eval MITRE="T1110 - Brute Force"
| table Account_Name, Source_Network_Address, count, Threat, MITRE
```
MITRE ATT&CK Mapping
Technique	ID	Tactic
Brute Force	T1110	Credential Access
Key Findings
19,059 failed logon attempts detected in Splunk
Attacker IP `192.168.56.102` identified as source
Account `testuser` targeted with rockyou.txt wordlist
Failure reason: "Unknown user name or bad password"
---
📋 Attack 2: Suspicious PowerShell Execution
What Happened
After gaining initial access, the attacker executed suspicious PowerShell commands using bypass flags commonly used by malware and threat actors.
Attack Commands (Windows — Simulating Post-Exploitation)
```powershell
powershell -nop -exec bypass -c "Write-Host 'Simulated Attack'"
powershell -nop -exec bypass -w hidden -c "IEX 'Write-Host Malware Simulation'"
```
Suspicious Flags Used
Flag	Meaning	Why Malicious
`-nop`	No Profile	Bypasses profile restrictions
`-exec bypass`	Bypass Execution Policy	Runs unsigned scripts
`-w hidden`	Hidden Window	Hides from user
`IEX`	Invoke Expression	Downloads & runs remote code
Detection Query (SPL)
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell"
| eval Threat="Suspicious PowerShell Detected!"
| eval MITRE="T1059.001 - PowerShell"
| table _time, host, Threat, MITRE
```
MITRE ATT&CK Mapping
Technique	ID	Tactic
PowerShell	T1059.001	Execution
Key Findings
PowerShell execution captured in Sysmon logs
`powershell.exe` path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
Bypass flags detected in event data
EventID 5 (Process Terminated) confirmed execution
---
📋 Attack 3: Reconnaissance & Discovery
What Happened
After gaining access, the attacker ran system discovery commands to enumerate users, groups, network connections — standard post-exploitation recon behavior.
Attack Commands (Simulating Attacker Recon)
```powershell
net user                        # List all user accounts
net localgroup administrators   # List admin group members
whoami /all                     # Current user privileges
netstat -ano                    # Active network connections
```
What Was Generated
26 process creation events (EventCode 4688)
Multiple suspicious processes logged
User enumeration activity recorded
Detection Query (SPL)
```spl
index=main source="WinEventLog:Security" EventCode=4688
| eval Threat="Suspicious Reconnaissance!"
| eval MITRE="T1087 - Account Discovery"
| table _time, User, New_Process_Name, Threat, MITRE
| head 10
```
MITRE ATT&CK Mapping
Technique	ID	Tactic
Account Discovery	T1087	Discovery
System Network Connections Discovery	T1049	Discovery
---
🔍 MITRE ATT&CK Summary
```
Initial Access → Credential Access → Execution → Discovery
                        │                │            │
                   T1110 Brute      T1059.001     T1087 Account
                   Force            PowerShell    Discovery
                                                      │
                                                  T1049 Network
                                                  Discovery
```
---
📊 Detection Rules Summary
Rule Name	EventCode	Logic	MITRE
Brute Force Detection	4625	Failed logins > 10 from same IP	T1110
PowerShell Execution	Sysmon	powershell.exe with bypass flags	T1059.001
Recon Detection	4688	net.exe, whoami.exe, netstat.exe	T1087, T1049
---
📈 Key Statistics
Metric	Value
Total Security Events Ingested	48,377+
Total Sysmon Events Ingested	3,151+
Brute Force Attempts Detected	19,059
Process Creation Events	26
Detection Rules Created	3
MITRE Techniques Covered	4
---
🧠 SOC Analyst Skills Demonstrated
✅ SIEM deployment and configuration (Splunk)
✅ Log ingestion from multiple Windows sources
✅ SPL (Search Processing Language) query writing
✅ Custom detection rule creation
✅ Alert configuration and tuning
✅ Attack simulation and investigation
✅ MITRE ATT&CK framework mapping
✅ Incident triage and documentation
✅ Sysmon deployment and configuration
---
📁 Project Structure
```
SOC-Splunk-SIEM-ThreatDetection/
│
├── README.md                          # This file
│
├── screenshots/
│   ├── attack1-bruteforce/            # Brute force attack evidence
│   ├── attack2-powershell/            # PowerShell attack evidence
│   └── attack3-recon/                 # Reconnaissance evidence
│
├── detection-rules/
│   ├── bruteforce_detection.spl       # SPL query for brute force
│   ├── powershell_detection.spl       # SPL query for PowerShell
│   └── recon_detection.spl            # SPL query for recon
│
└── docs/
    └── lab-setup.md                   # Lab setup documentation
```
---
🚀 How to Reproduce
Prerequisites
Windows 10/11 machine
VirtualBox with Kali Linux VM
Splunk Enterprise (Free — 500MB/day)
Sysmon + SwiftOnSecurity config
Step 1: Install Sysmon
```powershell
# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig-export.xml"

# Install Sysmon with config
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
Step 2: Configure Splunk inputs.conf
```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = main
disabled = false
renderXml = false

[WinEventLog://Security]
index = main
disabled = false
```
Step 3: Run Attacks
```bash
# From Kali Linux
hydra -l testuser -P /usr/share/wordlists/rockyou.txt 192.168.56.1 smb -t 4 -V
```
---
📚 References
Splunk Documentation
MITRE ATT&CK Framework
SwiftOnSecurity Sysmon Config
Sysinternals Sysmon
---
👩‍💻 Author
Munnaza Jameel
SOC Analyst (Home Lab)
📍 Rawalpindi, Pakistan
🔗 GitHub
---
> ⚠️ **Disclaimer:** All attacks were performed in an isolated home lab environment for educational purposes only. Never perform these activities on systems you do not own or have explicit permission to test.

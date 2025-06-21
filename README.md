# 📉 Sudden Network Slowness

In this project, we investigate and respond to unusual internal port-scan activity that resulted in sudden network slowdowns within a cloud-based environment.

_**Inception State:**_ the environment shows signs of degraded network performance with no clear cause identified. There are no existing indicators of compromise or known malicious activity, and the impacted virtual machine is still connected to the network.

_**Completion State:**_ the root cause is confirmed as a PowerShell-based port scan executed under the SYSTEM account. The malicious script is contained, the device is isolated and reimaged, attacker activity is mapped to MITRE ATT&CK techniques, and a full remediation and monitoring strategy is implemented to prevent recurrence.

---

## Technology Utilized
- Microsoft Defender for Endpoint (device-level detection, script monitoring, and live response isolation)
- Azure Virtual Machines (hosted the internet-exposed scanning VM and target systems)
- PowerShell (used for both malicious port scanning and incident response scripting)
- Azure Network Security Groups (NSG) (controlled inbound/outbound traffic to mitigate and block scan behavior)


---
## 📑 Table of Contents

- [📉 Sudden Network Slowness](#-sudden-network-slowness)
- [🧰 Technology Utilized](#technology-utilized)
- [📑 Table of Contents](#-table-of-contents)
- [🔍 Initial Anomaly Detection](#-initial-anomaly-detection)
- [🕵️‍♂️ Suspicious IP Focus](-#-suspicious-ip-focus)
- [🧨 Malicious Script Execution Identified](#-malicious-script-execution-identified)
- [🚨 Containment & Escalation Response](#-containment--escalation-response)
- [🧩 MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [🔧 Recommended Mitigations](#-recommended-mitigations)
  - [1. Isolate and Reimage the Affected VM](#1-isolate-and-reimage-the-affected-vm-containment--recovery)
  - [2. Investigate SYSTEM-Level Script Execution](#2-investigate-system-level-script-execution-detection--prevention)
  - [3. Block Unauthorized Internal Port Scans](#3-block-unauthorized-internal-port-scans-containment)
  - [4. Validate and Harden PowerShell Logging](#4-validate-and-harden-powershell-logging-hardening--detection)
  - [5. Set Up Sentinel Alerts for Abnormal Device Behavior](#5-set-up-sentinel-alerts-for-abnormal-device-behavior-detection)
- [📊 Summary Table](#-summary-table)



---
## 🔍 Initial Anomaly Detection

To kick off this investigation, we used an initial query into the DeviceNetworkEvents table in Microsoft Defender for Endpoint. We were able to analyze unexpected network activity originating from one of our lab VMs (r3dant-ls-lab6). This initial query revealed that the VM was failing a high volume of outbound connection requests not just to external systems, but also to itself and another internal host on the same subnet. This unusual behavior raised immediate concerns about internal scanning or misconfiguration and prompted a deeper investigation into possible port scanning activity. Here's one of the first queries we ran and the results:


![image](https://github.com/user-attachments/assets/59c13d5f-c8b8-48fe-86b5-0ea1bff8af12)

![image](https://github.com/user-attachments/assets/7c146d84-15c7-49c6-a750-88c8715de200)

---
## 🕵️‍♂️ Suspicious IP Focus

After identifying a large number of connection failures on our VM, we moved to examine the suspected source IP address *10.0.0.85* that quickly stood out due to the sequential pattern of ports it attempted to access which is a common indicator of a port scan.

We ran the following Kusto Query Language (KQL) query in Microsoft Defender for Endpoint to investigate the failed connection attempts from that IP:


![image](https://github.com/user-attachments/assets/d5db7aa6-e270-4dc0-8482-a4425799d626)

![image](https://github.com/user-attachments/assets/d5be39d0-9266-464b-8abb-b40225ae098f)


🧠 Insight:
The results revealed dozens of consecutive failed attempts on incrementally numbered ports, strongly indicating an automated port scan was being conducted internally.

✅ This helped confirm our theory that the VM was not only exposed to the internet but also being actively probed by an unauthorized script.

---
## 🧨 Malicious Script Execution Identified

To understand what triggered the suspicious network activity, we pivoted to the DeviceProcessEvents table to examine process activity around the time the port scan began. Our investigation revealed that a PowerShell script named portscan.ps1 was executed at 2025-06-18T20:37:35Z.

We used the following Kusto Query Language (KQL) query to identify processes that executed within a 10-minute window surrounding the event:

![image](https://github.com/user-attachments/assets/642d542c-2d82-42a9-8398-902bf3632554)

![image](https://github.com/user-attachments/assets/8eacc07d-fd9d-4863-9b27-81bcbd257553)

📌 Finding:
The output confirmed that portscan.ps1 was launched using PowerShell under the SYSTEM account, which is highly unusual and not part of any authorized task configuration which is a strong indication of malicious or misused automation.

After identifying the suspicious portscan.ps1 activity in the Defender logs, we logged into the suspected VM and located the actual PowerShell script used to conduct the internal port scan.

📂 Script Path:
C:\ProgramData\entropyGorilla.log (log file output)
portscan.ps1 (script name)

![image](https://github.com/user-attachments/assets/1a98c077-b7b9-479b-8b40-3202d60133ca)

🧠 Insight:
This script was custom-built to simulate or perform a broad internal reconnaissance, scanning multiple IPs and critical ports used for FTP, RDP, SSH, email, and databases. It also logs each action with a timestamp and log level suggesting this was an intentionally crafted, repeatable tool.

⚠️ The fact that it was launched under the SYSTEM account elevates the concern, as this is not typical behavior for any baseline admin task or patching process.


---
## 🚨 Containment & Escalation Response

During our investigation, we confirmed that the portscan.ps1 script was executed by the SYSTEM account, a highly privileged context. This behavior is not expected and had not been configured or approved by system administrators.

#### 🚫 Why this is critical:

Scripts run as SYSTEM can bypass typical user-level restrictions

Execution at this level suggests a misconfigured task, compromise, or unauthorized automation

#### 🔒 Immediate Response Actions:
- I Isolated the device in Microsoft Defender for Endpoint to prevent further scanning or lateral movement
- Ran a full malware scan to check for known threats
- No malware was detected, but to ensure full remediation and restore trust, we:
  - Kept the device isolated
  - Submitted a ticket to have the VM re-imaged and rebuilt from a secure baseline


---
## 🧩 MITRE ATT&CK Mapping
### A couple of the MITRE ATT&CK Tactics & Techniques Observed:
| Technique ID   | Name                             |
|----------------|----------------------------------|
| `T1046`        | Network Service Scanning (Discovery)         |
| `T1059.001`    | Command & Scripting Interpreter: PowerShell (Execution)   |
| `T1078`    | Valid Accounts: SYSTEM Abuse (Privilege Escalation / Defense Evasion)   |


## 🔧 Recommended Mitigations

### 1. Isolate and Reimage the Affected VM (Containment & Recovery)  
**Why:** Prevents further malicious activity from an untrusted or misconfigured system.

**How:**  
- Use **Microsoft Defender for Endpoint** to isolate the VM (`r3dant-ls-lab6`)  
- Submit a reimage/rebuild request through IT or automation pipelines (Intune, SCCM, Autopilot)  
- Apply hardened baseline configuration (e.g., CIS Level 1 or 2)


### 2. Investigate SYSTEM-Level Script Execution (Detection + Prevention)  
**Why:** Abuse of the SYSTEM account is a serious privilege escalation and security red flag. 

**How:**  
- Review process events with this KQL query:
  ```kql
  DeviceProcessEvents
  | where InitiatingProcessAccountName == "SYSTEM"
  | where FileName endswith ".ps1"
  ```
- Identify and disable unauthorized scheduled tasks, WMI consumers, or persistent services
- Implement AppLocker or Microsoft Defender Application Control (MDAC) to restrict script execution



### 3. Block Unauthorized Internal Port Scans (Containment)
**Why:** Prevents VM-initiated scans from impacting internal devices or degrading network performance.

**How:**
- Use NSG rules to limit outbound traffic from VMs to specific IP ranges
- Set up detections in Defender or Sentinel using:

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize Attempts = count() by RemotePort, bin(Timestamp, 1m)
| where Attempts > 50
 ```


### 4. Validate and Harden PowerShell Logging (Hardening & Detection)
**Why:** Increases visibility into malicious script use.

**How:**
- Enable PowerShell logging via GPO:
  - Turn on Module Logging
  - Turn on Script Block Logging
- Monitor logs through Microsoft Defender or forward them to Sentinel for correlation



### 5. Set Up Sentinel Alerts for Abnormal Device Behavior (Detection)
**Why:** Early warning for potential port scans or misuse of privileges.

**How:**

- Go to Microsoft Sentinel → Analytics → + Create → Scheduled Query Rule
- Sample rule to catch high-volume failed connections:

 ```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize Attempts = count() by DeviceName, RemoteIP, bin(Timestamp, 5m)
| where Attempts > 100
 ```


---

## 📊 Summary Table
| Action                                         | Purpose                | Status                 |
| ---------------------------------------------- | ---------------------- | ---------------------- |
| Isolate & Reimage the VM                       | Containment / Recovery | ✅ Required             |
| Investigate SYSTEM-level script use            | Detection / Prevention | ✅ Required             |
| Block internal scan behavior via NSG           | Containment            | ✅ Recommended          |
| Enable PowerShell logging                      | Hardening / Detection  | ✅ Strongly Recommended |
| Deploy Sentinel analytics for port scan alerts | Detection              | ✅ Essential            |





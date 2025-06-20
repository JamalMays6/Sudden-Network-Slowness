# 📉Sudden Network Slowness

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

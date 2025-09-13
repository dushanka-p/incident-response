# Scenario 01 – Virtual Machine Brute Force Detection

## Overview
This scenario demonstrates how to detect and respond to brute force attacks targeting an Azure Virtual Machine using **Microsoft Sentinel** and **Defender for Endpoint** logs.  
It follows the **NIST 800-61 Incident Response Lifecycle** and maps detection to relevant **MITRE ATT&CK techniques**.

---

## Learning Objectives
- Create and configure a **Scheduled Analytics Rule** in Microsoft Sentinel.  
- Detect repeated failed logons against a VM using **KQL queries**.  
- Trigger and investigate an incident in Sentinel.  
- Apply containment and recovery steps using **Network Security Groups (NSGs)**.  
- Document findings and lessons learned in line with NIST IR practices.  
- Map detection to **MITRE ATT&CK**.  

---

## Tools & Data Sources
- **Microsoft Defender for Endpoint (MDE)**  
  - Table: `DeviceLogonEvents`  
- **Microsoft Sentinel**  
  - Analytics → Scheduled Query Rules  
  - Incidents & Investigations  
- **Azure Network Security Groups (NSGs)** for containment  

---

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access → **Technique:** T1110 (Brute Force)  
- **Tactic:** Initial Access → **Technique:** T1078 (Valid Accounts)  

---

## Scenario Workflow
1. **Pre-Lab Setup** – Create and onboard VM to MDE.  
2. **Detection** – Build Sentinel Scheduled Query Rule (≥10 failed logons in 5 hours).  
3. **Alerting** – Trigger the rule and generate an incident.  
4. **Investigation** – Review entities, verify failed vs. successful logons.  
5. **Containment** – Apply NSG lockdown to restrict RDP access.  
6. **Recovery** – Validate no compromise, remove brute force attempts.  
7. **Post-Incident** – Document findings, propose policy updates.  
8. **Cleanup** – Safely delete your incident and analytics rule in Sentinel.  

---

## Key Queries

**Brute Force Detection**
```kusto
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
````

**Check for Successful Logons**

```kusto
let TargetDevice = "windows-target-1"; 
let SuspectIP = "89.116.158.44"; 
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```

---

## Outcome

* Successfully detected brute force attempts.
* Verified no successful compromise.
* Contained access with NSG lockdown.
* Closed incident as **True Positive**.

---

## Folder Structure

```markdown
## Folder Structure

01-virtual-machine-brute-force-detection/
│
├── README.md       # Overview of the scenario (high-level summary)
├── walkthrough.md  # Detailed step-by-step lab guide
├── queries/        # KQL queries used in the scenario
└── report/         # Final incident report (findings, screenshots, conclusions)
```
---


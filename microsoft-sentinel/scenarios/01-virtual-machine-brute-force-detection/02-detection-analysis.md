## Detection and Analysis

1. Go to **Sentinel → Incidents**.  
2. Locate the incident.  
3. Select the incident to open it.  
4. Assign the incident to yourself:  
   - Click **Owner** → from the dropdown, select **Assign to me**.  
5. Update the status:  
   - Set **Status** to **Active** → click **Apply**.  
6. Begin the investigation:  
   - Go to **Actions → Investigate**.  

### Analyzing the Incident

<img width="807" height="593" alt="image" src="https://github.com/user-attachments/assets/b0048f56-c858-4e45-bae7-e75b2f5b30c9" />

**Key Findings:**  
- Four different virtual machines were potentially impacted.  
- Three different remote public IP addresses attempted brute force logins.  

<img width="378" height="289" alt="image" src="https://github.com/user-attachments/assets/c69089ef-a77e-4f47-b52f-96b4acc65cb2" />

---

## Containment, Eradication, and Recovery

1. **Identify impacted systems:**  
   - Use **Defender for Endpoint** to find devices targeted by the brute force attempts.  

2. **Contain the incident:**  
   - Isolate the potentially impacted devices.  
   - Apply containment controls in Azure:  
     - Update the **Network Security Group (NSG)** for your VM.  
     - Restrict access so only your local PC can connect.  

   **Notes:**  
   - NSG was locked down to prevent RDP attempts from the public internet.  
   - Proposed policy: require NSG hardening for all VMs (can be enforced with Azure Policy).  

3. **Eradication:**  
   - Verify no successful brute force logons occurred.  

   **KQL Query (Log Analytics):**
   ```kusto
   let TargetDevice = "th--dp--win11"; // Replace with target VM
   let SuspectIP = "194.32.87.93";     // Replace with suspect IP
   DeviceLogonEvents
   | where ActionType == "LogonSuccess"
   | where DeviceName == TargetDevice and RemoteIP == SuspectIP
   | order by TimeGenerated desc

**Results:**

* `92.63.197.9` → unsuccessful
* `190.57.75.42` → unsuccessful
* `194.32.87.93` → unsuccessful

4. **Recovery:**

   * Run an **antivirus scan** from Defender for Endpoint.
   * Confirm systems are clean and access is restored securely.


---

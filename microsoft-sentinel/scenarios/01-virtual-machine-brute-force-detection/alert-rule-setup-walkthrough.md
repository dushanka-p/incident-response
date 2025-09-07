### 1. Open Sentinel Analytics

* Navigate to **Sentinel > Analytics**.
* Click **+ Create Alert Rule**.
* Name the rule:
  **DP--IR--Create Alert Rule (Brute Force Attempt Detection)**
* Add a description.

---

### 2. Build KQL Query

* Open a new tab: **Log Analytics Workspaces**.
* Go to **Logs**.
* Create and run the following query:

```kusto
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, DeviceName, ActionType
| where NumberOfFailures >= 50
```

* Test the query to confirm results.

---

### 3. Configure Alert Rule

* Go back to **Sentinel** (Alert Rule creation tab).
* Set **Severity**: Medium.
* Select appropriate **MITRE ATT\&CK TTPs**.
* Set **Status**: Enabled.
* In the **Rule Logic** section:

  * Paste the above query.

---

### 4. Alert Enhancements

* Click **Add** under Alert Enhancements.
* Add the following mappings:

  * **Host → Hostname → DeviceName**
  * **IP → Address → RemoteIP**

---

### 5. Query Scheduling

* Configure schedule:

  * **Run query:** Every 4 Hours
  * **Look up data from the last:** 5 Hours
* Set **Alert Threshold**: Greater Than 0
* Enable **Suppression**:

  * Stop running query for **24 Hours**
  * (to avoid overload since many analysts create this type of query).

---

### 6. Incident Settings

* Enable **Alert Grouping**.
* Leave default: **5 Hours**.

---

### 7. Save

* Click **Save** to complete rule creation.

---

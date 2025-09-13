<img width="1610" height="895" alt="image" src="https://github.com/user-attachments/assets/89e2f3b7-5c58-44c7-8f81-456fe098b6bc" />

# PowerShell Suspicious Web Request

## Explanation

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like **PowerShell** to blend in with normal activity.

By leveraging commands such as `Invoke-WebRequest`, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms.  

This tactic is a hallmark of **post-exploitation activity**, enabling adversaries to:  
- Deploy malware  
- Exfiltrate data  
- Establish communication channels with a command-and-control (C2) server  

## Why Detection Matters

Detecting this behavior is critical to identifying and disrupting an ongoing attack before it escalates into data loss, persistence, or full system compromise.



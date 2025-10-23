<img width="400" alt="image" src="https://github.com/user-attachments/assets/9baf31ca-d592-4e78-b091-ea0defd2a5d0" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/josephbcompton08/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents` table for any event that contained the string `"tor"`. Based on the results, between `2025-10-14T05:56:47.7330428Z` and the end of the observed activity window, an employee downloaded a Tor installer and performed actions that resulted in multiple Tor-related files being copied to the desktop. A new file named `tor-shopping-list.txt` was also created on the desktop during this period.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "josephcompton"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-14T05:56:47.7330428Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1188" height="440" alt="image" src="https://github.com/user-attachments/assets/9a33b5b7-3da5-4517-8dbb-aebe80f17c17" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` that contained the string `"tor-browser-windows-x86_64-portable-14.5.8.exe"`. Based on the logs returned, at `2025-10-14T01:58:00Z`, the user account `josephcompton` executed a Tor Browser installer from the `Downloads` folder on the device `threat-hunt-lab`. The installer was run in silent mode, meaning it executed automatically in the background without displaying any windows or prompts. This activity is notable due to the combination of a late-night execution time, the use of a silent installation method, and the installation of Tor Browser—a privacy-focused application that can sometimes be associated with attempts to conceal network activity.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1497" height="266" alt="image" src="https://github.com/user-attachments/assets/936a9904-498c-4309-89c2-75d80bdd6863" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that the user `josephcompton` opened the Tor Browser. Based on the logs returned, at `2025-10-14T05:59:27.1748704Z`, the user launched the Tor Browser. Multiple related processes were observed following this event, including instances of `firefox.exe` (Tor) and `tor.exe`, confirming active Tor usage on the device.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor-browser-windows-x86_64-portable-*.exe", "firefox.exe", "tor.exe", "tor-browser.exe", "Browser\firefox.exe", "Tor Browser\firefox.exe")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
| order by Timestamp desc

```
<img width="1547" height="492" alt="image" src="https://github.com/user-attachments/assets/331776e6-3bc5-4a57-b512-ca8f8052f32d" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication that the Tor Browser was used to establish a connection using any of the known Tor ports. About a minute after the Tor Browser installation began (`2025-10-14T05:59:50.4378636Z`), `firefox.exe` (the underlying browser that Tor uses) successfully established a connection to the local Tor control port on the same computer. This occurred at approximately 1:59 AM on the `threat-hunt-lab` device under the `josephcompton` account, connecting to port `9151` on `localhost`—the standard control port that Tor Browser uses to communicate with its Tor network component. This indicates that Tor Browser started up and began routing traffic anonymously. A few additional outbound connections were also observed to external sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "josephcompton"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1400" height="493" alt="image" src="https://github.com/user-attachments/assets/e1478291-77b9-4bc1-8594-e7285ae6564f" />

---

## Chronological Event Timeline  
### Tor Browser Usage Investigation - Detailed Timeline Report  

---

### **Investigation Subject**  
- **User Account:** `josephcompton`  
- **Device:** `threat-hunt-lab`  
- **Investigation Period:** October 14, 2025, 1:56 AM – 2:50 AM EST  

---

## **Chronological Timeline of Events**

### **Phase 1: Installation (1:56 AM – 1:59 AM)**  
- **1:56:47 AM** – The Tor Browser installer file `tor-browser-windows-x86_64-portable-14.5.8.exe` was renamed in the Downloads folder, indicating the download completed.  
- **1:58:39 AM** – User `josephcompton` executed the Tor Browser installer using silent installation mode (`/S` flag), allowing installation to proceed without user prompts or visible windows.  
- **1:59:12 AM – 1:59:13 AM** – Installation began extracting core Tor components:  
  - License documentation files created (`Torbutton.txt`, `Tor-Launcher.txt`, `tor.txt`)  
  - Main Tor executable `tor.exe` deployed to Desktop location  
- **1:59:26 AM** – Desktop shortcut **"Tor Browser.lnk"** created, completing the installation phase.  

---

### **Phase 2: Initial Browser Launch (1:59 AM – 2:03 AM)**  
- **1:59:27 AM** – Tor Browser (`firefox.exe`) launched for the first time by `josephcompton`.  
- **1:59:40 AM** – Browser profile initialization began with creation of `storage.sqlite` database file.  
- **1:59:50 AM** – **Critical moment:** Firefox established connection to `localhost:9151` (Tor Browser’s control port), confirming Tor network connectivity was established and the browser was ready for anonymous browsing.  
- **1:59:50 AM** – Additional browser storage file `storage-sync-v2.sqlite` created as part of profile setup.  
- **2:03:11 AM** – Form history database `formhistory.sqlite` created, indicating potential form interactions or browsing activity began.  

---

### **Phase 3: Suspicious Activity Period (2:29 AM – 2:50 AM)**  
- **2:29:26 AM – 2:29:27 AM** – Three Edge browser validator JavaScript files were modified in a temporary Chrome unpacker directory:  
  - `edge_checkout_page_validator.js`  
  - `edge_confirmation_page_validator.js`  
  - `edge_tracking_page_validator.js`  
  **Note:** These appear to be browser extension or shopping-related components being processed, possibly indicating the user was accessing e-commerce sites.  
- **2:48:24 AM** – File of interest created: `tor-shopping-list.txt` initially appeared in the Documents folder with a corresponding Windows Recent Files shortcut (`.lnk`) created, indicating the file was opened or accessed.  
- **2:48:38 AM** – The same `tor-shopping-list.txt` file was created on the Desktop (**SHA256 hash matches** the Documents version), confirming it’s the same content moved or copied to a more visible location.  
- **2:50:28 AM** – Web storage database `webappsstore.sqlite` created, indicating continued browser activity and potential web application usage through Tor.  

---

## **Summary**  

Between **1:56 AM and 2:50 AM** on **October 14, 2025**, user `josephcompton` conducted a complete Tor Browser installation and usage session on the `threat-hunt-lab` device. The session began with a **silent installation** of Tor Browser version **14.5.8**, executed without visible prompts at an **unusual hour** (late night/early morning).  

Within one minute of installation, the user launched Tor Browser and successfully established connection to the Tor network via the local control port (`localhost:9151`). The browser remained active for approximately **50 minutes**, during which the user engaged in browsing activity that involved form interactions and web storage usage.  

The most notable finding is the creation of a file named `tor-shopping-list.txt` at **2:48 AM**, approximately 50 minutes after first launch. This file was deliberately saved to both the **Documents** folder and **Desktop**, suggesting intentional user action. The presence of modified e-commerce validator JavaScript files around the same timeframe, combined with the “shopping list” filename, strongly suggests that the user was accessing online shopping or e-commerce platforms through the anonymized Tor network.  

---

### **Key Security Concerns**  
- Silent installation method used (commonly associated with automated or covert deployments)  
- Activity occurred during unusual hours (**1:58 AM – 2:50 AM**)  
- Evidence of shopping-related behavior through the Tor network  
- Combination of anonymous browsing tools and e-commerce activity warrants further investigation into the legitimacy of these transactions  

---

## **Response Taken**  
TOR usage was confirmed on endpoint **`threat-hunt-lab`** by the user **`josephcompton`**.  
The device was **isolated**, and the user’s **direct manager was notified**.  


---

# Phishing Email Analysis: Netflix Impersonation & CVE-2017-11882

Hands-on investigation of a phishing email impersonating Netflix, analyzing the header artifacts, malicious PDF/Excel attachments, and mapping the execution chain to MITRE ATT&CK. 

##  Objective
Document the investigation workflow for a multi-stage phishing attack, extract actionable Indicators of Compromise (IOCs), and identify detection opportunities for SOC alert triage.

##  1. Email Header Analysis
Static analysis of the email source to identify sender reputation and spoofing indicators.

*   **Intended Recipient:** `redacted@yahoo.com`
*   **Originating IP:** `10.197.37.234`
*   **Return-Path:** `etekno[.]xyz`
*   **Authentication Results:** SPF (`none`), DKIM (`unknown`), DMARC (`unknown`)
*   **Spoofing Tactic:** Lookalike domain `gogolecloud[.]com` used in the `header.from` field (typosquatting `googlecloud.com`).

##  2. The Lure (Initial Access)
*   **Action:** User is prompted to click an "UPDATE ACCOUNT NOW" button.
*   **Shortened URL:** `hxxps://t[.]co/yuxfZm8KPg?amp=1`
*   **Sandbox Verdict:** Flagged as Suspicious Activity by ANY.RUN.

##  3. Payload Execution Chain
The attack uses a dual-stage payload delivery, transitioning from a PDF lure to an Excel exploit.

### Stage 1: PDF Dropper
*   **Filename:** `Payment-updateid.pdf`
*   **MD5:** `4a2775eae2ebef41901a3f08d3b857c8`
*   **Embedded URL:** `hxxps://lihi1[.]com/JqdmJ`
*   **Resolved IP:** `35.244.149.249`

### Stage 2: Excel Exploit (CVE-2017-11882)
*   **Filename:** `CBJ200620039539.xlsx`
*   **Spawned Process:** `EQNEDT32.EXE`
*   **Process Path:** `C:\Program Files\Common Files\Microsoft Shared\EQUATION\EQNEDT32.EXE`
*   **Vulnerability:** CVE-2017-11882 (Microsoft Equation Editor RCE)
*   **C2 Domain:** `biz9holdings[.]com`
*   **IDS Alert:** `ET INFO Suspicious GET Request with Possible COVID-19 URI M1`

## 4. MITRE ATT&CK Mapping
| Technique | ID |
| :--- | :--- |
| Phishing: Spearphishing Attachment | T1566.001 |
| User Execution: Malicious File | T1204.002 |
| Exploitation for Client Execution | T1203 |
| Command and Scripting Interpreter | T1059 |

##  5. Detection Opportunities
*   **Email Gateway:** Alert on SPF/DKIM/DMARC failures, specifically targeting `etekno[.]xyz` and `gogolecloud[.]com`.
*   **Endpoint (Sysmon):** Monitor for the spawning of `EQNEDT32.EXE` by Microsoft Office applications (Excel/Word). 
*   **Network (IDS/IPS):** Alert on traffic to `biz9holdings[.]com` and `lihi1[.]com`. 
*   **Mitigation:** Disable the Microsoft Equation Editor via registry keys or Group Policy across the enterprise.

##  6. Indicators of Compromise (IOCs)
*Note: IOCs are defanged for safe sharing.*

```csv
type,value,context
ip,10.197.37.234,Originating email IP
domain,etekno[.]xyz,Return-Path domain
domain,gogolecloud[.]com,Lookalike sender domain
url,hxxps://t[.]co/yuxfZm8KPg?amp=1,Phishing button URL
md5,4a2775eae2ebef41901a3f08d3b857c8,Payment-updateid.pdf hash
url,hxxps://lihi1[.]com/JqdmJ,URL embedded in PDF
ip,35.244.149.249,IP resolved from lihi1[.]com
process,C:\Program Files\Common Files\Microsoft Shared\EQUATION\EQNEDT32.EXE,Exploited Equation Editor process
cve,CVE-2017-11882,Equation Editor RCE
domain,biz9holdings[.]com,Second-stage payload host
alert,ET INFO Suspicious GET Request with Possible COVID-19 URI M1,IDS signature

Author: Wunmi Adam.          
Project: Phishing Email Analysis — TryHackMe.
Focus: Cybersecurity | Detection Engineering | Threat Analysis | Defensive Security


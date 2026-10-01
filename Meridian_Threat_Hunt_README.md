# Meridian Threat Hunt Walkthrough (Hunt 25)

## 🎯 Hunt Overview

This threat hunt involved investigating a full-scale intrusion into the **MeridianCare** application environment. The objective was to reconstruct the adversary's activity from initial reconnaissance through credential access, SSH compromise, privilege escalation, persistence, command-and-control activity, automated remediation, and final forensic response.

The investigation was performed in **Azure Log Analytics** using KQL across several custom telemetry tables.

---

## Case File

Meridian's portal threw a real incident overnight. A single Ubuntu host exposed a web application in front of a patient database while an automated defense stack actively responded to changes on the system.

Some defensive detections represented real attacker activity. Others were caused by the environment's own bootstrap and remediation processes. Separating malicious activity from defensive noise was one of the core investigative challenges.

The attacker/source IP interacted with the web application, exposed sensitive configuration information, obtained access through an existing service account, escalated privileges, planted persistence, and repeatedly attempted outbound communication to attacker-controlled infrastructure.

At the same time, the automated defense system reverted SSH keys, crontabs, configuration changes, and temporary-directory artifacts.

---

## Environment Scope

- **Workspace:** `LAW-HuntPractice`
- **Target Host:** `ip-10-1-15-67`
- **Internal IP:** `10.1.15.67`
- **Operating System:** Ubuntu 22.04
- **Application Stack:** Apache, PHP, MySQL
- **Attacker/Source IP:** `10.1.134.57`
- **Investigation Window:** `2026-02-06 02:42–05:30 UTC`
- **Platform:** Azure Log Analytics

### Tables Used

- `MeridianAccess_CL`
- `MeridianAudit_CL`
- `MeridianAuth_CL`
- `MeridianDefender_CL`
- `MeridianSyslog_CL`
- `MeridianSnapshot_CL`
- `MeridianNetwork_CL`
- `MeridianMySQL_CL`

---

## Important Investigation Notes

1. Use `EventTime_t` for the true incident timeline.
2. `TimeGenerated` represents Azure ingestion time, not the original event time.
3. Use `isnotempty(EventTime_t)` when possible to avoid malformed or leftover ingestion rows.
4. The Azure Logs time-range selector still filters by ingestion time, so the portal time picker had to cover the August 30 ingestion window even though the incident occurred on February 6.
5. Not every defensive detection represented attacker activity.
6. Several evidence gaps existed, so conclusions were based only on what the logs supported.

---

# 🕵️ Investigation Steps

## 1. Reconnaissance and Initial Web Activity

I began by isolating requests from the attacker/source IP and ordering them by the true event timestamp.

### KQL

```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| project EventTime_t, ClientIp_s, HttpMethod_s, RequestUri_s,
          StatusCode_s, ResponseSize_s, UserAgent_s
| order by EventTime_t asc
```

This revealed a reconnaissance sequence using tooling including:

- Nmap Scripting Engine
- `curl/8.18.0`
- WhatWeb
- Gobuster

The attacker manually probed the application before broader enumeration.

---

## 2. Traversal Through `config_viewer.php`

The attacker specifically interacted with the public-facing `config_viewer.php` endpoint.

### KQL

```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s contains "config_viewer.php"
| project EventTime_t, HttpMethod_s, RequestUri_s,
          StatusCode_s, UserAgent_s
| order by EventTime_t asc
```

To focus on activity after the application dashboard was reached:

```kql
MeridianAccess_CL
| where ClientIp_s == "10.1.134.57"
| where EventTime_t > datetime(2026-02-06 03:54:09)
| where RequestUri_s contains "config_viewer.php"
| project EventTime_t, HttpMethod_s, RequestUri_s,
          StatusCode_s, UserAgent_s
| order by EventTime_t asc
```

This exposed access to:

```text
/etc/passwd
database.conf
```

The `database.conf` retrieval was especially important because SSH access as `svc_backup` followed shortly afterward.

---

## 3. Compromised SSH Access

I pivoted into authentication telemetry to identify successful access from the attacker/source IP.

### KQL

```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where SourceIP == "10.1.134.57"
| where RawMessage_s contains "Accepted password"
| project EventTime_t, Hostname_s, ProcessName_s,
          SourceIP, SourcePort_s, TargetUser_s, RawMessage_s
| order by EventTime_t asc
```

This confirmed successful SSH authentication using the existing account:

```text
svc_backup
```

Example event:

```text
Accepted password for svc_backup from 10.1.134.57
```

This showed that the attacker reused an existing service account rather than creating a new one for initial SSH access.

---

## 4. Failed Privilege Escalation Attempts

Before obtaining root-level execution, the attacker checked whether `svc_backup` could use sudo.

### KQL

```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where RawMessage_s contains "command not allowed"
| project EventTime_t, Hostname_s, ProcessName_s, RawMessage_s
| order by EventTime_t asc
```

The log showed that `svc_backup` was not permitted to perform the requested sudo action.

The attacker also attempted to authenticate directly as root over SSH.

### KQL

```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where SourceIP == "10.1.134.57"
| where RawMessage_s contains "Failed password for root"
| project EventTime_t, SourceIP, SourcePort_s,
          TargetUser_s, RawMessage_s
| order by EventTime_t asc
```

These root login attempts failed.

---

## 5. SUID Root Shell

The attacker eventually obtained privileged execution through a SUID-root shell located in `/tmp`.

### KQL

```kql
MeridianAudit_CL
| where isnotempty(EventTime_t)
| extend EventData = tostring(pack_all())
| where EventData contains "/tmp/rootbash"
| project EventTime_t, EventData
| order by EventTime_t asc
```

The telemetry showed:

```text
/tmp/rootbash -p
```

with mode:

```text
0104755
```

The leading `4` indicates the SUID bit.

The `-p` flag preserved the shell's effective privileged identity.

---

## 6. Secondary Backdoor

A later automated IR sweep detected an unexpected file inside Meridian's scripts directory.

### KQL

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s contains "health_check"
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

The sweep logged:

```text
Non-baseline file in scripts/: health_check
```

The resulting path was:

```text
/opt/meridian/scripts/health_check
```

The defense system detected the artifact but did not automatically remove it.

---

## 7. Automated IR Sweep

To understand exactly what the defense stack remediated, I isolated the sweep events.

### KQL

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s == "SWEEP"
| project EventTime_t, RawMessage_s
| order by EventTime_t asc
```

The sweep performed actions including:

```text
SSH keys reverted
Crontabs reverted
Killing PID from /tmp
backup.conf tampered -- reverting
Temp dirs cleaned
Removed SUID: /tmp/rootbash
Non-baseline file in scripts/: health_check
```

The automated response removed the clearly malicious SUID shell in `/tmp`, but only reported the secondary `health_check` artifact.

---

## 8. Command-and-Control Activity

I searched the defense telemetry for blocked outbound connections.

### KQL

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s contains "Blocked exfil"
| project EventTime_t, SourceIP, DestIp_s,
          DestPort_s, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

This revealed repeated outbound communication attempts from:

```text
10.1.15.67
```

to:

```text
10.1.134.57:43212
```

The same activity was visible in kernel telemetry.

### KQL

```kql
MeridianSyslog_CL
| where isnotempty(EventTime_t)
| extend EventData = tostring(pack_all())
| where EventData contains "NETMON_EXFIL"
| where EventData contains "10.1.134.57"
| project EventTime_t, EventData
| order by EventTime_t asc
```

The defense stack blocked these specific outbound connections, but that did not prove the backdoor itself had been eradicated.

---

## 9. Configuration Tampering

The final sweep also identified application configuration tampering.

### KQL

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s contains "backup.conf"
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

Result:

```text
backup.conf tampered -- reverting
```

This showed that the attacker modified application configuration in addition to establishing persistence.

---

## 10. Automated Defense Collateral Damage

One of the most important findings was that automated remediation also damaged defensive visibility.

The first sweep removed systemd services that differed from its expected baseline.

### KQL

```kql
MeridianDefender_CL
| where RawMessage_s contains "Removed service"
| project EventTime_t, RawMessage_s
| order by EventTime_t asc
```

Results included:

```text
2026-02-06T03:08:19Z    Removed service: 60
2026-02-06T03:08:20Z    Removed service: sysmon.service
```

The significant legitimate service removed was:

```text
sysmon.service
```

### Investigation Impact

Removing Sysmon caused a host telemetry gap for the remainder of the incident, reducing visibility into:

- process execution
- parent/child process relationships
- network connections
- filesystem activity
- other host-level Sysmon telemetry

This demonstrated that automated remediation can cause forensic collateral damage when it blindly enforces a baseline.

---

## 11. Forensic Memory Capture

Near the end of the incident, a legitimate administrator returned to the system and captured volatile memory.

### KQL

```kql
MeridianAudit_CL
| where isnotempty(EventTime_t)
| extend EventData = tostring(pack_all())
| where EventData contains "avml"
| project EventTime_t, EventData
| order by EventTime_t asc
```

The logs showed AVML being executed twice:

```text
/tmp/avml /tmp/evidence/memory.lime
```

The captures occurred at approximately:

```text
05:27:48 UTC
05:28:24 UTC
```

The memory image was written to:

```text
/tmp/evidence/memory.lime
```

This preserved volatile evidence before final eradication actions.

---

## 12. Final Containment Requirement

The incident was not fully contained after the automated sweep.

The surviving artifact:

```text
/opt/meridian/scripts/health_check
```

still required manual responder action.

The final containment step was to manually kill the associated process and remove the malicious `health_check` artifact.

This was necessary because the sweep detected it but did not automatically remediate it.

---

# 🧠 Timeline of Key Events

| Time UTC | Event |
|---|---|
| 03:08 | Initial automated sweep removes `sysmon.service` |
| 03:52 | Manual web reconnaissance with `curl` |
| 03:52 | `/config_viewer.php` identified |
| 04:07 | `/etc/passwd` retrieved |
| 04:08 | `database.conf` retrieved |
| 04:09 | SSH access as `svc_backup` follows |
| 04:15 | `svc_backup` sudo privilege check fails |
| 04:40 | `/tmp/rootbash -p` executed |
| 04:44–04:46 | Failed SSH authentication attempts as `root` |
| 04:47–04:48 | `svc_backup` SSH activity continues |
| ~04:48 onward | Repeated C2/exfil communication attempts to `10.1.134.57:43212` |
| 05:05 | Automated IR sweep executes |
| 05:05 | `/tmp/rootbash` removed |
| 05:05 | `health_check` flagged but not removed |
| 05:05 | `backup.conf` reverted |
| 05:27 | AVML memory acquisition begins |
| 05:28 | Second AVML capture performed |

---

# 🛡️ Automated Response vs. Manual IR

| Defensive Action | Result |
|---|---|
| Block C2 connection | Prevented individual outbound connections |
| Revert SSH keys | Removed that persistence mechanism |
| Revert crontabs | Removed cron changes |
| Clean temporary directories | Removed `/tmp/rootbash` |
| Revert `backup.conf` | Restored configuration |
| Flag `health_check` | Detected only |
| Remove `sysmon.service` | Defensive collateral damage |
| Memory capture with AVML | Preserved volatile evidence |
| Manual removal of `health_check` | Required for final containment |

The presence of repeated blocked C2 traffic demonstrated that a firewall block alone was not evidence of eradication.

---

# 🚨 Indicators of Compromise

| Type | Indicator | Significance |
|---|---|---|
| Source/C2 IP | `10.1.134.57` | Attacker-controlled infrastructure in the lab |
| C2 Port | `43212` | Repeated outbound communication |
| Compromised Host | `10.1.15.67` | MeridianCare server |
| Compromised Account | `svc_backup` | Existing account used for SSH |
| Vulnerable Endpoint | `/config_viewer.php` | File traversal/config exposure |
| Privilege Escalation | `/tmp/rootbash` | SUID-root shell |
| Execution | `/tmp/rootbash -p` | Privileged shell execution |
| Secondary Backdoor | `/opt/meridian/scripts/health_check` | Persistent malicious artifact |
| Tampered Config | `backup.conf` | Modified and later reverted |
| Memory Tool | `/tmp/avml` | Legitimate responder activity |
| Memory Image | `/tmp/evidence/memory.lime` | Forensic capture |

---

# 📚 Key Lessons Learned

## 1. Event Time and Ingestion Time Are Different

This lab contained historical events that were ingested into Azure later.

Example:

```text
EventTime_t   = 2026-02-06
TimeGenerated = 2026-08-30
```

For attack reconstruction:

```kql
| where isnotempty(EventTime_t)
| order by EventTime_t asc
```

However, the Azure Logs time-range selector still operates on ingestion time. The portal time picker therefore had to cover the August 30 ingestion period before querying the February `EventTime_t` values.

This distinction explained several early "No results" queries.

---

## 2. Detection Does Not Equal Remediation

The defense system detected:

```text
Non-baseline file in scripts/: health_check
```

but did not remove it.

---

## 3. Blocking C2 Does Not Equal Containment

The defense repeatedly blocked connections to:

```text
10.1.134.57:43212
```

but the malicious implant remained present.

---

## 4. Automated Remediation Can Destroy Visibility

The baseline sweep removed:

```text
sysmon.service
```

even though it was legitimate defensive tooling.

That reduced endpoint visibility during the real attack.

---

## 5. Preserve Evidence Before Eradication

The administrator captured system memory with AVML before completing containment:

```text
/tmp/avml /tmp/evidence/memory.lime
```

This preserved volatile evidence that could have been destroyed by terminating processes or rebooting the host.

---

# Final Takeaway

This hunt demonstrated how a real investigation depends on more than simply finding malicious indicators.

The key skills were:

- reconstructing a timeline from multiple telemetry sources
- distinguishing attacker activity from defensive automation
- validating authentication and privilege escalation paths
- identifying persistence that survived automated remediation
- understanding the difference between detection, blocking, containment, and eradication
- preserving volatile evidence before taking destructive remediation actions
- recognizing how defensive tooling itself can create forensic blind spots

The final lesson was that an automated defense stack can help contain an intrusion, but human validation is still required before an incident can truly be considered contained.

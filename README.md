# SOC & Detection Engineering Internship Portfolio

> An eight-week Security Operations Center (SOC) internship at a national regulatory authority, covering network segmentation, threat hunting, SIEM/TIP integration, detection engineering, and traffic analysis.

---

## Overview

This repository documents technical work completed during an eight-week SOC internship at a national regulatory authority (air-gapped, regulated environment). The programme progressed from regulatory orientation and SOC fundamentals to independent engineering deliverables spanning network isolation, detection engineering, enterprise endpoint concepts, network traffic investigation, and a working SIEM-TIP intelligence pipeline.

All hands-on work was performed inside an access-controlled guest workstation with no external sharing, USB, or internet-upload access. Findings are therefore presented in narrative form. Code and configuration snippets in this repository are **illustrative reconstructions** (clearly labelled as such), not exported originals.

---

## Programme at a Glance

| Field              | Detail                                       |
| ------------------ | -------------------------------------------- |
| Role               | SOC Intern (Detection Engineering focus)     |
| Duration           | 8 weeks                                      |
| Domain             | National regulatory authority (critical infrastructure) |
| Placement          | Information security directorate             |
| Environment        | Air-gapped, access-controlled guest workstation |
| Focus areas        | Network segmentation, threat hunting, SIEM/TIP integration, detection engineering, traffic analysis |

---

## Skills Matrix

### Technical Skills

| Category                  | Skills / Tools                                                       |
| ------------------------- | -------------------------------------------------------------------- |
| Virtualization            | VMware Workstation Pro 17.6.4, Ubuntu 24.04.4 LTS guests             |
| Network segmentation      | Netplan, hypervisor virtual switches (NAT, Host-Only), `ip addr`     |
| Endpoint / EDR            | Sysmon (SwiftOnSecurity config), Windows Event Log, Kaspersky       |
| Log & traffic analysis    | Wireshark, Zeek 8.2.2, Splunk Enterprise, rsyslog, journalctl        |
| SIEM & TIP                | Wazuh manager/agent, MISP REST API, custom Python integration       |
| Detection engineering     | OpenIOC authoring, MD5/SHA-256 offline hash validation              |
| Threat hunting            | DeepBlueCLI, PowerShell, BOTSv1 dataset                              |
| Windows internals         | Event IDs 4624/4625/4720/4732/1102, audit policy, Get-WinEvent XML   |
| Linux fundamentals        | SSH auth logging, syslog facility/severity routing, fail2ban         |

### Professional Skills

- Structured technical reporting under formal academic and organisational standards
- Independent time management on constrained, individually assigned tasks
- Compliance with confidentiality and on-premise access controls
- Clear communication of findings to site supervisors within SOP frameworks

---

## Repository Structure

```
|-- README.md                                   <-- You are here
|-- REFERENCES.md                               <-- Citations and external references
|-- 01-vm-topology-isolation.md                 VMware + Netplan dual-VM segmentation
|-- 02-deepbluecli-threat-hunting.md            Windows .evtx threat hunting findings
|-- 03-zeek-splunk-pcap-analysis.md             PCAP -> Zeek -> Splunk investigation
|-- 04-sysmon-wazuh-misp-pipeline.md            Capstone SIEM-TIP integration pipeline
|-- 05-detection-engineering-openioc.md         OpenIOC artifacts for air-gapped malware
|-- 06-kaspersky-edr-lab-proposal.md            EDR operations model + lab proposal
|-- 07-day-03-windows-event-logging-sysmon.md   Daily log: Windows logging and Sysmon
|-- 07-day-04-linux-logging-syslog-journald.md  Daily log: Linux logging
```

---

## Chronological Timeline

| Period                         | Focus                                  | Principal Outcomes                                                                        |
| ------------------------------ | -------------------------------------- | ----------------------------------------------------------------------------------------- |
| Week 1                         | Orientation & regulatory familiarisation | Organisation policies, safety rules, premises and data-handling protocols                         |
| Week 2                         | SOC training & CTF log analysis        | Module assessments; individual completion of team-scale CTF challenges                     |
| Weeks 3-4                      | Single-NIC isolated dual-VM project   | VMware + Netplan micro-segmentation; bidirectional isolation verified                     |
| Week 5                         | Firewalls, Kaspersky, air-gapped ops   | Firewall fundamentals; Kaspersky logging; offline hash validation                         |
| Week 6                         | Networking, Linux logs, detection eng  | Wireshark/DNS study; journalctl/auth.log; OpenIOC air-gap artifacts; Sysmon (5 Aug)       |
| Weeks 7-8                      | SIEM-TIP pipeline & traffic analysis   | Sysmon -> Wazuh -> MISP alerts; Zeek/Splunk PCAP investigation                           |

---

## Featured Projects

### 1. Isolated Dual-VM Network Topology (Single Physical NIC)

Under the constraint of a single physical NIC, two Ubuntu 24.04.4 LTS guests were deployed on VMware Workstation Pro 17.6.4. Hypervisor virtual switches plus guest-side Netplan configuration enforced rigid Layer-3 micro-segmentation. VM1 (NAT/VMnet8, 192.168.30.128/24) retained outbound WAN access; VM2 (Host-Only/VMnet2, 192.168.17.128/24) became a private sandbox. Cross-zone ICMP tests in both directions returned `Network is unreachable`, confirming absolute isolation.

[Read the full writeup ->](01-vm-topology-isolation.md)

### 2. DeepBlueCLI Threat Hunting

Windows `.evtx` analysis using DeepBlueCLI surfaced four distinct attack patterns in cohort lab samples: password spray (Event ID 4648, 41 accounts targeted), Security log clearing (Event ID 1102) occurring ~40 seconds before the spray, WMI-launched `cmd.exe` with remote threads into `lsass.exe`/`winlogon.exe` (Event ID 8), and obfuscated PowerShell (Event ID 4104) referencing `Invoke-Expression`, `PowerSploit`, `Mimikatz`, and `DownloadString`.

[Read the full writeup ->](02-deepbluecli-threat-hunting.md)

### 3. Network Traffic Analysis: PCAP -> Zeek -> Splunk

Zeek 8.2.2 processed the exercise PCAP offline on an Ubuntu VMware guest; JSON logs were monitored into Splunk Enterprise (`index=zeek`, `sourcetype=zeek_json`). Dataset spanned 2024-09-01 to 2024-09-11 with 386 connection events from primary internal host `172.17.0.99`. One finding was flagged for follow-up: 68 connections (~75s avg) to external IP `79.124.78.197` with no preceding DNS resolution. No confirmed compromise; severity assessed as Low-Medium pending threat-intel lookup.

[Read the full writeup ->](03-zeek-splunk-pcap-analysis.md)

### 4. Capstone: Sysmon -> Wazuh -> MISP Alert Pipeline

End-to-end SIEM-TIP integration: Wazuh manager on Amazon Linux VM (10.0.0.14), MISP on Ubuntu (10.0.0.18), Windows endpoint with Sysmon and Wazuh agent (WIN-ENDPOINT). A custom Python integration (`custom-misp_file_hashes.py`) queried MISP's REST API for file-hash IOCs. On match, Wazuh raised rule 100802 (level 12) and pushed a sighting back to MISP, closing the enrichment loop. Three integration issues were systematically resolved: self-signed SSL on MISP, `tlp:white` tag-filter exclusion, and direct curl validation of API/credentials/hash.

[Read the full writeup ->](04-sysmon-wazuh-misp-pipeline.md)

### 5. Detection Engineering: OpenIOC for Air-Gapped / Removable-Media Malware

Companion Windows OpenIOC and Linux-native indicator documents authored for malware patterns that abuse removable media against air-gapped systems. Cross-platform mappings cover staging paths (FileItem vs hidden directory), file hashes, persistence (Run key vs cron/systemd), device recognition events (EventLogItem vs syslog/journalctl USB mount), and scheduled tasks (Windows Task Scheduler vs cron/systemd timer).

[Read the full writeup ->](05-detection-engineering-openioc.md)

### 6. Kaspersky-Centred EDR Operations Model & Lab Proposal

A conceptual operations model positioning Kaspersky Security Center as the central management and visibility platform for heterogeneous Windows/Linux estates. Documents the EDR workflow (`Document -> Script/PowerShell -> Executable -> Network connection -> Behavioural analysis -> Alert`) and the investigate-contain-eradicate-recover-monitor response loop. Includes a formal proposal for a dedicated cybersecurity development and test lab isolated from production, covering VMs, management server, EDR components, IOC repository, logging, and SOP documentation.

[Read the full writeup ->](06-kaspersky-edr-lab-proposal.md)

### 7. Daily Activity Logs

Focused daily writeups from the SOC training programme:

- [Day 3 - Windows Event Logging & Sysmon Setup](07-day-03-windows-event-logging-sysmon.md)
- [Day 4 - Linux Logging: Syslog, Journald, Authentication Logs](07-day-04-linux-logging-syslog-journald.md)

---

## Results Summary

| # | Deliverable                                                                         | Status |
| - | ----------------------------------------------------------------------------------- | ------ |
| 1 | Validated isolated dual-VM topology on single physical NIC (all verification cases PASS) | Done   |
| 2 | Kaspersky-centred monitoring/EDR concept + cybersecurity lab proposal              | Done   |
| 3 | Reusable Windows/Linux IOC artifacts for air-gap removable-media malware            | Done   |
| 4 | End-to-end Sysmon-Wazuh-MISP pipeline with confirmed level-12 hash-match alert     | Done   |
| 5 | Zeek/Splunk PCAP investigation: no confirmed compromise; one Low-Medium open IP    | Done   |
| 6 | Windows logging internals + Sysmon deployment readiness for SIEM ingestion         | Done   |
| 7 | Regulated-environment professional practice under strict on-premise data controls | Done   |

---

## Challenges, Constraints, and Mitigations

| Challenge                                                                 | Mitigation / Response                                                                                          |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| CTF / team exercises completed individually due to limited intern staffing | Prioritised roles sequentially; allocated fixed time blocks per analytical task                              |
| No export/USB/internet-upload on guest workstation; narrative-only evidence | Documented all work on-site; formal evidence to be issued by host institution if required                     |
| Single physical NIC for isolation project                                 | Hypervisor switch abstraction (VMnet8/VMnet2) plus Netplan micro-segmentation                                  |
| Kaspersky console and offline log complexity                               | Hands-on practice with supervisor guidance and internal documentation                                        |
| Wazuh-MISP SSL, tag-filter, and API validation issues                      | Systematic isolation: debug mode, curl replay, payload comparison, config correction                          |

---

## Key Learnings

- **Network segmentation is enforced at multiple layers.** Hypervisor-level switch separation combined with guest-side static Netplan is sufficient to achieve complete Layer-3 isolation on a single physical NIC, without dedicated hardware per environment.
- **Structured logs beat rendered text for automation.** PowerShell's `Get-WinEvent` XML output exposes System XML + EventData XML + Manifest Template, which is what SIEM platforms actually need. Plain-text messages are presentation-only.
- **SIEM-TIP integration fails silently in non-obvious ways.** Self-signed certificates, tag filters, and missing `tlp:white` markers each produced failures that looked like API problems. Systematic isolation via debug mode and curl replay was the only reliable triage method.
- **Volume + duration + missing DNS is a stronger signal than any single indicator.** The `79.124.78.197` finding was flagged not because of any one suspicious attribute, but because the combination was inconsistent with surrounding benign traffic.
- **Air-gapped environments demand offline-first detection patterns.** Hash validation, removable-media staging paths, and cross-platform persistence mappings cannot assume cloud lookups; they must be authored as local artifacts.

---

## References

See [REFERENCES.md](REFERENCES.md) for the full citation list covering Kaspersky, OpenIOC, Netplan, VMware, Zeek, Wazuh, MISP, and internal training materials.

---

## About

**Author:** Uliya Fatima  
**GitHub:** [your-github-username](https://github.com/your-github-username) <!-- TODO: replace with your real handle -->  
**Email:** your-email@example.com <!-- TODO: add your public email -->  
**Domain:** Cyber Security - SOC, Detection Engineering, Threat Intelligence

Organisation name, internal addresses and hostnames have been generalised (placeholder values such as `10.0.0.x` and `WIN-ENDPOINT` are used). This portfolio is shared for educational and professional showcase purposes. No proprietary data or real internal identifiers from the host environment are reproduced.

---

> Built during an eight-week SOC internship. Feedback and suggestions welcome via Issues.

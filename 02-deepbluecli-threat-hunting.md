# DeepBlueCLI Threat Hunting

> Analysing Windows Event Log (`.evtx`) files with DeepBlueCLI to identify password spraying, log clearing, WMI execution, and PowerShell obfuscation.

---

## Objective

Use DeepBlueCLI to analyse Windows Event Log (`.evtx`) files and identify suspicious activity such as password spraying, log clearing, WMI execution, and PowerShell obfuscation. The exercise demonstrates how a lightweight PowerShell-based hunting tool can surface high-signal indicators from native Windows telemetry, without requiring a full SIEM backend.

---

## Environment & Tools

| Component       | Detail                                                |
| --------------- | ----------------------------------------------------- |
| OS              | Windows                                               |
| Tool            | DeepBlueCLI                                           |
| Shell           | PowerShell                                            |
| Log format      | `.evtx`                                               |
| Install path    | `C:\Tools\DeepBlueCLI`                                |
| Repository      | Cloned from the public DeepBlueCLI GitHub repository |

DeepBlueCLI was installed by cloning the repository to `C:\Tools\DeepBlueCLI`, after which `DeepBlue.ps1` was visible and ready to invoke from PowerShell.

---

## Methodology

For each sample `.evtx` file, DeepBlueCLI was invoked directly with the path to the log file:

```powershell
.\DeepBlue.ps1 .\evtx\<sample>.evtx
```

The tool parses the `.evtx` structure, applies built-in detection heuristics for common attacker techniques, and outputs matched Event IDs with descriptive messages. The exercise covered four samples spanning authentication abuse, defense evasion, lateral movement primitives, and PowerShell-based execution.

---

## Findings

### Finding 1 - Password Spray Attack (Event ID 4648)

**Sample:** `password-spray.evtx`

DeepBlueCLI detected a Distributed Account Explicit Credential Use pattern consistent with a password spray attack. A single source account (`jwrig`) on host `DESKTOP-JR78RLP` attempted explicit credential use against 41 unique accounts - a volume and pattern characteristic of automated spraying tooling rather than interactive logon behaviour.

| Field                  | Value                                                             |
| ---------------------- | ----------------------------------------------------------------- |
| Event ID               | 4648                                                              |
| Detection              | Password Spray Attack                                             |
| Accounts targeted      | 41                                                                |
| Username               | jwrig                                                             |
| Host                   | DESKTOP-JR78RLP                                                   |
| Message                | Distributed Account Explicit Credential Use (Password Spray Attack) |

### Finding 2 - Security Audit Log Clear (Event ID 1102)

**Sample:** `password-spray.evtx` (same log)

The same log also contained an audit log clear event occurring approximately 40 seconds before the password spray detection. The combination is highly suspicious: clearing the Security log is a common defense-evasion technique used to remove evidence of preceding activity. The temporal correlation between the log clear and the spray strengthens the likelihood that the spray was the actual malicious activity the attacker sought to obscure.

| Field                  | Value                                  |
| ---------------------- | -------------------------------------- |
| Event ID               | 1102                                   |
| Detection              | Audit Log Clear                        |
| Account                | jwrig                                  |
| Time                   | 5/1/2019 12:27:00 AM                   |

> **Triage signal:** Log clearing immediately before a high-volume authentication anomaly is a classic paired indicator. In SOC triage, the pair should be treated as a single incident, not two separate events.

### Finding 3 - Suspicious WMI Execution & Remote Threads (Event ID 8)

**Sample:** `metasploit-sysmon.evtx`

Analysis of the Metasploit/Sysmon sample identified multiple process injection primitives consistent with post-exploitation framework behaviour. The notable chain was: WMI-launched `cmd.exe`, access to the `ADMIN$` share, and remote thread creation involving both `lsass.exe` and `winlogon.exe`.

Remote thread creation into `lsass.exe` is particularly significant because it is the canonical credential-dumping pattern used by tools such as Mimikatz. Thread injection into `winlogon.exe` is associated with process hollowing and token impersonation techniques.

| Field                  | Value                                  |
| ---------------------- | -------------------------------------- |
| Event ID               | 8                                      |
| Detection              | Suspicious remote thread               |
| Target processes       | lsass.exe, winlogon.exe                |
| Lateral indicator      | WMI-launched cmd.exe                   |
| Lateral indicator      | ADMIN$ share access                    |

### Finding 4 - Obfuscated PowerShell (Event ID 4104)

**Sample:** `Powershell-Invoke-Obfuscation-many.evtx`

The PowerShell obfuscation sample produced multiple Event ID 4104 detections (PowerShell ScriptBlock logging). DeepBlueCLI identified several high-signal string matches within the obfuscated command lines, each consistent with well-known offensive PowerShell tradecraft.

| Indicator                       | Significance                                                            |
| ------------------------------- | ----------------------------------------------------------------------- |
| `Invoke-Expression`              | Common obfuscation primitive used to evaluate encoded payloads          |
| `PowerSploit` references         | Reference to the PowerSploit post-exploitation framework                 |
| `Mimikatz` references            | Indicates credential dumping intent (`Invoke-Mimikatz.ps1`)             |
| `DownloadString`                 | Cradling pattern - remote script download and execution                 |
| Long / obfuscated commands      | Heuristic flag for encoded or chained payloads                          |

The combination of `DownloadString` + `Invoke-Expression` + `Mimikatz` reference is a strong indicator of a fileless attack chain: download a remote script, evaluate it in memory, and execute Mimikatz to harvest credentials without writing the binary to disk.

---

## Detection Summary

| # | Event ID | Detection                         | Sample                                | Severity    |
| - | -------- | --------------------------------- | ------------------------------------- | ----------- |
| 1 | 4648     | Password Spray (41 accounts)      | password-spray.evtx                   | High        |
| 2 | 1102     | Audit Log Clear (precedes spray)  | password-spray.evtx                   | High        |
| 3 | 8        | Remote thread into lsass/winlogon | metasploit-sysmon.evtx                | Critical    |
| 4 | 4104     | Obfuscated PowerShell (Mimikatz)   | Powershell-Invoke-Obfuscation-many.evtx | High        |

---

## Conclusion

The investigation demonstrated how DeepBlueCLI can assist with Windows threat hunting. The analysed samples contained indicators of password spraying, Security log clearing, suspicious WMI execution, possible process injection, and PowerShell obfuscation. The password-spray sample was particularly significant because 41 accounts were targeted and the Security audit log was cleared shortly before the detection - a paired indicator that should be escalated as a single incident in any real SOC workflow.

These findings should be further validated against additional authentication, process, and network logs during a real SOC investigation. DeepBlueCLI is best used as a first-pass triage tool: it rapidly narrows the surface area for deeper manual analysis with full SIEM correlation, packet capture, and endpoint EDR telemetry.

---

## Recommendations

1. **Forward PowerShell Event ID 4104 (ScriptBlock) and Sysmon Event ID 8 (RemoteThread) to SIEM.** These two event IDs alone cover a large fraction of fileless attack patterns.
2. **Configure alerting on Event ID 1102 (Audit Log Clear).** Log clearing outside of approved maintenance windows should trigger immediate review.
3. **Correlate 4648 with geographic / time anomalies.** Explicit credential use from unusual source hosts or outside business hours should raise the priority of any 4648 spike.
4. **Hunt for `Invoke-Expression` + `DownloadString` co-occurrence.** This pair is a near-certain cradle pattern and should be a saved detection rule.

---

## References

- DeepBlueCLI - https://github.com/sans-blue-team/DeepBlueCLI
- MITRE ATT&CK T1078 (Valid Accounts), T1070.001 (Clear Windows Event Logs), T1059.001 (PowerShell)
- SwiftOnSecurity Sysmon configuration - https://github.com/SwiftOnSecurity/sysmon-config

---

[<- Back to Portfolio README](README.md)

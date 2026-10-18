# Kaspersky-Centred EDR Operations Model & Cybersecurity Lab Proposal

> Conceptual operations model positioning Kaspersky Security Center as the central management and visibility platform for a heterogeneous Windows/Linux estate, plus a formal proposal for a dedicated cybersecurity development and test lab isolated from production.

---

## Part 1 - EDR Operations Model (Kaspersky-Centred)

### Objective

Document a conceptual operations model that positions Kaspersky Security Center (KSC) as the central management and visibility plane for a heterogeneous Windows/Linux enterprise estate. The model covers the full EDR event flow, from initial document-based IOCs through to alerting and the standardised incident-response loop.

### EDR Event Flow

The EDR workflow is documented as a linear pipeline that begins with knowledge of a threat (typically a published IOC document, vendor advisory, or internal hunt hypothesis) and ends with a behaviour-driven alert. Each stage feeds telemetry into the next, narrowing the surface area from "everything that happened" to "this specific behaviour is consistent with a known threat".

```
+------------+    +------------------+    +--------------+    +-----------------+    +----------------+    +---------+
| Document   |--->| Script /         |--->| Executable   |--->| Network         |--->| Behavioural    |--->| Alert   |
| (IOC,      |    | PowerShell       |    | (spawned     |    | connection      |    | analysis       |    | (raised |
|  advisory, |    | (loader /        |    |  child       |    | (C2 callback,   |    | (KSC heuristic |    |  in KSC |
|  hypothesis)|   |  dropper)        |    |  process)    |    |  staging upload)|    |  + sandbox)    |    |  console)|
+------------+    +------------------+    +--------------+    +-----------------+    +----------------+    +---------+
```

| Stage                       | Description                                                                                          |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| 1. Document                 | Threat intelligence input (IOC, advisory, hunt hypothesis) drives configuration of detection rules. |
| 2. Script / PowerShell      | Loader or dropper stage - often obfuscated PowerShell or signed-binary script abuse.                 |
| 3. Executable               | Spawned child process from the loader. KSC records process lineage via the endpoint agent.            |
| 4. Network connection       | Outbound connection to C2, staging host, or exfiltration endpoint. Captured by endpoint firewall log. |
| 5. Behavioural analysis    | KSC heuristic engine correlates the above stages and matches against behavioural signatures.          |
| 6. Alert                    | A consolidated alert is raised in the KSC console with full kill-chain context.                       |

### Incident Response Loop

Once an alert is raised, the response follows the standard SANS-aligned incident-handling loop:

```
Investigate -> Contain -> Eradicate -> Recover -> Monitor
    ^                                                          |
    |__________________________________________________________|
                          (feedback)
```

| Phase       | Action                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------- |
| Investigate | Pivot from alert context to full kill-chain: process tree, network flows, file modifications. |
| Contain     | Isolate affected endpoint (network quarantine via KSC), suspend suspicious processes.          |
| Eradicate   | Remove persistence (Run keys, scheduled tasks, services, malicious files).                    |
| Recover     | Restore from known-good backup; re-image if integrity is in doubt.                          |
| Monitor     | Add the specific IOC and behavioural signature to active monitoring; verify the loop closes. |

---

## Part 2 - Cybersecurity Development & Test Lab Proposal

### Rationale

Detection engineering, IOC validation, and EDR configuration changes should never be tested in production. A dedicated, isolated lab is the lowest-risk mechanism for validating detections before they touch live endpoints. This proposal recommends establishing a cybersecurity development and test lab that is fully isolated from production networks, with controlled egress for threat-intel feed retrieval only.

### Proposed Lab Architecture

```
+----------------------------------------------------------+
|         Cybersecurity Development & Test Lab            |
|         (VLAN-isolated, egress via controlled proxy)     |
|                                                          |
|  +----------------+   +-----------------+                 |
|  | Windows VM     |   | Linux VM        |                |
|  | (test endpoint)|   | (test endpoint) |                |
|  +-------+--------+   +--------+--------+                |
|          |                      |                         |
|          +----------+-----------+                         |
|                     |                                     |
|          +----------+---------+                           |
|          | KSC Management VM |<--+ controlled proxy       |
|          | (KSC + EDR)        |   | (CVE feeds, MISP)      |
|          +--------------------+   +-------------------+    |
|                                                       |    |
|  +----------------+    +----------------+              |    |
|  | IOC repository |    | Logging VM     |              |    |
|  | (YARA, OpenIOC)|    | (Wazuh/Splunk) |              |    |
|  +----------------+    +----------------+              |    |
|                                                       |    |
+-------------------------------------------------------|----+
                                                        |
                                              +---------+---------+
                                              | Controlled Egress |
                                              | (signed feeds)   |
                                              +-------------------+
```

### Lab Components

| Component                    | Purpose                                                                                   |
| ---------------------------- | ----------------------------------------------------------------------------------------- |
| Windows test VM               | Endpoint for Sysmon/KSC agent installation, malware detonation, detection tuning          |
| Linux test VM                 | Endpoint for `auditd`/OSSEC/Wazuh agent, Linux-specific detections                        |
| KSC management VM             | Kaspersky Security Center administration console + EDR policy authoring                    |
| IOC repository                | Curated OpenIOC/YARA bundle, version-controlled, signed                                    |
| Logging VM                    | Wazuh or Splunk aggregator for centralised test telemetry                                  |
| Controlled egress proxy       | Whitelisted upstream for MISP/abuse.ch/CIRCL feed retrieval only; everything else blocked   |
| SOP documentation             | Lab usage SOP, detonation procedure, sanitisation checklist                                |

### Why Isolate the Lab

| Risk if lab is not isolated                          | Mitigation provided by isolation                                            |
| ---------------------------------------------------- | --------------------------------------------------------------------------- |
| Malware sample detonation leaks into production      | Air-gapped or strictly VLAN-separated lab network                          |
| Misconfigured EDR policy degrades production endpoints | All EDR policy changes validated in lab before staged rollout            |
| Test IOCs pollute production SIEM with false positives | Lab SIEM is independent; only validated detections migrate to production   |
| Uncontrolled outbound egress from malware samples     | Controlled egress proxy permits only known feed endpoints                   |

### SOP Highlights (Recommended)

1. **No sample leaves the lab.** All malware samples, detonation outputs, and IOCs remain inside the lab network. IOCs destined for production are exported only as signed hash lists.
2. **Detonation in snapshot-revertable VMs.** Each detonation runs in a fresh VM snapshot, reverted immediately after the test.
3. **Time-boxed tests.** Each policy or detection change is validated against a defined test matrix (true positive, true negative, false positive, false negative) within a fixed time window.
4. **Signed egress only.** Outbound from the lab is permitted only to a pre-approved, signed feed list (MISP, abuse.ch, CIRCL). Everything else is logged and denied.
5. **Quarterly review.** Re-evaluate the lab's component versions, test matrix coverage, and SOP adherence on a fixed quarterly cadence.

---

## Conclusion

A Kaspersky-centred operations model provides a coherent EDR pipeline from threat-intel input through to behaviour-driven alerting, with the standard investigate-contain-eradicate-recover-monitor loop closing the response cycle. Pairing this operations model with a dedicated, isolated cybersecurity development and test lab removes the most common deployment risk - testing in production - and creates a sustainable foundation for detection engineering maturity.

---

## Recommendations

1. **Adopt the proposed lab as a strategic capability**, not a one-off project. Budget for VM licensing, management-server maintenance, and a fixed weekly time block for detection tuning.
2. **Version-control the IOC repository** in Git (internal instance) with signed commits. Every IOC should carry an attribution (`source`, `first_seen`, `TLP classification`).
3. **Cross-train analysts on both KSC and an open-source EDR (Wazuh).** Vendor lock-in is a strategic risk in regulated environments.
4. **Feed lab detections into production SIEM via signed, reviewed export.** Never wire the lab directly to production - always go through a human-in-the-loop review.
5. **Establish a quarterly red-team-vs-blue-team exercise** in the lab to validate the full detect-respond loop end-to-end.

---

## References

- Kaspersky Security Center documentation - https://support.kaspersky.com/KSC
- Kaspersky Endpoint Security documentation
- MITRE ATT&CK Enterprise Matrix - https://attack.mitre.org/
- NIST SP 800-61 (Computer Security Incident Handling Guide)
- SANS Incident Handler's Handbook

---

[<- Back to Portfolio README](README.md)

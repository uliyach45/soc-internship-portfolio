# Capstone: Sysmon -> Wazuh -> MISP Alert Pipeline

> End-to-end SIEM-TIP integration correlating Sysmon endpoint telemetry through Wazuh with MISP threat intelligence, producing a level-12 hash-match alert and a sighting-feedback loop back to MISP.

---

## Objective

Build and validate an end-to-end detection pipeline that combines endpoint telemetry (Sysmon), a SIEM/correlation engine (Wazuh), and a threat intelligence platform (MISP) into a single closed-loop workflow. On a successful IOC match, the pipeline must (1) raise a high-severity alert in Wazuh, and (2) push a sighting back to MISP, enriching the threat-intel record with the observation.

---

## Architecture

```
+-------------------------+        +-------------------------+        +---------------------+
|  Windows Endpoint       |        |  Wazuh Manager          |        |  MISP (TIP)          |
|  WIN-ENDPOINT        |        |  Amazon Linux VM        |        |  Ubuntu VM           |
|                         |        |  10.0.0.14         |        |  10.0.0.18      |
|  +-------------------+  |        |                         |        |                     |
|  | Sysmon            |--+--------+->  Wazuh Agent  +--------+--------+->  REST API          |
|  +-------------------+  |  secure |                   JSON  |  HTTP/ |                     |
|  +-------------------+  |  channel|                         |  HTTPS |  IOC repository      |
|  | FIM / syscheck    |--+--------+->  Correlation         |        |                     |
|  +-------------------+  |        |  Rule 100802 (L12)     |        |  Sighting feedback   |
|                         |        |  Custom integration     |        |  (POST /sightings)   |
+-------------------------+        +-------------------------+        +---------------------+
                                          |
                                          v
                                     Alert fired
```

### Environment

| Component                  | Host                           | IP                | Role                                |
| -------------------------- | ------------------------------ | ----------------- | ----------------------------------- |
| Wazuh Manager              | Amazon Linux VM                | 10.0.0.14    | Centralised log collection + rules  |
| MISP                       | Ubuntu VM                      | 10.0.0.18    | Threat intelligence platform        |
| Windows endpoint           | WIN-ENDPOINT                | -                 | Sysmon + Wazuh agent source          |
| Custom integration script  | Wazuh manager                  | -                 | `custom-misp_file_hashes.py`        |

---

## Pipeline Components

| Component                | Function                    | Outcome                                            |
| ------------------------ | --------------------------- | -------------------------------------------------- |
| Sysmon                   | Process/file telemetry      | Detailed Windows endpoint events                    |
| Wazuh Agent              | Forward events              | Centralised collection                              |
| Wazuh Manager            | Correlate / analyse         | SIEM visibility                                     |
| MISP                     | Store/serve IOCs            | Threat intelligence source                          |
| Custom Python script     | Hash lookup                 | Automated correlation against MISP                  |
| Rule 100802              | IOC match alert             | Level-12 high-severity alert                        |
| Sighting feedback        | Report match to MISP         | Intelligence enrichment loop                        |

---

## Implementation

### 1. Sysmon Deployment on the Windows Endpoint

Sysmon was deployed with the SwiftOnSecurity community configuration to maximise coverage of process creation, network connections, file creation time changes, and driver/module loading. Sysmon events feed into the Wazuh agent's local event channel for forwarding to the manager.

### 2. Wazuh Manager Configuration

The Wazuh manager on Amazon Linux (10.0.0.14) was configured to:
- Receive forwarded Sysmon events from the Windows agent.
- Run File Integrity Monitoring (syscheck) for changes to sensitive paths.
- Evaluate custom local rules for IOC-hash matches against MISP-curated indicators.

### 3. Custom Python Integration (`custom-misp_file_hashes.py`)

A custom Python integration was authored on the Wazuh manager to query MISP's REST API for file-hash IOCs. On each Sysmon-reported file hash event, the script:

1. Extracts the observed SHA-256/MD5 hash from the alert payload.
2. Issues a POST to MISP's `/attributes/restSearch` endpoint, filtered to `tlp:white` (shareable) indicators.
3. Parses the JSON response; on `"response": {"Attribute": [...]}` containing matches, raises an alert via Wazuh's integration framework.
4. On match, issues a POST to MISP's `/sightings/add` endpoint to feed the observation back into the threat-intel platform.

### 4. Custom Rule 100802 (Level 12)

A local rule in Wazuh's `local_rules.xml` matched the script's alert payload and raised a level-12 (high-severity) alert:

> **Illustrative example:** reconstructed to show the rule logic; not the original configuration file.

```xml
<rule id="100802" level="12">
    <if_group>sysmon_file_hash</if_group>
    <field name="misp.match">^1$</field>
    <description>Sysmon-reported file hash matched a MISP IOC</description>
    <group>sysmon,misp,ioc_match,</group>
</rule>
```

---

## Troubleshooting - Issues Resolved

Three integration issues were systematically resolved before the pipeline produced a successful detection:

### Issue 1 - Self-signed SSL on MISP caused silent script failure

**Symptom:** The custom Python script terminated silently with exit status `4` whenever it tried to contact the MISP API.

**Root cause:** MISP was running behind a self-signed TLS certificate. The Python `requests` library refused to complete the TLS handshake, and the integration framework treated the silent exit as a non-event.

**Resolution (lab only):** Disabled certificate verification on the API calls inside the integration script by setting `verify=False`. This is acceptable in a lab setting where MISP and the Wazuh manager are on the same trust boundary, but **must not** be carried into production - production deployments should install MISP's CA certificate into the Wazuh manager's trust store and keep `verify=True`.

### Issue 2 - Direct curl validation confirmed MISP API, credentials, and stored hash were correct

**Symptom:** Even after disabling SSL verification, the script reported no matches. The integration appeared to be working but produced no detections.

**Diagnostic step:** Bypassed the script entirely and issued a direct `curl` against the MISP REST API using the same auth key and the same hash known to exist in the MISP database:

> **Illustrative example:** generic form of the curl check (API key and hash replaced with placeholders).

```bash
curl -k -H "Authorization: <API_KEY>" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{"returnFormat":"json","value":"<KNOWN_HASH>"}' \
     https://10.0.0.18/attributes/restSearch
```

This direct curl returned a successful match. That proved three things: the API was reachable, the API key was valid, and the target hash actually existed in MISP. The problem therefore had to be in the script's request construction or filtering, not in MISP itself.

### Issue 3 - `tlp:white` tag filter excluded untagged events

**Symptom:** The script was constructing requests correctly but returning `"response": []` (empty) for hashes that curl had just confirmed existed.

**Root cause:** The script's POST body included a `tags` filter set to `tlp:white`. The hash stored in MISP existed but had not been tagged with `tlp:white`, so it was excluded from the filtered search - even though it was otherwise a valid IOC.

**Resolution:** Removed the `tags` filter from the script's request body. After this change, the same query returned `"found": 1` matches and triggered rule 100802. The sighting was then successfully pushed back to MISP.

---

## Verification

| Step                                                            | Result                                                  |
| --------------------------------------------------------------- | ------------------------------------------------------- |
| Sysmon reporting file events to Wazuh                           | Confirmed via `tail -f /var/ossec/logs/alerts/alerts.log` |
| Custom integration script reaches MISP API                      | Confirmed via successful curl replay                    |
| MISP returns match for known hash                               | Confirmed (`"found": 1`)                                |
| Wazuh rule 100802 fires                                          | Confirmed at severity level 12                         |
| Sighting pushed back to MISP                                     | Confirmed via MISP UI sighting record                   |

---

## Sample Alert Output

> **Illustrative example:** sample alert layout with placeholder values, not an exported log.

```
**Alert 100802 - Level 12**
**Rule groups:** sysmon, misp, ioc_match
**Source:** WIN-ENDPOINT
**Title:** Sysmon-reported file hash matched a MISP IOC

Field: sysmon.file.hash        = <SHA-256 of observed file>
Field: misp.match              = 1
Field: misp.attribute_id       = <MISP attribute ID>
Field: misp.event_id           = <MISP event ID>
```

---

## Conclusion

The capstone successfully demonstrates a closed-loop SIEM-TIP integration: endpoint telemetry collected by Sysmon is forwarded by Wazuh, correlated against MISP-curated IOCs by a custom Python integration, and on match both raises a high-severity alert and feeds the observation back to MISP as a sighting. The three issues encountered during integration (self-signed SSL, tag filtering, request-construction validation) are representative of real-world SIEM-TIP integration pitfalls and the systematic triage approach used - debug mode, curl replay, payload comparison, config correction - is reproducible for similar future deployments.

---

## Recommendations

1. **Subscribe Wazuh/MISP to live threat-intelligence feeds** (e.g. CIRCL, abuse.ch, MITRE ATT&CK STIX bundles) so production IOCs populate automatically instead of manual test hashes.
2. **Re-enable TLS verification in production.** Install MISP's CA certificate into the Wazuh manager's trust store and set `verify=True` in the integration script.
3. **Tag discipline in MISP.** Establish an SOP requiring every imported IOC to carry at minimum a `tlp:white|green|amber|red` classification so tag-based filtering becomes safe and useful.
4. **Alert tuning.** Consider raising rule 100802 to trigger an active response (e.g. agent isolation) when the match is on a hash associated with known ransomware families.
5. **Sighting-based decay.** Use the sighting feedback to feed back into detection quality - IOCs observed in production should be reviewed for continued relevance and retired when stale.

---

[<- Back to Portfolio README](README.md)

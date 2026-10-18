# Network Traffic Analysis: PCAP -> Zeek -> Splunk

> Offline PCAP processing with Zeek 8.2.2, log forwarding to Splunk Enterprise, and dashboard-driven investigation of 386 connection events from a primary internal host.

---

## Executive Summary

Zeek analysis of network traffic from internal host `172.17.0.99` (capture window 2024-09-01 to 2024-09-11) identified 386 connection events. The overwhelming majority of this traffic - internal communication and connections to well-known Microsoft Azure and Akamai CDN address ranges - is consistent with routine Windows Update, Office 365, and telemetry activity, and no evidence of malicious activity was found in these. One item was flagged for follow-up: 68 connections (avg duration ~75 seconds) from `172.17.0.99` to external IP `79.124.78.197`, which stood out due to its disproportionate volume, duration, and the absence of a preceding DNS resolution in the captured `dns.log` - a pattern atypical of ordinary application traffic.

**Overall verdict:** No confirmed compromise. Severity of the open item (`79.124.78.197`) is assessed as Low-Medium pending threat-intel confirmation. No further indicators of lateral movement, data exfiltration, or command-and-control were observed in the reviewed logs.

| # | Finding                                                                                     | Severity        |
| - | ------------------------------------------------------------------------------------------- | --------------- |
| 1 | Disproportionate external connection volume to `79.124.78.197` (68 conns, ~75s avg, no preceding DNS) | Low-Medium    |
| 2 | Remaining external connections (Microsoft Azure/Akamai CDN ranges) - routine Windows/O365 telemetry | Informational / Benign |
| 3 | DNS query set - standard Windows/O365 telemetry domains and internal AD SRV lookups only    | Informational / Benign |

---

## Scope and Objectives

### Scope

| Field              | Detail                                                                                   |
| ------------------ | ---------------------------------------------------------------------------------------- |
| PCAP file          | `2024-09-04-exercise`                                                                    |
| Internal host      | `172.17.0.99` (primary source)                                                            |
| Internal subnet    | `172.17.0.0/24`                                                                          |
| External destinations observed | `79.124.78.197`, `20.189.173.18`, `20.10.31.115`, others (CDN ranges)           |
| AD domain         | `bepositive.com`                                                                          |
| Capture window    | 2024-09-01 to 2024-09-11                                                                 |

### Objectives

- Reconstruct network sessions and protocol activity from raw packet data.
- Identify indicators of suspicious, anomalous, or malicious activity.
- Correlate Zeek-derived logs in Splunk to build a timeline of events.
- Produce actionable findings and recommendations for the SOC/IR team.

---

## Tools and Environment

| Component                                                                  | Purpose                                                                  | Version / Notes                                                                                                                                  |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Zeek                                                                       | Deep packet inspection of PCAP; generates protocol-level logs            | version 8.2.2                                                                                                                                    |
| Splunk Enterprise                                                          | Centralised log indexing, search (SPL), and dashboarding                 | Splunk Enterprise                                                                                                                                |
| Splunk Add-on for Zeek/Bro (or Splunk-Stream/CIM app)                      | Parses Zeek TSV/JSON logs into Splunk fields                              | Not used - logs ingested in native Zeek JSON format (`sourcetype=zeek_json`) directly, without a dedicated Zeek/Bro parsing add-on                 |
| Splunk Universal Forwarder / Filebeat                                       | Forwards Zeek logs from analysis host into Splunk indexers                | No forwarder used - native Splunk file monitor input configured directly on the Splunk instance via `inputs.conf`                                |
| Analysis workstation / VM                                                  | Host running Zeek against the PCAP                                        | Ubuntu (VMware Virtual Platform), hostname: `ubuntu-VMware-Virtual-Platform`                                                                   |

---

## Methodology

The analysis followed a four-stage pipeline: packet capture ingestion, Zeek processing, log forwarding to Splunk, and dashboard-driven investigation.

### Stage 1 - Processing the PCAP with Zeek

Zeek was run in offline (read) mode against the captured PCAP file to generate protocol-aware logs rather than analysing raw packets directly. Analysis was performed on an Ubuntu VM under the working directory `~/zeek-analysis/2024-09-04-exercise`, with output logs organised into subfolders (`zeek-splunk`, `zeek-splunk-reindex`) for staged ingestion into Splunk.

```bash
zeek --version
zeek -r 2024-09-04-exercise.pcap local LogAscii::use_json=T
```

Logs were generated in JSON output format (one JSON object per line), rather than the default tab-separated (TSV) format. This is reflected in the `dns.log` excerpt and confirmed by the Splunk sourcetype used downstream (`zeek_json`).

This run produced the full standard Zeek log set for the traffic observed:

| Log file                                                                | Contents                                                                                       |
| ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `conn.log`                                                              | Every connection/flow: src/dst IP & port, protocol, duration, bytes, state                     |
| `dns.log`                                                              | DNS queries and responses                                                                     |
| `http.log`                                                              | HTTP requests/responses, user agents, URIs, status codes                                       |
| `ssl.log` / `x509.log`                                                  | TLS handshake metadata and certificate details                                                |
| `files.log`                                                            | Files extracted/observed in transit (hashes, MIME types)                                       |
| `kerberos.log` / `ntlm.log` / `ldap.log` / `ldap_search.log`           | Windows authentication and directory-service activity                                           |
| `dhcp.log`                                                            | DHCP lease/address assignment activity                                                         |
| `dce_rpc.log` / `smb_files.log` / `smb_mapping.log`                     | Windows file-sharing and RPC activity                                                          |
| `quic.log` / `ocsp.log`                                                | QUIC transport and certificate revocation checks                                               |
| `packet_filter.log`                                                    | Zeek's own capture-filter status                                                                |

### Stage 2 - Forwarding Zeek Logs to Splunk

Zeek's JSON-formatted logs were ingested into Splunk directly on the same host - no separate Universal Forwarder was used. Splunk Enterprise was configured with a native file monitor input pointed at the Zeek log output directory, defined in a local `inputs.conf` on the Splunk instance itself:

```ini
[monitor:///home/ubuntu/zeek-analysis/zeek-splunk-reindex]
disabled = false
```

Configuration was confirmed via `btool`:

```bash
sudo /opt/splunk/bin/splunk cmd btool inputs list --debug | grep -A2 zeek-splunk-reindex
```

Data was indexed under `index=zeek` with `sourcetype=zeek_json`, consistent with Zeek's JSON log output format.

#### Verifying Ingestion

```spl
index=zeek sourcetype=zeek_json | stats count by sourcetype
```

### Stage 3 - Splunk Dashboard Analysis

Ingested Zeek data was investigated in Splunk's search interface. An initial scoping search confirmed the dataset and surfaced the primary internal host and its communication partners:

```spl
index=zeek sourcetype=zeek_json
| table _time ts uid id.orig_h id.resp_h
| head 20
```

This search returned **386 events** across the full time range. The internal host `172.17.0.99` (`id.orig_h`) accounts for the large majority of connections, communicating with:

- `172.17.0.17` internal host (repeated, high-frequency connections)
- `224.0.0.251` multicast (mDNS), expected background traffic
- `79.124.78.197`, `20.189.173.18`, `20.10.31.115` external IPs (see Findings)

#### Dashboard Panels (SPL queries)

| Panel                          | Purpose                                              | SPL                                                                                       |
| ------------------------------ | ---------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Top talkers                    | Identify hosts generating the most traffic/connections | `index=zeek sourcetype=zeek_json \| stats count by id.orig_h,id.resp_h \| sort -count`     |
| External destinations          | Isolate outbound connections to non-internal IPs      | `index=zeek sourcetype=zeek_json \| stats count by id.resp_h \| sort -count \| head 10`  |
| DNS query volume / rare domains | Surface unusual or low-frequency domains             | `index=zeek sourcetype=zeek_json query=* \| stats count by query \| sort count \| head 20` |
| Long-duration / beaconing connections | Detect periodic C2-style beacons                | `index=zeek sourcetype=zeek_json \| stats count avg(duration) by id.orig_h,id.resp_h \| where count>20` |
| HTTP user agents / URIs        | Identify suspicious clients or requests              | `index=zeek sourcetype=zeek_json http_method=* \| stats count by user_agent,uri`         |
| Geo / external destinations     | Map outbound connections to external ASNs/countries  | `index=zeek sourcetype=zeek_json \| iplocation id.resp_h \| stats count by Country`       |

#### Confirmed Panel Results

The **External Destinations** panel confirms the ranking of outbound contacts from `172.17.0.99`:

| Destination IP       | Connection Count | Classification                          |
| -------------------- | ---------------- | --------------------------------------- |
| 172.17.0.17          | 227              | Internal host                           |
| 172.17.0.255         | 25               | Internal broadcast                      |
| **79.124.78.197**    | **68**           | **External - flagged for follow-up**    |
| 23.45.119.144        | single digit     | Akamai CDN - benign                     |
| 204.79.197.203       | single digit     | Microsoft - benign                      |
| 52.113.194.132       | single digit     | Microsoft Azure - benign                |
| 23.195.212.189       | single digit     | Akamai CDN - benign                     |
| 20.189.173.18        | single digit     | Microsoft Azure - benign                |
| 20.96.153.111        | single digit     | Microsoft Azure - benign                |

`79.124.78.197` stands out sharply with 68 connections - an order of magnitude above the next external IP. The remaining external addresses each have single-digit connection counts and fall within known Microsoft Azure / Akamai CDN address ranges, consistent with routine Windows Update, Office 365, and telemetry traffic.

The **beaconing/duration** panel adds average connection duration per pair. `172.17.0.99 -> 79.124.78.197` shows 68 connections at an average duration of ~75 seconds - both the count and duration are the highest of any non-broadcast pairing in the dataset, which is why this destination is carried forward as the primary finding.

The **DNS query panel** (106 distinct query events) was also reviewed. Observed queries are dominated by standard Windows/Office 365 telemetry and update domains (`windowsupdate.com`, `*.office.com`, `onecollector...sfx.ms`, `live.com`, Adobe update check), along with internal Active Directory SRV lookups (`_ldap._tcp...` resolving against `bepositive.com`, the environment's internal AD domain). No queries to newly-registered, algorithmically-generated, or otherwise suspicious-looking domains were observed in this sample.

---

## Detailed Findings

### Finding 1 - Disproportionate external connection volume to 79.124.78.197

| Field             | Detail                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- |
| Severity          | Low-Medium (unconfirmed - flagged for follow-up, not a confirmed compromise)                                          |
| Source(s)         | `conn.log` via Splunk (`index=zeek sourcetype=zeek_json`)                                                              |
| Affected host(s)  | `172.17.0.99` (internal source) to `79.124.78.197` (external)                                                         |
| Description       | Internal host `172.17.0.99` made 68 connections to external IP `79.124.78.197` during the capture window (2024-09-01 to 2024-09-11), averaging roughly 75 seconds per connection. This volume and duration are both notably higher than any other external destination observed, all of which fell within known Microsoft Azure/Akamai CDN ranges at single-digit connection counts. `79.124.78.197` did not resolve to a recognizable Microsoft/CDN range and was not preceded by a corresponding DNS query in the reviewed `dns.log` sample, which is atypical for legitimate application traffic. |
| Evidence          | External Destinations panel (68 connections); Beaconing/duration panel (~75s avg)                                    |
| Recommended next step | Run WHOIS / passive DNS / threat-intel lookup (e.g. VirusTotal, AbuseIPDB) on `79.124.78.197`; if unresolved, inspect payload/session content for this pair in `conn.log` or full packet capture if retained |

> **Triage note:** The absence of DNS resolution alone is not conclusive - some legitimate services connect by static/pinned IP without a preceding DNS lookup in a given sample window. The combination of volume, duration, and missing DNS is what makes this finding inconsistent with normal background traffic and warrants follow-up.

### Finding 2 - Remaining external connections (benign, CDN/telemetry)

The remaining external addresses observed (`23.45.119.144`, `204.79.197.203`, `52.113.194.132`, `23.195.212.189`, `20.189.173.18`, `20.96.153.111`), together with the DNS query set, are consistent with routine Windows/Office 365 update and telemetry traffic. No further action is recommended for these unless a future finding correlates them with suspicious activity.

---

## Indicators of Compromise (IOCs)

| Type                           | Value                                                                                                  | Context                                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| IP (unconfirmed - under review) | `79.124.78.197`                                                                                        | 68 connections from `172.17.0.99`, avg duration ~75s, no preceding DNS resolution - pending WHOIS/TI confirmation |
| IP (benign - CDN/telemetry)     | `20.189.173.18`, `23.45.119.144`, `204.79.197.203`, `52.113.194.132`, `23.195.212.189`, `20.96.153.111` | Single-digit connection counts, consistent with Microsoft Azure/Akamai CDN ranges                     |
| Domain                          | [none flagged]                                                                                          | DNS query set contained only standard Windows/Office 365 telemetry domains and internal AD SRV lookups |
| File hash                      | [SHA256 - if extracted via `files.log` and relevant to Finding 1]                                       | Pending correlation                                                                                  |

---

## Conclusion and Recommendations

### Conclusion

No confirmed malicious activity was identified in this dataset. The large majority of network activity from `172.17.0.99` - internal traffic and connections to well-known Microsoft/Akamai CDN ranges - is consistent with normal Windows/Office 365 background activity. One item remains open: the disproportionate connection volume and duration to `79.124.78.197`, which does not fit the pattern of the surrounding benign traffic and was not resolved via DNS in the observed sample. This is flagged as a follow-up item rather than a confirmed incident.

### Recommendations

1. **Run WHOIS / passive DNS / threat-intelligence lookup** (VirusTotal, AbuseIPDB, or equivalent) on `79.124.78.197` to determine ownership and reputation before further action.
2. **Conditional host isolation.** If `79.124.78.197` proves unattributed or malicious, isolate `172.17.0.99` for deeper forensic review and consider blocking the IP at the firewall/proxy.
3. **Saved Splunk alert for repeat patterns.** Add a saved search/alert for repeat high-volume connections to IPs outside known-good CDN ranges, to catch similar patterns automatically going forward.
4. **Future ingestion of `notice.log` / `weird.log`.** When available in a future capture, ingest them into the same Splunk index - Zeek's own built-in detections would strengthen this kind of triage.

---

## Appendix

### A. Full Zeek Log Field Reference

Key fields referenced during this analysis, from Zeek's JSON log schema (`zeek_json` sourcetype):

| Field                       | Meaning                                                                      |
| --------------------------- | ---------------------------------------------------------------------------- |
| `ts`                        | Event timestamp (epoch seconds)                                              |
| `uid`                       | Unique connection identifier, correlates a session across log types          |
| `id.orig_h` / `id.orig_p`   | Originating (source) IP address / port                                       |
| `id.resp_h` / `id.resp_p`   | Responding (destination) IP address / port                                   |
| `duration`                  | Connection duration in seconds (`conn.log`)                                  |
| `query`                     | DNS query string (`dns.log`)                                                 |
| `qclass_name`               | DNS query class (e.g. `C_INTERNET`)                                          |
| `answers` / `TTLs`          | DNS resolved answers and their TTL values (`dns.log`)                        |
| `rejected`                  | Whether the DNS query was rejected (`dns.log`)                               |

### B. Raw SPL Queries Used

```spl
-- 1. Ingestion check
index=zeek sourcetype=zeek_json | stats count by sourcetype

-- 2. Initial scoping (386 events)
index=zeek sourcetype=zeek_json
| table _time ts uid id.orig_h id.resp_h
| head 20

-- 3. External destinations ranked by connection count
index=zeek sourcetype=zeek_json
| stats count by id.resp_h
| sort -count
| head 10

-- 4. Beaconing / average duration check by host pair
index=zeek sourcetype=zeek_json
| stats count avg(duration) by id.orig_h,id.resp_h
| where count>5
| sort -count

-- 5. DNS query volume by domain
index=zeek sourcetype=zeek_json query=*
| stats count by query
| sort count
| head 20
```

### C. References

- Zeek Documentation - https://docs.zeek.org/
- Splunk Add-on for Zeek/Bro - Splunkbase
- VirusTotal - https://www.virustotal.com/
- AbuseIPDB - https://www.abuseipdb.com/

---

[<- Back to Portfolio README](README.md)

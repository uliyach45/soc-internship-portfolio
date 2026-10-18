# Detection Engineering: OpenIOC for Air-Gapped / Removable-Media Malware

> Authoring cross-platform OpenIOC indicator documents for malware patterns that abuse removable media against air-gapped systems, with paired Windows OpenIOC and Linux-native equivalents.

---

## Objective

Produce reusable detection artifacts for malware that targets air-gapped systems via removable media. Air-gapped environments cannot rely on cloud-hosted IOC lookups or real-time threat-intel feeds, so detections must be authored as local artifacts that can be validated offline. The deliverable is a pair of indicator documents - one Windows OpenIOC and one Linux-native equivalent - covering the same behavioural patterns in each operating system's telemetry model.

---

## Background - Why Air-Gapped Detection Is Different

Air-gapped environments (industrial control systems, regulatory networks, classified infrastructure) face a unique threat category: malware designed to bridge the air gap via removable media. Stuxnet is the canonical example, but the pattern is general - any attacker who can deliver a USB-loaded payload into an environment with no outbound network path must rely on:

1. **Staging** - copying payload files to removable media on an internet-connected host.
2. **Persistence** - establishing a foothold on the air-gapped host when the media is inserted.
3. **Exfiltration preparation** - staging collected data back onto the removable media for later retrieval.

Detection in such environments must be local, deterministic, and observable from system logs that exist regardless of network connectivity. This exercise produces paired indicator documents that map the same behavioural pattern across Windows and Linux.

---

## Cross-Platform Indicator Mapping

The following table maps the Windows OpenIOC element to its Linux-native equivalent for each behaviour in the removable-media malware kill chain:

| Behaviour                          | Windows OpenIOC Element                  | Linux-Native Equivalent                                  |
| ---------------------------------- | ---------------------------------------- | -------------------------------------------------------- |
| Staging path on removable media    | `FileItem` (staging path)                 | Hidden staging directory on filesystem (e.g. `.staging/`) |
| File hash                          | `FileItem` (hash - MD5/SHA-1/SHA-256)    | `sha256sum` / `md5sum` of suspect file                   |
| Persistence via autorun            | `RegistryItem` (Run key)                  | `cron` job / `systemd` service unit                      |
| Device recognition events          | `EventLogItem` (device recognition)        | `syslog` / `journalctl` USB mount events (`/dev/sd*`, `/media/`) |
| Scheduled execution                | Scheduled Task (Task Scheduler)            | `cron` job / `systemd` timer                             |

---

## OpenIOC Document Structure (Windows)

A representative OpenIOC document for a Windows removable-media malware pattern contains the following indicator tree:

> **Illustrative example:** a representative OpenIOC structure written for this portfolio (placeholder values), not the original exercise file.

```xml
<ioc xmlns="http://schemas.mandiant.com/2010/ioc">
  <short_description>Removable-Media Malware - Windows</short_description>
  <authored_by>Uliya Fatima</authored_by>
  <authored_date>2026-08-06</authored_date>

  <definition>
    <Indicator operator="OR" id="staging-or-persistence">

      <!-- Staging path on removable media -->
      <Indicator operator="OR" id="staging-path">
        <IndicatorItem id="staging-file-path" condition="is">
          <Context document="FileItem" search="FileItem/FullPath" type="string" />
          <Content type="string">%SYSTEMDRIVE%\Users\*\AppData\Local\Temp\*.lnk</Content>
        </IndicatorItem>
        <IndicatorItem id="staging-file-path-usb" condition="is">
          <Context document="FileItem" search="FileItem/FullPath" type="string" />
          <Content type="string">D:\*.exe</Content>
        </IndicatorItem>
      </Indicator>

      <!-- File hash (known bad) -->
      <IndicatorItem id="suspicious-hash" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="md5" />
        <Content type="md5">[KNOWN_BAD_HASH]</Content>
      </IndicatorItem>

      <!-- Persistence via Run key -->
      <IndicatorItem id="run-key-persistence" condition="contains">
        <Context document="RegistryItem" search="RegistryItem/Key" type="string" />
        <Content type="string">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</Content>
      </IndicatorItem>

      <!-- Scheduled task persistence -->
      <IndicatorItem id="scheduled-task-persistence" condition="is">
        <Context document="TaskItem" search="TaskItem/Name" type="string" />
        <Content type="string">[SUSPICIOUS_TASK_NAME]</Content>
      </IndicatorItem>

      <!-- Device recognition / removable media mount -->
      <IndicatorItem id="removable-mount-event" condition="is">
        <Context document="EventLogItem" search="EventLogItem/Source" type="string" />
        <Content type="string">Microsoft-Windows-DriverFrameworks-UserMode</Content>
      </IndicatorItem>

    </Indicator>
  </definition>
</ioc>
```

---

## Linux-Native Equivalent

The Linux equivalent cannot use OpenIOC's Windows-specific document types (`RegistryItem`, `TaskItem`, `EventLogItem`). Instead, detection logic is implemented as a shell-based or `auditd`-rule-based hunt that observes the same behaviours in Linux-native telemetry:

> **Illustrative example:** a sample hunting script mirroring the Windows indicators; not the original deliverable.

```bash
#!/usr/bin/env bash
# Linux-native detection for removable-media malware patterns
# Mirrors the Windows OpenIOC: staging path, hash, persistence, mount events, scheduled execution

# 1. Staging path on mounted removable media
STAGING_DIRS=("/media/*/.staging" "/mnt/*/.staging" "/run/media/*/*/.[a-z]*")
for d in "${STAGING_DIRS[@]}"; do
  find $d -type f 2>/dev/null
done

# 2. Known-bad file hash
KNOWN_BAD_HASH="[KNOWN_BAD_SHA256]"
find /media /mnt /run/media -type f -exec sha256sum {} + 2>/dev/null \
  | grep -E "${KNOWN_BAD_HASH}"

# 3. Persistence via cron
grep -rE "(curl|wget|bash|python|nc )" \
  /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly} /var/spool/cron 2>/dev/null

# 4. Persistence via systemd service (network-touching services are suspicious)
systemctl list-unit-files --state=enabled \
  | grep -vE "(sshd|networking|systemd-|getty|cron|dbus|rsyslog|udev|polkit)"

# 5. Removable media mount events (auditd / journalctl)
journalctl -k -g "usb|usb-storage|sd[a-z]:|partition" --since "24 hours ago"
ausearch -k removable_mount 2>/dev/null

# 6. systemd timer persistence
systemctl list-timers --all --no-pager \
  | grep -vE "(apt-daily|systemd-tmpfiles|logrotate|fstrim|motd|man-db)"
```

---

## Verification Workflow (Air-Gapped / Offline)

Because the target environment is air-gapped, the verification workflow must avoid any cloud-based hash lookup:

| Step                                                | Mechanism                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------- |
| 1. Hash validation                                  | Maintain a local IOC repository (text file or SQLite DB) on a secured admin host. Update via signed, sneakernet-delivered feed bundles. |
| 2. Stage artifact to air-gapped host                 | Sign the IOC bundle, transport via write-once media (e.g. CD-R) or an authenticated read-only USB device. |
| 3. Validate signature on air-gapped host            | `gpg --verify ioc-bundle.sig` before ingestion.                      |
| 4. Run detection scan                                | Execute the OpenIOC scanner (Windows) or the shell script (Linux) against the local IOC repository. |
| 5. Manual triage of hits                            | Cross-check staging paths and persistence entries against the local IOC list; quarantine suspect files to a sandbox directory for analyst review. |

---

## Recommendations

1. **Maintain a local IOC repository.** Build a curated, signed IOC bundle updated on a fixed cadence (weekly) and delivered via authenticated sneakernet to air-gapped hosts.
2. **Pair OpenIOC with YARA.** For file-content matching, supplement OpenIOC's hash-based matching with YARA rules that target behavioural signatures (less brittle than hash rotation).
3. **Enable `auditd` rules for removable media.** A watch rule on `/dev/sd*` and `/media` ensures mount events are captured even before journald rotates them out.
4. **Cross-platform consistency review.** When a new IOC is added to the Windows OpenIOC document, immediately add its Linux equivalent to the shell-based hunter. Drift between the two documents is the most common source of detection gaps in mixed-OS air-gapped estates.
5. **Test detections quarterly.** Use a benign signature-bearing test file (e.g. EICAR variant) to verify each detection rule still fires in production.

---

## References

- OpenIOC schema documentation - https://www.fireeye.com/services/freeware/openioc.html
- Mandiant OpenIOC 1.1 specification
- Linux `auditd` documentation - https://man7.org/linux/man-pages/man8/auditd.8.html
- MITRE ATT&CK T1091 (Replication Through Removable Media), T1052 (Exfiltration Over Physical Medium)

---

[<- Back to Portfolio README](README.md)

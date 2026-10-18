# Isolated Dual-VM Network Topology (Single Physical NIC)

> Designing, deploying, and validating rigid Layer-3 micro-segmentation between two Ubuntu Linux guests on a single physical host using VMware virtual switches and Netplan.

---

## Problem Statement

Organisations that run multiple virtual machines on a single physical host but only have one physical Network Interface Card (NIC) face a security challenge: if both VMs share the same network path without proper segmentation, a compromise of one VM (malware, unauthorised access, misconfigured service) can move laterally to the other, exposing sensitive data or expanding the attack surface. This is a common real-world constraint in labs, testing environments, and resource-limited enterprise setups where cost or hardware availability prevents dedicating a separate NIC to each isolated environment.

**The cybersecurity problem this project addresses:** how to enforce strict network-layer isolation between two virtual machines sharing a single physical NIC, so that one VM cannot reach, scan, or communicate with the other, while still allowing one VM controlled outbound access to the internet.

---

## Objective

Design, deploy, and validate a secure networking topology featuring two isolated Ubuntu Linux virtual machines (VMs) running on a single physical host infrastructure. The architecture leverages hypervisor virtualisation-layer options combined with Linux Netplan configurations to force rigid Layer-3 network isolation, ensuring zero cross-communication between the target VMs while preserving individual deterministic operational states.

---

## Environment & Tools

| Component                  | Detail                                                       |
| -------------------------- | ------------------------------------------------------------ |
| Host OS                    | Ubuntu 24.04.4 LTS (Noble Numbat)                            |
| Hypervisor                 | VMware Workstation Pro 17.6.4                                |
| Guest OS                   | Ubuntu 24.04.4 LTS (Server/Desktop)                          |
| Network configuration tool | Netplan 1.1.2-8ubuntu1~24.04.2 (systemd-networkd backend)    |
| Physical NIC               | 1 x shared across the virtualisation platform               |

### Virtual Device Resource Allocations

Both VMs were built uniformly inside VMware Workstation using the following resource template:

| Resource          | Allocation                             |
| ----------------- | -------------------------------------- |
| Memory (RAM)      | 4 GB per instance                      |
| Processors        | 2 CPU cores per instance               |
| Virtual storage   | 20 GB SCSI virtual disk                |
| Virtual media     | Auto-installation ISO + virtual floppy |

---

## Network Topology

To satisfy the isolation criteria using a single physical interface, distinct network connection types were mapped inside the VMware Workstation virtual hardware abstraction layer. This split setup restricts the machines to independent collision domains at the hypervisor level.

```
                     +-------------------------------------------+
                     |       Physical Host (1 NIC, Ubuntu)       |
                     |                                           |
                     |   +-----------------------------------+   |
                     |   |     VMware Workstation Pro 17.6.4  |   |
                     |   |                                   |   |
                     |   |  VMnet8 (NAT)      VMnet2 (Host)  |   |
                     |   |   192.168.30.0/24   192.168.17.0/24|   |
                     |   |        |                 |         |   |
                     |   |   +-------+         +-------+     |   |
                     |   |   |  VM1  |         |  VM2  |     |   |
                     |   |   |ens33  |         |ens33  |     |   |
                     |   |   |.30.128|         |.17.128|     |   |
                     |   |   +-------+         +-------+     |   |
                     |   |       |                 |         |   |
                     |   |  NAT out          Host-only (no   |   |
                     |   |  to WAN           external route)  |   |
                     |   +-----------------------------------+   |
                     +-------------------|-----------------------+
                                         |
                                       WAN
```

| VM Identifier              | Hypervisor Network Setting                  | Target Subnet      | Intended Behaviour                                                                 |
| -------------------------- | ------------------------------------------- | ------------------- | --------------------------------------------------------------------------------- |
| Virtual Machine 1 (vm 1)   | NAT (Network Address Translation)           | 192.168.30.0/24     | Shares host IP for outbound external propagation; masks internal guest presence.   |
| Virtual Machine 2 (vm 2)   | Custom (Specific Virtual Network: VMnet2)    | 192.168.17.0/24     | Strictly mapped to a custom Host-only logical segment; traffic fully decoupled from VMnet8/NAT domains. |

---

## Netplan Configuration

### VM1 - Static configuration (NAT segment)

The network stack on VM1 was statically hardcoded to communicate over interface `ens33` through the `50-cloud-init.yaml` file in `/etc/netplan/`. DHCP was explicitly disabled to establish absolute layout predictability.

```yaml
network:
  version: 2
  ethernets:
    ens33:
      addresses:
        - 192.168.30.128/24
      routes:
        - to: default
          via: 192.168.30.2
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
      dhcp4: false
      dhcp6: false
```

### VM2 - NetworkManager-managed (Host-Only segment)

On VM2, network interface management was designated to standard Ubuntu network handling utilities via `/etc/netplan/01-network-manager-all.yaml`. This configures the instance to allow the NetworkManager backend daemon to dynamically govern device discovery states within the constrained Host-Only segment.

```yaml
# Let NetworkManager manage all devices on this system
network:
  version: 2
  renderer: NetworkManager
```

---

## Deployment & State Verification

After editing the configurations, updates were compiled into the runtime state of the kernel engine by executing the standard `netplan apply` inside administrative bash shells:

```bash
sudo netplan apply
```

### IP Address State Table

Execution of the `ip addr` utility confirmed precise Layer-3 interface states matching the architectural specifications:

| VM    | Interface | IPv4 Address         | MAC Address          | Link Status    |
| ----- | --------- | -------------------- | -------------------- | -------------- |
| VM 1  | ens33     | 192.168.30.128/24    | 00:0c:29:c1:a4:aa   | UP, LOWER_UP   |
| VM 2  | ens33     | 192.168.17.128/24    | 00:0c:29:66:c5:23   | UP, LOWER_UP   |

---

## Functional Testing & Isolation Matrix

Cross-domain connection checks were completed using ICMP echo requests via the `ping` utility to verify that isolation boundaries were strictly maintained at the hypervisor layer.

### VM1 -> VM2

```
ubuntu@ubuntu:~$ ping -c 4 192.168.17.128
ping: connect: Network is unreachable
```

Packet transmission was dropped instantly by the network subsystem stack; route generation across the logical boundaries failed as intended.

### VM2 -> VM1

```
ubuntu@ubuntu:~$ ping -c 4 192.168.30.128
ping: connect: Network is unreachable
```

Zero penetration achieved from the custom VMnet2 environment back to the primary NAT workstation segment.

### Final Verification Matrix

| Verification Metric         | Target Entity | Endpoint Tested     | Expected Result             | Actual Result                | Status |
| --------------------------- | ------------- | ------------------- | --------------------------- | ---------------------------- | ------ |
| Outbound WAN propagation    | VM 1          | google.com          | ICMP echo success           | Normal WAN packets transmitted | PASS   |
| Interface binding accuracy  | VM 1          | 192.168.30.128      | Local network context       | Static routing bound         | PASS   |
| Interface binding accuracy  | VM 2          | 192.168.17.128      | Host-only logical context  | Segment dynamic routing bound | PASS   |
| Cross-zone partition test   | VM 1 -> VM 2  | 192.168.17.128      | Transmission denied         | Blocked at subnet frontier   | PASS   |
| Cross-zone partition test   | VM 2 -> VM 1  | 192.168.30.128      | Transmission denied         | Blocked at subnet frontier   | PASS   |

> **Note on testing depth:** ICMP-based ping verification establishes Layer-3 reachability boundaries. For a production-grade isolation audit, additional verification via Nmap subnet scans and explicit TCP/UDP port probes is recommended to fully rule out alternate transport-layer paths (see Recommendations).

---

## Conclusion

This implementation validates that complete sandbox isolation of virtual machines can be successfully accomplished while utilising a single shared physical host adapter interface. By separating hypervisor-level virtual switches (NAT/VMnet8 vs. Custom Host-Only/VMnet2) and explicitly governing network routing using strict local Linux Netplan declarations, cross-communication between the virtual endpoints was entirely mitigated. Both servers function smoothly inside separate, secure collision environments, successfully achieving all specified security requirements.

---

## Recommendations

1. **Augment ICMP tests with Nmap scans.** Run `nmap -sn 192.168.17.0/24` from VM1 and `nmap -sn 192.168.30.0/24` from VM2 to confirm no host discovery is possible across segments.
2. **Add explicit TCP/UDP port probes.** Attempt connections on common ports (22, 80, 443, 445) across the boundary to verify transport-layer blocking.
3. **Enable firewall rules.** Even with hypervisor segmentation, add explicit `ufw`/`iptables` deny rules on each VM as defense-in-depth.
4. **Document MAC-to-IP bindings.** Static ARP entries prevent spoofing attempts within each segment.
5. **Capture a baseline `tcpdump`.** For future audit, retain a packet capture confirming no cross-segment frames are observed on either `ens33` interface.

---

[<- Back to Portfolio README](README.md)

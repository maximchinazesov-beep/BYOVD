# GoFly64.sys — Microsoft WHQL-Signed BYOVD Vulnerability Analysis [not ended]

A deep-dive technical analysis of the `GoFly64.sys` kernel-mode network filter driver. This driver was developed by a Chinese software company (Nanjing Siyanrui Network Technology) and exhibits highly dangerous, **Insecure by Design** primitives that enable Local Privilege Escalation (LPE) and arbitrary process termination.

## 🔴 The Security Paradox: Microsoft WHQL Signed
Unlike typical third-party drivers signed with standard commercial certificates, `GoFly64.sys` carries an official **Microsoft Windows Hardware Compatibility Publisher** (sha256) digital signature. 

![Microsoft WHQL Signature](./assets/whql_signature.png)

### Structural Validation Failure:
* **Absolute Trust:** Because it is verified by Microsoft, this binary completely bypasses **Driver Signature Enforcement (DSE)** out-of-the-box on any standard Windows 10/11 deployment.
* **AV Blindness:** Traditional Endpoint Detection and Response (EDR) and Anti-Virus (AV) solutions treat this file as a trusted operating system component, resulting in an extremely low static detection rate (**~9/71 on VirusTotal**).

---

## 🛠️ Reversed IOCTL Map & Exploitation Primitives

During our static analysis using IDA Pro, we mapped the core dispatch routine (`IRP_MJ_DEVICE_CONTROL`) and uncovered multiple unauthenticated control channels exposed directly to User-Mode applications.

### 1. Process Termination Primitive (`IOCTL 0x12227A`)
This routine accepts a target Process ID (PID) from the user-mode buffer without any privilege validation.
* **Internal Logic:** The driver explicitly uses **`ZwOpenProcess`** requesting `PROCESS_TERMINATE` access rights (`1u`), followed by an immediate execution of **`ZwTerminateProcess`**.
* **Impact:** Since `Zw`-prefixed system calls originate from Kernel-Mode, the operating system bypasses standard security descriptors (ACLs/DACLs). Non-privileged users can weaponize this IOCTL to instantly terminate protected security solutions (Windows Defender, Kaspersky, EDR agents), blinding the OS.

### 2. Arbitrary Kernel Write / LPE Primitive (`IOCTL 0x122282`)
A critical Write-What-Where flaw hidden deep within the custom command handlers.
* **Internal Logic:** The subroutine `sub_14000BC40` extracts a memory offset/size directly from the user-mode input buffer. It fetches a kernel destination address via an internal helper and executes a blind **`qmemcpy`** up to `0x104` bytes.
* **Impact:** Direct arbitrary kernel memory overwrite without bounds validation. This primitive provides a reliable vector for **Token Stealing** attacks (overwriting the target process access token with the `System` PID 4 token) to achieve an instant Local Privilege Escalation (LPE) to `NT AUTHORITY\SYSTEM`.

---

## 🚧 Current Status & Future Roadmap

* [x] Reverse-engineer `DriverEntry` and basic IRP major dispatch mapping.
* [x] Document Kernel-level process termination mechanism (`0x12227A`).
* [x] Document Arbitrary Kernel-Write vulnerability (`0x122282`).
* [ ] **[WIP]** Reverse-engineer the Windows Filtering Platform (WFP) network subroutines.
* [ ] Analyze IOCTLs `0x122262` / `0x12226A` / `0x12226E` (Traffic interception and asynchronous packet injection).
* [ ] Perform dynamic verification and capture execution artifacts on an isolated virtual environment.

***
*Disclaimer: This repository is maintained strictly for educational purposes, OS security research, and defensive auditing documentation.*

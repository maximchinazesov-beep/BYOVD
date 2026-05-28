# Latest analysis of the BYOVD vulnerability in the Lenovo bootrepair.sys driver

This repository contains a detailed analysis and Proof of Concept (PoC) for a vulnerability in the legitimate kernel driver **`bootrepair.sys`**, which is part of the Lenovo PC Manager utility. This driver was added to the public LOLDrivers database in May 2026.

## 📌 Information about the file being analyzed
* **File name:** `bootrepair.sys`
* **Vendor:** Lenovo
* **Digital signature:** Microsoft Windows Hardware Compatibility Publisher (Lenovo)
* **Threat class:** Bring Your Own Vulnerable Driver (BYOVD)
* **SHA-256:** `5ab36c116767eaae53a466fbc2dae7cfd608ed77721f65e83312037fbd57c946`

---

## 🔍 Technical analysis

Static analysis in IDA Pro restored the original logic and structure of the vulnerable section of the driver code.

### 1. Device Creation (DriverEntry)
The driver registers the symbolic link `\DosDevices\BootRepair` and creates a device object using the `IoCreateDevice` function. The vulnerability lies in the fact that when creating the device object, **no discretionary access control lists (DACLs)** were set.

This allows absolutely any local user (even Guest / Low Integrity) to open a device handle using the standard call:
```cpp
CreateFileA("\\\\.\\BootRepair", GENERIC_READ | GENERIC_WRITE, ...);
```

### 2. IOCTL Handler (MajorFunction)
The driver receives the control code (IOCTL) `0x222014` (displayed in the code as the decimal number `2236436`). The driver expects to receive an input buffer of exactly 4 bytes (type DWORD) from user mode, which is interpreted as a process identifier (PID).

### 3. Arbitrary process termination
The IOCTL handling function (`sub_14000198C`) completely lacks any privilege checks (Token / Access Check) for the calling user. The driver blindly trusts the incoming PID and executes the following sequence of actions in kernel space:

1. **`PsLookupProcessByProcessId`** — accepts the PID from user mode and finds the `PEPROCESS` structure.
2. **`ObOpenObjectByPointer`** — opens the process handle with the maximum `PROCESS_ALL_ACCESS` (`0x1FFFFF`) privileges.
3. **`ZwTerminateProcess`** — forcibly terminates the target process on behalf of the system (`NT AUTHORITY\SYSTEM`).

---

## 💥 Actual Damage and Attack Potential

Since the code executes at Ring 0, it completely bypasses the self-defense mechanisms of the operating system and third-party software:
* **AV/EDR Kill:** An attacker can instantly terminate security software processes (Windows Defender, CrowdStrike, Kaspersky), ignoring PPL (Protected Process Light) protection.
* **Blue Screen of Death (BSOD):** By passing the PIDs of critical system processes (`csrss.exe`, `lsass.exe`) to the driver, an immediate operating system crash can be caused.

---

## 📁 Project Structure
* `/reverse` — IDA Pro database (`.i64`) with reconstructed variable names (`status`, `ProcessHandle`) and comments.
* `/src` — C++ exploit source code (PoC) for demonstrating the vulnerability.

  <img width="800" height="450" alt="showcase_bootrepair" src="https://github.com/user-attachments/assets/360712b0-5dfe-43f5-9d66-eb990653f9f1" />


## ⚠️ Disclaimer
This research is published for educational purposes only, to demonstrate the operation of BYOVD mechanisms and improve reverse engineering skills. The author is not responsible for any damages caused by using these materials.

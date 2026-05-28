# Latest analysis of the BYOVD vulnerability in the WinRing0x64.sys driver

This repository contains a detailed analysis and technical breakdown of a vulnerability in the legitimate kernel driver **`WinRing0x64.sys`** (also distributed as `WinRing0.sys`), which is widely used in hardware monitoring and RGB control utilities (e.g., OpenRGB). This driver is actively blacklisted in public LOLDrivers and Microsoft databases.

## 📌 Information about the file being analyzed
* **File name:** `WinRing0x64.sys`
* **Vendor:** Noriyuki MIYAMURA (OpenLibSys)
* **Digital signature:** Microsoft Windows Hardware Compatibility Publisher
* **Threat class:** Bring Your Own Vulnerable Driver (BYOVD)
* **SHA-256:** `3ec5ad51e6879464dfbccb9f4ed76c6325056a42548d5994ba869da9c4c039a8`

---

## 🔍 Technical analysis

Static analysis in IDA Pro restored the original logic and structure of the vulnerable section of the driver code.

### 1. Device Creation (RealDriverEntry)
The driver registers the symbolic link `\DosDevices\WinRing0_1_0_1` and creates a device object using the `IoCreateDevice` function. The vulnerability lies in the fact that when creating the device object, **no discretionary access control lists (DACLs)** were set.

This allows absolutely any local user (even Guest / Low Integrity) to open a device handle using the standard call:
```cpp
CreateFileA("\\\\.\\WinRing0_1_0_1", GENERIC_READ | GENERIC_WRITE, ...);
```

### 2. IOCTL Handler (MajorFunction)
The main dispatcher function (`sub_110D8`) handles hardware communication control codes. It accepts multiple low-level control IOCTLs without any token validation or privilege verification. The internal functions read the input buffer directly from the I/O Request Packet (IRP).

### 3. Arbitrary MSR Read/Write and Direct I/O Access
The internal routines completely lack any privilege checks for the calling user. The driver blindly trusts the user-supplied buffers and executes the following privileged sequences in kernel space:

1. **`VulnerableReadMSR` (`sub_11494`) [IOCTL 0x9C402084]** — accepts a target DWORD index from user mode and passes it directly to the **`__readmsr`** intrinsic, returning the 64-bit hardware register value back to user-mode.
2. **`VulnerableWriteMSR` (`sub_114C8`) [IOCTL 0x9C402088]** — takes a target MSR register index and a 64-bit value from the input buffer, executing the privileged **`__writemsr`** instruction unconditionally.
3. **Raw I/O Port Access [IOCTL 0x9C4060CC - 0x9C40A0E0]** — routes user-mode inputs directly into direct hardware assembly instructions (**`__inbyte`** / **`__outbyte`** family), bypassing OS access restrictions.

---

## 💥 Actual Damage and Attack Potential

Since the code executes at Ring 0, it completely bypasses the self-defense mechanisms of the operating system and third-party software:
* **KASLR Bypass:** An attacker can trigger an arbitrary MSR read on the `IA32_LSTAR` register (`0xC0000082`) to leak the exact kernel pointer for `KiSystemCall64`, completely neutralizing **KASLR** protection.
* **Local Privilege Escalation (LPE):** By utilizing the arbitrary MSR write vulnerability, an attacker can overwrite `IA32_LSTAR` to hijack the OS system call handler, redirecting kernel execution flow into a user-controlled payload to gain full **`NT AUTHORITY\SYSTEM`** privileges.
* **Hardware Manipulation:** Raw I/O port access allows untrusted local applications to interact directly with motherboard controllers, potentially causing physical hardware instability or immediate system lockups.

---

## 📁 Project Structure
* `/reverse` — IDA Pro database (`.i64`) with reconstructed variable names (`VulnerableReadMSR`, `VulnerableWriteMSR`) and comments.

## ⚠️ Disclaimer
This research is published for educational purposes only, to demonstrate the operation of BYOVD mechanisms and improve reverse engineering skills. The author is not responsible for any damages caused by using these materials.

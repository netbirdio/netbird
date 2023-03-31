#!/bin/sh
# This code is based on the netbird-installer contribution by physk on GitHub.
# Source: https://github.com/physk/netbird-installer
set -e

OWNER="netbirdio"
REPO="netbird"
CLI_APP="netbird"
UI_APP="netbird-ui"

# Set default variable
OS_NAME=""
OS_TYPE=""
ARCH="$(uname -m)"
PACKAGE_MANAGER=""
INSTALL_DIR=""

get_latest_release() {
    curl -s "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" \
    | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

download_release_binary() {
    VERSION=$(get_latest_release)
    BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download"
    BINARY_BASE_NAME="${VERSION#v}_${OS_TYPE}_${ARCH}.tar.gz"
    
    # for Darwin, download the signed Netbird-UI
    if [ "$OS_TYPE" = "darwin" ] && [ "$1" = "$UI_APP" ]; then
        BINARY_BASE_NAME="${VERSION#v}_${OS_TYPE}_${ARCH}_signed.zip"
    fi

    BINARY_NAME="$1_${BINARY_BASE_NAME}"
    DOWNLOAD_URL="${BASE_URL}/${VERSION}/${BINARY_NAME}"

    echo "Installing $1 from $DOWNLOAD_URL"
    cd /tmp && curl -LO "$DOWNLOAD_URL" 
    
    if [ "$OS_TYPE" = "darwin" ] && [ "$1" = "$UI_APP" ]; then
        # Unzip the app
        unzip -q -o "$BINARY_NAME"

        INSTALL_DIR="/Applications/NetBird UI.app/Contents"
        UNZIPPED_FOLDER="netbird_ui_${OS_TYPE}_${ARCH}"
    
        if mkdir -p "${INSTALL_DIR}/MacOS/"; then
            mv "$UNZIPPED_FOLDER"/netbird-ui "${INSTALL_DIR}/MacOS/"
        fi

        if mkdir -p "${INSTALL_DIR}/Resources/"; then
            mv "$UNZIPPED_FOLDER"/Netbird.icns "${INSTALL_DIR}/Resources/"
        fi

        mv "$UNZIPPED_FOLDER"/Info.plist "${INSTALL_DIR}/"
        mv "$UNZIPPED_FOLDER"/_CodeSignature/ "${INSTALL_DIR}/"
    else
        tar -xzvf "$BINARY_NAME"
        sudo mv "${1%_"${BINARY_BASE_NAME}"}" "$INSTALL_DIR"
    fi
}

add_rpm_repo() {
cat <<-EOF |  tee /etc/yum.repos.d/wiretrustee.repo
[Wiretrustee]
name=Wiretrustee
baseurl=https://pkgs.wiretrustee.com/yum/
enabled=1
gpgcheck=0
gpgkey=https://pkgs.wiretrustee.com/yum/repodata/repomd.xml.key
repo_gpgcheck=1
EOF
} 

install_native_binaries() {
    # Checks  for supported architecture
    case "$ARCH" in
        x86_64|amd64)
            ARCH='amd64'
        ;;
        i?86|x86)
            ARCH='386'
        ;;
        aarch64|arm64)
            ARCH='arm64'
        ;;
        *)
            echo "Architecture ${ARCH} not supported"
            exit 2
        ;;
    esac

    # download and copy binaries to INSTALL_DIR
    download_release_binary "$CLI_APP"
    if ! $SKIP_UI_APP; then 
        download_release_binary "$UI_APP"
    fi  
}

install_netbird() {
    # Checks if SKIP_UI_APP env is set
    if [ -z "$SKIP_UI_APP" ]; then
        SKIP_UI_APP=false
    fi

    # Identify OS name and default package manager
    if type uname >/dev/null 2>&1; then
	case "$(uname)" in
        Linux)
            OS_NAME="$(. /etc/os-release && echo "$ID")" 
            OS_TYPE="linux"
            INSTALL_DIR="/usr/bin"
            
            # Allow netbird UI installation for x64 arch only
            if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ] \
                && [ "$ARCH" != "x86_64" ];then
                echo "$ARCH is not a compatible architecture for Netbird UI"
                SKIP_UI_APP=true
            fi

            # Allow netbird UI installation for linux running desktop enviroment
            if [ -z "$XDG_CURRENT_DESKTOP" ];then
                    SKIP_UI_APP=true
            fi

            # Check the availability of a compatible package manager
            if [ -x "$(command -v apt)" ]; then
                PACKAGE_MANAGER="apt"
            fi
            if [ -x "$(command -v yum)" ]; then
                PACKAGE_MANAGER="yum"
            fi
            if [ -x "$(command -v dnf)" ]; then
                PACKAGE_MANAGER="dnf"
            fi
            if [ -x "$(command -v pacman)" ]; then
                PACKAGE_MANAGER="pacman"
            fi
		;;
		Darwin)
            OS_NAME="macos"
			OS_TYPE="darwin"
            INSTALL_DIR="/usr/local/bin"
            
            # Check the availability of a compatible package manager
            if [ -x "$(command -v brew)" ]; then 
                PACKAGE_MANAGER="brew"
            fi
		;;
	esac
    fi

    # Run the installation, if a desktop environment is not detected
    # only the CLI will be installed
    case "$PACKAGE_MANAGER" in
    apt)
        apt-get update
        apt-get install ca-certificates gnupg -y
        
        curl -sSL https://pkgs.wiretrustee.com/debian/public.key \
        |  gpg --dearmor --output /usr/share/keyrings/wiretrustee-archive-keyring.gpg

        APT_REPO="deb [signed-by=/usr/share/keyrings/wiretrustee-archive-keyring.gpg] https://pkgs.wiretrustee.com/debian stable main"
        echo "$APT_REPO" |  tee /etc/apt/sources.list.d/wiretrustee.list

        apt-get update
        apt-get install netbird -y
        
        if ! $SKIP_UI_APP; then 
            apt-get install netbird-ui -y
        fi
    ;;
    yum)
        add_rpm_repo
        yum -y install netbird
        if ! $SKIP_UI_APP; then 
            yum -y install netbird-ui
        fi
    ;;
    dnf)
        add_rpm_repo
        dnf -y install dnf-plugin-config-manager
        dnf config-manager --add-repo /etc/yum.repos.d/wiretrustee.repo
        dnf -y install netbird

        if ! $SKIP_UI_APP; then 
            dnf -y install netbird-ui
        fi
    ;;
    pacman)
        sudo pacman -Syy
        sudo pacman -Sy --needed --noconfirm git base-devel go

        # Build package from AUR
        cd /tmp && git clone https://aur.archlinux.org/netbird.git 
        cd netbird && makepkg -sri --noconfirm

        if ! $SKIP_UI_APP; then 
            cd /tmp && git clone https://aur.archlinux.org/netbird-ui.git
            cd netbird-ui && makepkg -sri --noconfirm
        fi
    ;;
    brew)
        # Remove Wiretrustee if it had been installed using Homebrew before
        if brew ls --versions wiretrustee >/dev/null 2>&1; then
            echo "Removing existing wiretrustee client"
            
            # Stop and uninstall daemon service:
            wiretrustee service stop
            wiretrustee service uninstall 

            # Unlik the app
            brew unlink wiretrustee
        fi

        brew install netbirdio/tap/netbird
        if ! $SKIP_UI_APP; then 
            brew install --cask netbirdio/tap/netbird-ui
        fi
    ;;
    *)
        if [ "$OS_NAME" = "nixos" ];then
            echo "Please add Netbird to your NixOS configuration.nix directly:"
			echo
			echo "services.netbird.enable = true;"

            if ! $SKIP_UI_APP; then 
                 echo "environment.systemPackages = [ pkgs.netbird-ui ];"
            fi

            echo "Build and apply new configuration:"
            echo
            echo "sudo nixos-rebuild switch"
			exit 0
        fi   

        install_native_binaries
    ;;
    esac

    # Start client daemon service if only CLI is installed
    if ! $SKIP_UI_APP; then
        sudo netbird service install 2>/dev/null
        sudo netbird service start 2>/dev/null
    fi
}

install_netbird
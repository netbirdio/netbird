#!/bin/sh
# This code is based on the netbird-installer contribution by physk on GitHub.
# Source: https://github.com/physk/netbird-installer
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

OWNER="netbirdio"
REPO="netbird"
CLI_APP="netbird"
UI_APP="netbird-ui"

# Set default variable
OS_NAME=""
OS_TYPE=""
ARCH="$(uname -m)"
PACKAGE_MANAGER=""
INSTALL_DIR="/usr/bin/"

get_latest_release() {
    curl -s "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" \
    | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

download_and_extract_tar() {
    VERSION=$(get_latest_release)
    BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download"
    BINARY_BASE_NAME="${VERSION#v}_${OS_TYPE}_${ARCH}.tar.gz"
    
    BINARY_NAME="$1_${BINARY_BASE_NAME}"
    DOWNLOAD_URL="${BASE_URL}/${VERSION}/${BINARY_NAME}"

    echo "Downloading $1 from $DOWNLOAD_URL"
    curl -LO "$DOWNLOAD_URL" 
  
    if tar -xzvf "$BINARY_NAME"; then
        echo "Extraction $1 completed"
        mv "${1%_"${BINARY_BASE_NAME}"}" "$INSTALL_DIR"
    else
      echo "Failed to extract $1"
      exit 2
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

    # download and extract netbird binaries to INSTAD_DIR
    download_and_extract_tar "$CLI_APP"
    if ! $SKIP_UI_APP; then 
        download_and_extract_tar "$UI_APP"
    fi

    # Start client daemon service if only CLI is installed
    if SKIP_UI_APP; then 
        netbird service install
        netbird service start
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
		;;
		Darwin)
            OS_NAME="macos"
			OS_TYPE="darwin"
            PACKAGE_MANAGER="brew"

            # If Homebrew is not installed, install it
            if [ -z "$(command -v $PACKAGE_MANAGER)" ]; then 
                echo "Homebrew is not installed. Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                echo "Homebrew has been installed."
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
}

install_netbird
# This code is based on the netbird-installer contribution by physk on GitHub.
# Source: https://github.com/physk/netbird-installer
set -e

CONFIG_FOLDER="/etc/netbird"
CONFIG_FILE="$CONFIG_FOLDER/install.conf"

OWNER="netbirdio"
REPO="netbird"
CLI_APP="netbird"
UI_APP="netbird-ui"

# Set default variable
OS_NAME=""
OS_TYPE=""
ARCH="$(uname -m)"
PACKAGE_MANAGER="bin"
INSTALL_DIR=""
SUDO=""


if command -v sudo > /dev/null && [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

if [ -z ${NETBIRD_RELEASE+x} ]; then
    NETBIRD_RELEASE=latest
fi

get_release() {
    local RELEASE=$1
    if [ "$RELEASE" = "latest" ]; then
        local TAG="latest"
    else
        local TAG="tags/${RELEASE}"
    fi
    if [ -n "$GITHUB_TOKEN" ]; then
          curl -H  "Authorization: token ${GITHUB_TOKEN}" -s "https://api.github.com/repos/${OWNER}/${REPO}/releases/${TAG}" \
              | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
    else
          curl -s "https://api.github.com/repos/${OWNER}/${REPO}/releases/${TAG}" \
              | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
    fi
}

download_release_binary() {
    VERSION=$(get_release "$NETBIRD_RELEASE")
    BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download"
    BINARY_BASE_NAME="${VERSION#v}_${OS_TYPE}_${ARCH}.tar.gz"

    # for Darwin, download the signed NetBird-UI
    if [ "$OS_TYPE" = "darwin" ] && [ "$1" = "$UI_APP" ]; then
        BINARY_BASE_NAME="${VERSION#v}_${OS_TYPE}_${ARCH}_signed.zip"
    fi

    if [ "$1" = "$UI_APP" ]; then
       BINARY_NAME="$1-${OS_TYPE}_${BINARY_BASE_NAME}"
       if [ "$OS_TYPE" = "darwin" ]; then
         BINARY_NAME="$1_${BINARY_BASE_NAME}"
       fi
    else
       BINARY_NAME="$1_${BINARY_BASE_NAME}"
    fi

    DOWNLOAD_URL="${BASE_URL}/${VERSION}/${BINARY_NAME}"

    echo "Installing $1 from $DOWNLOAD_URL"
    if [ -n "$GITHUB_TOKEN" ]; then
      cd /tmp && curl -H  "Authorization: token ${GITHUB_TOKEN}" -LO "$DOWNLOAD_URL"
    else
      cd /tmp && curl -LO "$DOWNLOAD_URL"
    fi


    if [ "$OS_TYPE" = "darwin" ] && [ "$1" = "$UI_APP" ]; then
        INSTALL_DIR="/Applications/NetBird UI.app"

        if test -d "$INSTALL_DIR" ; then
          echo "removing $INSTALL_DIR"
          rm -rfv "$INSTALL_DIR"
        fi

        # Unzip the app and move to INSTALL_DIR
        unzip -q -o "$BINARY_NAME"
        mv "netbird_ui_${OS_TYPE}_${ARCH}/" "$INSTALL_DIR/"
    else
        ${SUDO} mkdir -p "$INSTALL_DIR"
        tar -xzvf "$BINARY_NAME"
        ${SUDO} mv "${1%_"${BINARY_BASE_NAME}"}" "$INSTALL_DIR/"
    fi
}

add_apt_repo() {
    ${SUDO} apt-get update
    ${SUDO} apt-get install ca-certificates curl gnupg -y

    # Remove old keys and repo source files
    ${SUDO} rm -f \
        /etc/apt/sources.list.d/netbird.list \
        /etc/apt/sources.list.d/wiretrustee.list \
        /etc/apt/trusted.gpg.d/wiretrustee.gpg \
        /usr/share/keyrings/netbird-archive-keyring.gpg \
        /usr/share/keyrings/wiretrustee-archive-keyring.gpg

    curl -sSL https://pkgs.netbird.io/debian/public.key \
    | ${SUDO} gpg --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg

    echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' \
    | ${SUDO} tee /etc/apt/sources.list.d/netbird.list

    ${SUDO} apt-get update
}

add_rpm_repo() {
cat <<-EOF | ${SUDO} tee /etc/yum.repos.d/netbird.repo
[NetBird]
name=NetBird
baseurl=https://pkgs.netbird.io/yum/
enabled=1
gpgcheck=0
gpgkey=https://pkgs.netbird.io/yum/repodata/repomd.xml.key
repo_gpgcheck=1
EOF
}

add_aur_repo() {
    INSTALL_PKGS="git base-devel go"
    REMOVE_PKGS=""

    # Check if dependencies are installed
    for PKG in $INSTALL_PKGS; do
        if ! pacman -Q "$PKG" > /dev/null 2>&1; then
            # Install missing package(s)
            ${SUDO} pacman -S "$PKG" --noconfirm

            # Add installed package for clean up later
            REMOVE_PKGS="$REMOVE_PKGS $PKG"
        fi
    done

    # Build package from AUR
    cd /tmp && git clone https://aur.archlinux.org/netbird.git
    cd netbird && makepkg -sri --noconfirm

    if ! $SKIP_UI_APP; then
        cd /tmp && git clone https://aur.archlinux.org/netbird-ui.git
        cd netbird-ui && makepkg -sri --noconfirm
    fi

    # Clean up the installed packages
    ${SUDO} pacman -Rs "$REMOVE_PKGS" --noconfirm
}

install_native_binaries() {
    # Checks  for supported architecture
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
        ;;
        i?86|x86)
            ARCH="386"
        ;;
        aarch64|arm64)
            ARCH="arm64"
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

check_use_bin_variable() {
    if [ "${USE_BIN_INSTALL}-x" = "true-x" ]; then
      echo "The installation will be performed using binary files"
      return 0
    fi
    return 1
}

install_netbird() {
    if [ -x "$(command -v netbird)" ]; then
        status_output=$(netbird status)
        if echo "$status_output" | grep -q 'Management: Connected' && echo "$status_output" | grep -q 'Signal: Connected'; then
            echo "NetBird service is running, please stop it before proceeding"
            exit 1
        fi

        if [ -n "$status_output" ]; then
            echo "NetBird seems to be installed already, please remove it before proceeding"
            exit 1
        fi
    fi

    # Run the installation, if a desktop environment is not detected
    # only the CLI will be installed
    case "$PACKAGE_MANAGER" in
    apt)
        add_apt_repo
        ${SUDO} apt-get install netbird -y

        if ! $SKIP_UI_APP; then
            ${SUDO} apt-get install netbird-ui -y
        fi
    ;;
    yum)
        add_rpm_repo
        ${SUDO} yum -y install netbird
        if ! $SKIP_UI_APP; then
            ${SUDO} yum -y install netbird-ui
        fi
    ;;
    dnf)
        add_rpm_repo
        ${SUDO} dnf -y install dnf-plugin-config-manager
        ${SUDO} dnf config-manager --add-repo /etc/yum.repos.d/netbird.repo
        ${SUDO} dnf -y install netbird

        if ! $SKIP_UI_APP; then
            ${SUDO} dnf -y install netbird-ui
        fi
    ;;
    pacman)
        ${SUDO} pacman -Syy
        add_aur_repo
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
        echo "Please add NetBird to your NixOS configuration.nix directly:"
			  echo ""
			  echo "services.netbird.enable = true;"

        if ! $SKIP_UI_APP; then
          echo "environment.systemPackages = [ pkgs.netbird-ui ];"
        fi

        echo "Build and apply new configuration:"
        echo ""
        echo "${SUDO} nixos-rebuild switch"
			  exit 0
      fi

        install_native_binaries
    ;;
    esac

    # Add package manager to config
    ${SUDO} mkdir -p "$CONFIG_FOLDER"
    echo "package_manager=$PACKAGE_MANAGER" | ${SUDO} tee "$CONFIG_FILE" > /dev/null

    # Load and start netbird service
    if  ! ${SUDO} netbird service install 2>&1; then
        echo "NetBird service has already been loaded"
    fi
    if  ! ${SUDO} netbird service start 2>&1; then
        echo "NetBird service has already been started"
    fi


    echo "Installation has been finished. To connect, you need to run NetBird by executing the following command:"
    echo ""
    echo "netbird up"
}

version_greater_equal() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

is_bin_package_manager() {
  if ${SUDO} test -f "$1" && ${SUDO} grep -q "package_manager=bin" "$1" ; then
    return 0
  else
    return 1
  fi
}

stop_running_netbird_ui() {
  NB_UI_PROC=$(ps -ef | grep "[n]etbird-ui" | awk '{print $2}')
  if [ -n "$NB_UI_PROC" ]; then
    echo "NetBird UI is running with PID $NB_UI_PROC. Stopping it..."
    kill -9 "$NB_UI_PROC"
  fi
}

update_netbird() {
  if is_bin_package_manager "$CONFIG_FILE"; then
    latest_release=$(get_release "latest")
    latest_version=${latest_release#v}
    installed_version=$(netbird version)

    if [ "$latest_version" = "$installed_version" ]; then
      echo "Installed NetBird version ($installed_version) is up-to-date"
      exit 0
    fi

    if version_greater_equal "$latest_version" "$installed_version"; then
      echo "NetBird new version ($latest_version) available. Updating..."
      echo ""
      echo "Initiating NetBird update. This will stop the netbird service and restart it after the update"

      ${SUDO} netbird service stop || true
      ${SUDO} netbird service uninstall || true
      stop_running_netbird_ui
      install_native_binaries

      ${SUDO} netbird service install
      ${SUDO} netbird service start
    fi
  else
     echo "NetBird installation was done using a package manager. Please use your system's package manager to update"
  fi
}

# Checks if SKIP_UI_APP env is set
if [ -z "$SKIP_UI_APP" ]; then
    SKIP_UI_APP=false
else
    if $SKIP_UI_APP; then
      echo "SKIP_UI_APP has been set to true in the environment"
      echo "NetBird UI installation will be omitted based on your preference"
    fi
fi

# Identify OS name and default package manager
if type uname >/dev/null 2>&1; then
	case "$(uname)" in
        Linux)
          OS_TYPE="linux"
          UNAME_OUTPUT="$(uname -a)"
          if echo "$UNAME_OUTPUT" | grep -qi "synology"; then
            OS_NAME="synology"
            INSTALL_DIR="/usr/local/bin"
            PACKAGE_MANAGER="bin"
            SKIP_UI_APP=true
          else
            if [ -f /etc/os-release ]; then
              OS_NAME="$(. /etc/os-release && echo "$ID")"
              INSTALL_DIR="/usr/bin"

              # Allow netbird UI installation for x64 arch only
              if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ] \
                  && [ "$ARCH" != "x86_64" ];then
                  SKIP_UI_APP=true
                  echo "NetBird UI installation will be omitted as $ARCH is not a compatible architecture"
              fi

              # Allow netbird UI installation for linux running desktop environment
              if [ -z "$XDG_CURRENT_DESKTOP" ];then
                  SKIP_UI_APP=true
                  echo "NetBird UI installation will be omitted as Linux does not run desktop environment"
              fi

              # Check the availability of a compatible package manager
              if check_use_bin_variable; then
                  PACKAGE_MANAGER="bin"
              elif [ -x "$(command -v apt-get)" ]; then
                  PACKAGE_MANAGER="apt"
                  echo "The installation will be performed using apt package manager"
              elif [ -x "$(command -v dnf)" ]; then
                  PACKAGE_MANAGER="dnf"
                  echo "The installation will be performed using dnf package manager"
              elif [ -x "$(command -v yum)" ]; then
                  PACKAGE_MANAGER="yum"
                  echo "The installation will be performed using yum package manager"
              elif [ -x "$(command -v pacman)" ]; then
                  PACKAGE_MANAGER="pacman"
                  echo "The installation will be performed using pacman package manager"
              fi

            else
              echo "Unable to determine OS type from /etc/os-release"
              exit 1
            fi
          fi


		;;
		Darwin)
            OS_NAME="macos"
			OS_TYPE="darwin"
            INSTALL_DIR="/usr/local/bin"

            # Check the availability of a compatible package manager
            if check_use_bin_variable; then
                PACKAGE_MANAGER="bin"
            elif [ -x "$(command -v brew)" ]; then
                PACKAGE_MANAGER="brew"
                echo "The installation will be performed using brew package manager"
            fi
		;;
	esac
fi

UPDATE_FLAG=$1

if [ "${UPDATE_NETBIRD}-x" = "true-x" ]; then
  UPDATE_FLAG="--update"
fi

case "$UPDATE_FLAG" in
    --update)
      update_netbird
    ;;
    *)
      install_netbird
esac

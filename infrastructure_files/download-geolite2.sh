#!/bin/bash

# set $MM_ACCOUNT_ID and $MM_LICENSE_KEY when calling this script
# see https://dev.maxmind.com/geoip/updating-databases#directly-downloading-databases

# Check if MM_ACCOUNT_ID is set
if [ -z "$MM_ACCOUNT_ID" ]; then
    echo "MM_ACCOUNT_ID is not set. Please set the environment variable."
    exit 1
fi

# Check if MM_LICENSE_KEY is set
if [ -z "$MM_LICENSE_KEY" ]; then
    echo "MM_LICENSE_KEY is not set. Please set the environment variable."
    exit 1
fi

# to install sha256sum on mac: brew install coreutils
if ! command -v sha256sum &> /dev/null
then
    echo "sha256sum is not installed or not in PATH, please install with your package manager. e.g. sudo apt install sha256sum" > /dev/stderr
    exit 1
fi

DATABASE_URL="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
SIGNATURE_URL="https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz.sha256"

# Download the database and signature files
echo "Downloading database file..."
DATABASE_FILE=$(curl -s -u "$MM_ACCOUNT_ID":"$MM_LICENSE_KEY" -L -O -J "$DATABASE_URL" -w "%{filename_effective}")
echo "Downloading signature file..."
SIGNATURE_FILE=$(curl -s -u "$MM_ACCOUNT_ID":"$MM_LICENSE_KEY" -L -O -J "$SIGNATURE_URL" -w "%{filename_effective}")

# Verify the signature
echo "Verifying signature..."
if sha256sum -c --status "$SIGNATURE_FILE"; then
    echo "Signature is valid."
else
    echo "Signature is invalid. Aborting."
    exit 1
fi

# Unpack the database file
EXTRACTION_DIR=$(basename "$DATABASE_FILE" .tar.gz)
echo "Unpacking $DATABASE_FILE..."
mkdir -p "$EXTRACTION_DIR"
tar -xzvf "$DATABASE_FILE"

# Create a SHA256 signature file
MMDB_FILE="GeoLite2-City.mmdb"
cd "$EXTRACTION_DIR"
sha256sum "$MMDB_FILE" > "$MMDB_FILE.sha256"
echo "SHA256 signature created for $MMDB_FILE."
cd -

# Remove downloaded files
rm "$DATABASE_FILE" "$SIGNATURE_FILE"

# Done. Print next steps
echo "Process completed successfully."
echo "Now you can place $EXTRACTION_DIR/$MMDB_FILE to 'datadir' of management service."
echo -e "Example:\n\tdocker compose cp $EXTRACTION_DIR/$MMDB_FILE management:/var/lib/netbird/"

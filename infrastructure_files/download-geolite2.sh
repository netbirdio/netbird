#!/bin/bash

# to install sha256sum on mac: brew install coreutils
if ! command -v sha256sum &> /dev/null
then
    echo "sha256sum is not installed or not in PATH, please install with your package manager. e.g. sudo apt install sha256sum" > /dev/stderr
    exit 1
fi

if ! command -v sqlite3 &> /dev/null
then
    echo "sqlite3 is not installed or not in PATH, please install with your package manager. e.g. sudo apt install sqlite3" > /dev/stderr
    exit 1
fi

if ! command -v unzip &> /dev/null
then
    echo "unzip is not installed or not in PATH, please install with your package manager. e.g. sudo apt install unzip" > /dev/stderr
    exit 1
fi

download_geolite_mmdb() {
  DATABASE_URL="https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
  SIGNATURE_URL="https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
  # Download the database and signature files
  echo "Downloading mmdb signature file..."
  SIGNATURE_FILE=$(curl -s  -L -O -J "$SIGNATURE_URL" -w "%{filename_effective}")
  echo "Downloading mmdb database file..."
  DATABASE_FILE=$(curl -s  -L -O -J "$DATABASE_URL" -w "%{filename_effective}")

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
  tar -xzvf "$DATABASE_FILE" > /dev/null 2>&1

  MMDB_FILE="GeoLite2-City.mmdb"
  cp "$EXTRACTION_DIR"/"$MMDB_FILE" $MMDB_FILE

  # Remove downloaded files
  rm -r "$EXTRACTION_DIR"
  rm "$DATABASE_FILE" "$SIGNATURE_FILE"

  # Done. Print next steps
  echo ""
  echo "Process completed successfully."
  echo "Now you can place $MMDB_FILE to 'datadir' of management service."
  echo -e "Example:\n\tdocker compose cp $MMDB_FILE management:/var/lib/netbird/"
}


download_geolite_csv_and_create_sqlite_db() {
  DATABASE_URL="https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip"
  SIGNATURE_URL="https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip.sha256"


  # Download the database file
  echo "Downloading csv signature file..."
  SIGNATURE_FILE=$(curl -s  -L -O -J "$SIGNATURE_URL" -w "%{filename_effective}")
  echo "Downloading csv database file..."
  DATABASE_FILE=$(curl -s  -L -O -J "$DATABASE_URL" -w "%{filename_effective}")

  # Verify the signature
  echo "Verifying signature..."
  if sha256sum -c --status "$SIGNATURE_FILE"; then
      echo "Signature is valid."
  else
      echo "Signature is invalid. Aborting."
      exit 1
  fi

  # Unpack the database file
  EXTRACTION_DIR=$(basename "$DATABASE_FILE" .zip)
  DB_NAME="geonames.db"

  echo "Unpacking $DATABASE_FILE..."
  unzip "$DATABASE_FILE" > /dev/null 2>&1

# Create SQLite database and import data from CSV
sqlite3 "$DB_NAME" <<EOF
.mode csv
.import "$EXTRACTION_DIR/GeoLite2-City-Locations-en.csv" geonames
EOF


  # Remove downloaded and extracted files
  rm -r -r "$EXTRACTION_DIR"
  rm  "$DATABASE_FILE" "$SIGNATURE_FILE"
  echo ""
  echo "SQLite database '$DB_NAME' created successfully."
  echo "Now you can place $DB_NAME to 'datadir' of management service."
  echo -e "Example:\n\tdocker compose cp $DB_NAME management:/var/lib/netbird/"
}

download_geolite_mmdb
echo -e "\n\n"
download_geolite_csv_and_create_sqlite_db
echo -e "\n\n"
echo "After copying the database files to the management service. You can restart the management service with:"
echo -e "Example:\n\tdocker compose restart management"
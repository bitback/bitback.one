#!/bin/bash
#
# Update SRI hash for crypto.js across the project.
# Run this after ANY change to crypto.js.
#
# Usage: bash tools/update-crypto-hash.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CRYPTO_FILE="$PROJECT_DIR/crypto.js"

if [ ! -f "$CRYPTO_FILE" ]; then
    echo "ERROR: crypto.js not found at $CRYPTO_FILE"
    exit 1
fi

# Generate SHA-384 hash (SRI format)
HASH=$(openssl dgst -sha384 -binary "$CRYPTO_FILE" | openssl base64 -A)
SRI="sha384-$HASH"

echo "crypto.js SRI hash: $SRI"
echo ""

# Update index.php + view.php (TYLKO linie z crypto.js - nie ruszac SRI qrcode/totp)
for f in "$PROJECT_DIR/index.php" "$PROJECT_DIR/view.php"; do
    if grep -q 'crypto\.js' "$f"; then
        sed -i "/crypto\.js/ s|integrity=\"sha384-[A-Za-z0-9+/=]*\"|integrity=\"$SRI\"|" "$f"
        echo "Updated: $(basename "$f")"
    else
        echo "WARNING: No crypto.js tag found in $(basename "$f")"
    fi
done

# Update README.md / SECURITY.md
# Matchuj TYLKO pelny hash (base64 SHA-384 = 64 znaki) - inaczej sed trafia
# w prozowe "sha384-..." i dokleja hash w srodek zdania przy kazdym przebiegu.
for f in "$PROJECT_DIR/README.md" "$PROJECT_DIR/SECURITY.md"; do
    if grep -qE 'sha384-[A-Za-z0-9+/=]{64}' "$f"; then
        sed -i -E "s|sha384-[A-Za-z0-9+/=]{64}|$SRI|g" "$f"
        echo "Updated: $(basename "$f")"
    else
        echo "NOTE: No SHA-384 hash found in $(basename "$f") (add verification section first)"
    fi
done

echo ""
echo "Done. Verify changes with: git diff"
echo "Then commit: git add crypto.js index.php view.php README.md SECURITY.md"

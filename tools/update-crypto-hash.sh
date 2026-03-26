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

# Update index.php
if grep -q 'integrity="sha384-' "$PROJECT_DIR/index.php"; then
    sed -i "s|integrity=\"sha384-[A-Za-z0-9+/=]*\"|integrity=\"$SRI\"|g" "$PROJECT_DIR/index.php"
    echo "Updated: index.php"
else
    echo "WARNING: No SRI integrity attribute found in index.php"
fi

# Update view.php
if grep -q 'integrity="sha384-' "$PROJECT_DIR/view.php"; then
    sed -i "s|integrity=\"sha384-[A-Za-z0-9+/=]*\"|integrity=\"$SRI\"|g" "$PROJECT_DIR/view.php"
    echo "Updated: view.php"
else
    echo "WARNING: No SRI integrity attribute found in view.php"
fi

# Update README.md (the verification section)
if grep -q 'Expected SHA-384' "$PROJECT_DIR/README.md"; then
    sed -i "s|sha384-[A-Za-z0-9+/=]*|$SRI|g" "$PROJECT_DIR/README.md"
    echo "Updated: README.md"
else
    echo "NOTE: No SHA-384 hash found in README.md (add verification section first)"
fi

# Update SECURITY.md
if grep -q 'sha384-' "$PROJECT_DIR/SECURITY.md"; then
    sed -i "s|sha384-[A-Za-z0-9+/=]*|$SRI|g" "$PROJECT_DIR/SECURITY.md"
    echo "Updated: SECURITY.md"
else
    echo "NOTE: No SHA-384 hash found in SECURITY.md (add verification section first)"
fi

echo ""
echo "Done. Verify changes with: git diff"
echo "Then commit: git add crypto.js index.php view.php README.md SECURITY.md"

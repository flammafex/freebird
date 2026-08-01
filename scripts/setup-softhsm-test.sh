#!/bin/bash
# Setup SoftHSM for provider-level testing
#
# This script initializes a SoftHSM token and generates a P-256 key
# for testing the optional PKCS#11 provider. Issuer startup HSM integration is
# not implemented, so HSM_ENABLE=true is rejected by the issuer.
#
# Prerequisites:
#   - softhsm2
#   - pkcs11-tool (from opensc package)
#
# Usage:
#   ./scripts/setup-softhsm-test.sh

set -e

echo "🔐 Setting up SoftHSM for PKCS#11 provider-level testing..."

# Configuration
TOKEN_LABEL="freebird-test"
SLOT=0
USER_PIN="1234"
SO_PIN="1234"
KEY_LABEL="freebird-voprf-key"

# Detect SoftHSM module path
if [ -f "/usr/lib/softhsm/libsofthsm2.so" ]; then
    MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
elif [ -f "/usr/local/lib/softhsm/libsofthsm2.so" ]; then
    MODULE_PATH="/usr/local/lib/softhsm/libsofthsm2.so"
elif [ -f "/opt/homebrew/lib/softhsm/libsofthsm2.so" ]; then
    MODULE_PATH="/opt/homebrew/lib/softhsm/libsofthsm2.so"
else
    echo "❌ SoftHSM module not found. Please install softhsm2."
    echo ""
    echo "Ubuntu/Debian: sudo apt install softhsm2"
    echo "macOS: brew install softhsm"
    exit 1
fi

echo "📍 Using SoftHSM module: $MODULE_PATH"

# Check if token already exists
if softhsm2-util --show-slots | grep -q "$TOKEN_LABEL"; then
    echo "⚠️  Token '$TOKEN_LABEL' already exists. Deleting..."
    softhsm2-util --delete-token --token "$TOKEN_LABEL" || true
fi

# Initialize token
echo "🔧 Initializing SoftHSM token..."
softhsm2-util --init-token \
    --slot $SLOT \
    --label "$TOKEN_LABEL" \
    --pin "$USER_PIN" \
    --so-pin "$SO_PIN"

echo "✅ Token initialized"

# Generate P-256 key pair
echo "🔑 Generating P-256 key pair..."
pkcs11-tool --module "$MODULE_PATH" \
    --login --pin "$USER_PIN" \
    --keypairgen \
    --key-type EC:secp256r1 \
    --label "$KEY_LABEL" \
    --id 01

echo "✅ Key pair generated"

# Verify key was created
echo "🔍 Verifying key..."
pkcs11-tool --module "$MODULE_PATH" \
    --login --pin "$USER_PIN" \
    --list-objects

echo ""
echo "✅ SoftHSM setup complete!"
echo ""
echo "Provider-level test values (do not enable issuer HSM startup):"
echo "  HSM_ENABLE=true is rejected by the issuer until startup integration exists"
echo "  HSM_MODE=storage (reserved)"
echo "  HSM_MODULE_PATH=$MODULE_PATH"
echo "  HSM_SLOT=$SLOT"
echo "  HSM_PIN=$USER_PIN"
echo "  HSM_KEY_LABEL=$KEY_LABEL"
echo ""
echo "Use these values only with the optional PKCS#11 provider tests."

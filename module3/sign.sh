#!/usr/bin/env bash
# Simple OpenSSL digital signature demo (ECDSA P-256)

# Stop on first error
set -e

# 1) Generate ECDSA P-256 keypair
echo "[+] Generating ECDSA P-256 keypair..."
openssl ecparam -name prime256v1 -genkey -noout -out private.key
openssl ec -in private.key -pubout -out public.pem

# 2) Create a message file
echo "important message" > message.txt

# 3) Sign the file
echo "[+] Signing message..."
openssl dgst -sha256 -sign private.key -out signature.bin message.txt

# 4) Verify the signature
echo "[+] Verifying signature..."
openssl dgst -sha256 -verify public.pem -signature signature.bin message.txt

echo "[+] Done. If you saw 'Verified OK', the signature is valid."

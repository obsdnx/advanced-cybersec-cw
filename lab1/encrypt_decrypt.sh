#!/usr/bin/env bash
# =============================================================================
# Lab 1 — Secret Key Encryption
# Task: Demonstrating AES encryption/decryption modes with openssl enc
# Description:
#   Shows AES-128-CBC with explicit key and IV, password-based encryption
#   (with and without -pbkdf2), and AES-128-ECB for comparison.
# =============================================================================

set -euo pipefail

PLAINTEXT="plaintext.txt"
CIPHERTEXT_CBC="cipher_aes_cbc.bin"
DECRYPTED_CBC="decrypted_cbc.txt"
CIPHERTEXT_ECB="cipher_aes_ecb.bin"
DECRYPTED_ECB="decrypted_ecb.txt"
CIPHERTEXT_PWD="cipher_password.bin"
CIPHERTEXT_PBKDF2="cipher_pbkdf2.bin"
DECRYPTED_PWD="decrypted_pwd.txt"

# Create a sample plaintext file for demonstration
echo "This is a secret message for Lab 1 encryption demonstration." > "$PLAINTEXT"

# -----------------------------------------------------------------------------
# Section 1: AES-128-CBC with explicit key and IV
# -----------------------------------------------------------------------------
# Key and IV must each be 128 bits (32 hex characters = 16 bytes).
# Using -K and -iv flags tells openssl to use the raw hex values directly,
# bypassing any key derivation function.

KEY="00112233445566778899aabbccddeeff"   # 128-bit key (32 hex digits)
IV="0102030405060708090a0b0c0d0e0f10"    # 128-bit IV  (32 hex digits)

echo "=== AES-128-CBC Encryption (explicit key + IV) ==="
openssl enc -aes-128-cbc \
    -e \                    # -e = encrypt mode
    -in  "$PLAINTEXT" \
    -out "$CIPHERTEXT_CBC" \
    -K   "$KEY" \           # Raw hex key (no KDF)
    -iv  "$IV"              # Raw hex IV

echo "Encrypted '$PLAINTEXT' -> '$CIPHERTEXT_CBC'"

echo ""
echo "=== AES-128-CBC Decryption (explicit key + IV) ==="
openssl enc -aes-128-cbc \
    -d \                    # -d = decrypt mode
    -in  "$CIPHERTEXT_CBC" \
    -out "$DECRYPTED_CBC" \
    -K   "$KEY" \
    -iv  "$IV"

echo "Decrypted '$CIPHERTEXT_CBC' -> '$DECRYPTED_CBC'"
echo "Decrypted content:"
cat "$DECRYPTED_CBC"

# -----------------------------------------------------------------------------
# Section 2: Password-based encryption — DEPRECATED WARNING
# -----------------------------------------------------------------------------
# When -pass is used without -pbkdf2, openssl defaults to the old EVP_BytesToKey
# key derivation, which is weak and triggers this warning:
#
#   *** WARNING : deprecated key derivation used.
#   Using -iter or -pbkdf2 would be better.
#
# This section intentionally demonstrates that behaviour.

echo ""
echo "=== Password-based AES-128-CBC (DEPRECATED KDF — warning expected) ==="
openssl enc -aes-128-cbc \
    -e \
    -in   "$PLAINTEXT" \
    -out  "$CIPHERTEXT_PWD" \
    -pass pass:"supersecretpassword"
# ^ openssl will print a deprecation warning here

echo "Password-based ciphertext written to '$CIPHERTEXT_PWD'"

# -----------------------------------------------------------------------------
# Section 3: Password-based encryption with -pbkdf2 (recommended fix)
# -----------------------------------------------------------------------------
# The -pbkdf2 flag switches the KDF to PBKDF2-HMAC-SHA256, which is far more
# resistant to brute-force attacks. The -iter flag controls the iteration count
# (default 10000 when -pbkdf2 is specified).

echo ""
echo "=== Password-based AES-128-CBC with -pbkdf2 (no deprecation warning) ==="
openssl enc -aes-128-cbc \
    -e \
    -pbkdf2 \               # Use PBKDF2 instead of EVP_BytesToKey
    -iter 100000 \          # 100 000 iterations makes brute-force slower
    -in   "$PLAINTEXT" \
    -out  "$CIPHERTEXT_PBKDF2" \
    -pass pass:"supersecretpassword"

echo "PBKDF2-encrypted ciphertext written to '$CIPHERTEXT_PBKDF2'"

echo ""
echo "=== Decrypt the PBKDF2-encrypted file ==="
openssl enc -aes-128-cbc \
    -d \
    -pbkdf2 \
    -iter 100000 \
    -in   "$CIPHERTEXT_PBKDF2" \
    -out  "$DECRYPTED_PWD" \
    -pass pass:"supersecretpassword"

echo "Decrypted content:"
cat "$DECRYPTED_PWD"

# -----------------------------------------------------------------------------
# Section 4: AES-128-ECB — for comparison with CBC
# -----------------------------------------------------------------------------
# ECB (Electronic Codebook) encrypts each 16-byte block independently with the
# same key. Identical plaintext blocks produce IDENTICAL ciphertext blocks, so
# patterns in the plaintext leak into the ciphertext — see encrypt_image.sh for
# a visual demonstration of this weakness.
#
# Note: ECB does NOT use an IV (there is no chaining between blocks).

echo ""
echo "=== AES-128-ECB Encryption (no IV, for comparison) ==="
openssl enc -aes-128-ecb \
    -e \
    -in  "$PLAINTEXT" \
    -out "$CIPHERTEXT_ECB" \
    -K   "$KEY"             # ECB takes a key but no IV

echo "ECB ciphertext written to '$CIPHERTEXT_ECB'"

echo ""
echo "=== AES-128-ECB Decryption ==="
openssl enc -aes-128-ecb \
    -d \
    -in  "$CIPHERTEXT_ECB" \
    -out "$DECRYPTED_ECB" \
    -K   "$KEY"

echo "ECB decrypted content:"
cat "$DECRYPTED_ECB"

echo ""
echo "All encryption/decryption demonstrations complete."

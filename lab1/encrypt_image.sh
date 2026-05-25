#!/usr/bin/env bash
# =============================================================================
# Lab 1 — Secret Key Encryption
# Task: Encrypt a BMP image with ECB and CBC to compare visual leakage
# Description:
#   Encrypts pic_original.bmp using AES-128-ECB and AES-128-CBC.
#   For ECB, the original 54-byte BMP header is prepended back onto the
#   encrypted body so it can be rendered as a valid (but scrambled) image.
#   This visually demonstrates why ECB mode is insecure for structured data.
# =============================================================================

set -euo pipefail

ORIGINAL="pic_original.bmp"
HEADER_BYTES=54          # Standard BMP header size (14-byte file header + 40-byte DIB header)

ECB_ENCRYPTED_BODY="pic_ecb_body.bin"
ECB_OUTPUT="pic_ecb.bmp"

CBC_OUTPUT_RAW="pic_cbc_raw.bin"
CBC_OUTPUT="pic_cbc.bmp"

# Fixed key and IV (128-bit = 32 hex chars each)
KEY="00112233445566778899aabbccddeeff"
IV="aabbccddeeff00112233445566778899"

# -----------------------------------------------------------------------------
# Step 1: Extract the BMP header from the original file
# -----------------------------------------------------------------------------
# The first 54 bytes of any BMP file describe the image dimensions, bit depth,
# colour table, etc. Image viewers use this header to know how to render the data.
# We must preserve the header so the encrypted output is still a "valid" BMP.

dd if="$ORIGINAL" of=pic_header.bin bs=1 count=$HEADER_BYTES 2>/dev/null
echo "Extracted $HEADER_BYTES-byte BMP header -> pic_header.bin"

# Extract the pixel data (everything after the header) for encryption
dd if="$ORIGINAL" of=pic_body.bin bs=1 skip=$HEADER_BYTES 2>/dev/null
echo "Extracted pixel body -> pic_body.bin"

# -----------------------------------------------------------------------------
# Step 2: Encrypt the pixel body with AES-128-ECB
# -----------------------------------------------------------------------------
# ECB encrypts each 16-byte block INDEPENDENTLY with the same key.
# Because the same plaintext block always produces the same ciphertext block,
# repeated patterns in the image (e.g., large uniform-colour regions) will
# appear as repeated blocks in the ciphertext — the structure is visible!

openssl enc -aes-128-ecb \
    -e \
    -nosalt \               # No salt so the ciphertext is deterministic
    -in  pic_body.bin \
    -out "$ECB_ENCRYPTED_BODY" \
    -K   "$KEY"
echo "ECB-encrypted pixel body -> $ECB_ENCRYPTED_BODY"

# -----------------------------------------------------------------------------
# Step 3: Reassemble ECB image — prepend original header onto encrypted body
# -----------------------------------------------------------------------------
# cat-joining the original header with the encrypted body produces a BMP
# that viewers can open. The header tells the viewer the image dimensions;
# the body contains ciphertext — yet patterns from the original image
# remain recognisable in the ECB output.

cat pic_header.bin "$ECB_ENCRYPTED_BODY" > "$ECB_OUTPUT"
echo "Reassembled ECB BMP (header + encrypted body) -> $ECB_OUTPUT"

# -----------------------------------------------------------------------------
# Step 4: Encrypt the WHOLE file with AES-128-CBC
# -----------------------------------------------------------------------------
# CBC XORs each plaintext block with the previous ciphertext block before
# encrypting. This "chaining" ensures that identical plaintext blocks produce
# DIFFERENT ciphertext blocks, destroying any visible patterns.
# However, because the header is also encrypted, the output is NOT a valid BMP.
# To produce a viewable file we apply the same header-swap trick.

openssl enc -aes-128-cbc \
    -e \
    -nosalt \
    -in  pic_body.bin \    # Encrypt only the body so we can prepend the header
    -out pic_cbc_body.bin \
    -K   "$KEY" \
    -iv  "$IV"
echo "CBC-encrypted pixel body -> pic_cbc_body.bin"

# Prepend the original header to the CBC-encrypted body
cat pic_header.bin pic_cbc_body.bin > "$CBC_OUTPUT"
echo "Reassembled CBC BMP (header + encrypted body) -> $CBC_OUTPUT"

# -----------------------------------------------------------------------------
# Step 5: Visual comparison guidance
# -----------------------------------------------------------------------------
# WHY ECB LEAKS STRUCTURE:
#   In ECB mode, block i of ciphertext = E_K(block_i of plaintext).
#   If two plaintext blocks are identical, their ciphertext blocks are also
#   identical. Large flat regions of an image produce many identical 16-byte
#   pixel blocks, which map to identical ciphertext blocks. The result is
#   that the shape/outline of objects in the image is still visible.
#
# WHY CBC DOES NOT:
#   In CBC mode, block i of ciphertext = E_K(block_i XOR ciphertext_{i-1}).
#   Even if two plaintext blocks are identical, the XOR with the previous
#   ciphertext block (which differs) makes their ciphertext blocks different.
#   The output looks like random noise — no structure is preserved.

echo ""
echo "=== Visual comparison ==="
echo "Open the following files side-by-side in an image viewer:"
echo "  Original :  $ORIGINAL"
echo "  ECB mode :  $ECB_OUTPUT   <- patterns from original are visible!"
echo "  CBC mode :  $CBC_OUTPUT   <- looks like random noise (secure)"
echo ""
echo "On Linux with eog (Eye of GNOME):"
echo "  eog $ORIGINAL $ECB_OUTPUT $CBC_OUTPUT"
echo ""
echo "On macOS:"
echo "  open $ORIGINAL $ECB_OUTPUT $CBC_OUTPUT"

# Clean up temporary files
rm -f pic_header.bin pic_body.bin "$ECB_ENCRYPTED_BODY" pic_cbc_body.bin
echo ""
echo "Temporary intermediate files removed."

#!/usr/bin/env python3
"""
Lab 1 — Secret Key Encryption
Task: Frequency Analysis on a Monoalphabetic Substitution Cipher
Description:
    Reads ciphertext.txt, performs letter-frequency analysis (unigrams,
    bigrams, trigrams), identifies single-letter words, and applies a
    known substitution mapping to recover the plaintext.
"""

import sys
from collections import Counter

# =============================================================================
# 1. Load ciphertext
# =============================================================================

CIPHERTEXT_FILE = "ciphertext.txt"

try:
    with open(CIPHERTEXT_FILE, "r") as fh:
        raw = fh.read()
except FileNotFoundError:
    print(f"[ERROR] '{CIPHERTEXT_FILE}' not found. Place the ciphertext in the same directory.")
    sys.exit(1)

# Work with lowercase only; preserve original for display
ciphertext = raw.lower()

# =============================================================================
# 2. Unigram frequency table with bar chart
# =============================================================================

# Count only alphabetic characters (ignore punctuation, digits, spaces)
letters_only = [ch for ch in ciphertext if ch.isalpha()]
total_letters = len(letters_only)

letter_counts = Counter(letters_only)

print("=" * 60)
print("UNIGRAM FREQUENCY TABLE")
print("=" * 60)
print(f"{'Cipher':<8} {'Count':<8} {'Freq %':<10} {'Bar'}")
print("-" * 60)

# Sort by frequency descending — most common cipher letters appear first,
# which we compare against known English frequencies (E, T, A, O, I, N, ...)
for letter, count in sorted(letter_counts.items(), key=lambda x: -x[1]):
    freq = count / total_letters * 100
    bar = "#" * int(freq)          # Each '#' ≈ 1 % of the text
    print(f"  {letter!r:<6} {count:<8} {freq:<10.2f} {bar}")

# =============================================================================
# 3. Bigrams (two-letter combinations)
# =============================================================================

bigrams = [letters_only[i] + letters_only[i + 1] for i in range(len(letters_only) - 1)]
bigram_counts = Counter(bigrams)

print("\n" + "=" * 60)
print("TOP-20 BIGRAMS")
print("=" * 60)
for bigram, count in bigram_counts.most_common(20):
    print(f"  {bigram}  :  {count}")

# Common English bigrams for reference: TH, HE, IN, ER, AN, RE, ON, EN, ...

# =============================================================================
# 4. Trigrams (three-letter combinations)
# =============================================================================

trigrams = [
    letters_only[i] + letters_only[i + 1] + letters_only[i + 2]
    for i in range(len(letters_only) - 2)
]
trigram_counts = Counter(trigrams)

print("\n" + "=" * 60)
print("TOP-20 TRIGRAMS")
print("=" * 60)
for trigram, count in trigram_counts.most_common(20):
    print(f"  {trigram}  :  {count}")

# Common English trigrams for reference: THE, AND, ING, HER, HAT, ...

# =============================================================================
# 5. Single-letter words
# =============================================================================
# In English the only common single-letter words are 'a' and 'i'.
# Finding the most frequent single-letter cipher word gives a quick anchor.

words = ciphertext.split()
single_letter_words = [w.strip(".,;:!?\"'()-") for w in words if len(w.strip(".,;:!?\"'()-")) == 1 and w.strip(".,;:!?\"'()-").isalpha()]
single_counts = Counter(single_letter_words)

print("\n" + "=" * 60)
print("SINGLE-LETTER WORDS (strong clues for 'a' and 'i')")
print("=" * 60)
for letter, count in single_counts.most_common():
    print(f"  '{letter}'  :  {count} occurrence(s)")

# =============================================================================
# 6. Substitution key mapping (cipher -> plaintext)
# =============================================================================
# This mapping was derived iteratively by comparing cipher frequencies to
# English letter frequencies and testing bigram/trigram patterns.
#
# Cipher letter  ->  Real (plaintext) letter
#   v -> a      (most frequent cipher letter maps to most frequent English 'e'? No —
#                 analysis placed 'v' as 'a' after checking single-letter words)
#   g -> b
#   a -> c
#   p -> d
#   n -> e
#   b -> f
#   r -> g
#   t -> h
#   m -> i
#   o -> j
#   s -> k
#   i -> l
#   c -> m
#   u -> n
#   x -> o
#   e -> p
#   j -> q
#   h -> r
#   q -> s
#   y -> t
#   z -> u
#   f -> v
#   l -> w
#   k -> x
#   d -> y
#   w -> z

CIPHER_TO_PLAIN = {
    "v": "a",
    "g": "b",
    "a": "c",
    "p": "d",
    "n": "e",
    "b": "f",
    "r": "g",
    "t": "h",
    "m": "i",
    "o": "j",
    "s": "k",
    "i": "l",
    "c": "m",
    "u": "n",
    "x": "o",
    "e": "p",
    "j": "q",
    "h": "r",
    "q": "s",
    "y": "t",
    "z": "u",
    "f": "v",
    "l": "w",
    "k": "x",
    "d": "y",
    "w": "z",
}

# =============================================================================
# 7. Apply the substitution to produce plaintext
# =============================================================================

def apply_substitution(text: str, mapping: dict) -> str:
    """
    Translate each character in *text* using *mapping*.
    Non-alphabetic characters (spaces, punctuation) are preserved as-is.
    Case is handled by decoding lowercase ciphertext then restoring original case.
    """
    result = []
    for orig_char in text:
        lower_char = orig_char.lower()
        if lower_char in mapping:
            plain_char = mapping[lower_char]
            # Preserve original capitalisation
            result.append(plain_char.upper() if orig_char.isupper() else plain_char)
        else:
            # Keep spaces, digits, punctuation unchanged
            result.append(orig_char)
    return "".join(result)


plaintext = apply_substitution(raw, CIPHER_TO_PLAIN)

print("\n" + "=" * 60)
print("RECOVERED PLAINTEXT")
print("=" * 60)
print(plaintext)

# =============================================================================
# 8. Verify: frequency table of recovered plaintext (should look like English)
# =============================================================================

plain_letters = [ch for ch in plaintext.lower() if ch.isalpha()]
plain_counts = Counter(plain_letters)

print("\n" + "=" * 60)
print("PLAINTEXT LETTER FREQUENCIES (sanity check — should look like English)")
print("=" * 60)
for letter, count in sorted(plain_counts.items(), key=lambda x: -x[1])[:10]:
    freq = count / len(plain_letters) * 100
    bar = "#" * int(freq)
    print(f"  {letter!r:<6} {count:<8} {freq:<10.2f} {bar}")

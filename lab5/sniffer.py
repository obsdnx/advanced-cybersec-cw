#!/usr/bin/env python3
"""
Lab 5 — Sniffing and Spoofing
Task: Passive packet sniffer using Scapy
Description:
    Listens on the specified network interface and prints every ICMP packet
    that passes through it.  Uses a BPF (Berkeley Packet Filter) expression
    to discard non-ICMP traffic at the kernel level before Scapy sees it,
    minimising userspace overhead.

    Must be run as root (or with CAP_NET_RAW capability):
        sudo python3 sniffer.py
"""

from scapy.all import sniff, Packet

# =============================================================================
# Network interface to sniff on
# =============================================================================
# br-551f268b0f64 is the Linux bridge interface created by Docker for the
# lab network (10.9.0.0/24).  Change this to 'eth0', 'ens33', etc. if your
# environment uses a different interface.
#
# Find the correct interface with:
#   ip link show
# or:
#   ifconfig -a

INTERFACE = "br-551f268b0f64"

# =============================================================================
# BPF filter
# =============================================================================
# BPF (Berkeley Packet Filter) is a mini-language compiled into the kernel's
# packet filtering engine.  Filtering in the kernel is far more efficient than
# receiving every packet in Python and discarding unwanted ones.
#
# Syntax examples:
#   "icmp"              — only ICMP packets
#   "tcp port 23"       — only TCP packets on port 23 (Telnet)
#   "udp"               — only UDP packets
#   "src host 10.9.0.1" — only packets from a specific source IP
#   "not arp"           — exclude ARP frames
#
# Multiple expressions can be combined with and / or / not.

BPF_FILTER = "icmp"   # Capture only ICMP (ping) traffic

# =============================================================================
# Packet callback
# =============================================================================

def print_pkt(pkt: Packet) -> None:
    """
    Called by Scapy for each packet matching the BPF filter.

    pkt.show() prints a human-readable breakdown of every layer:
        ###[ Ethernet ]###
          dst = ff:ff:ff:ff:ff:ff
          src = 02:42:0a:09:00:01
          type = IPv4
        ###[ IP ]###
          version = 4
          ...
        ###[ ICMP ]###
          type = echo-request (8)
          code = 0
          ...
    """
    pkt.show()   # Dump all layers to stdout
    print("-" * 60)  # Visual separator between packets

# =============================================================================
# Start sniffing
# =============================================================================

print(f"[*] Sniffing ICMP on interface '{INTERFACE}' ...")
print(f"[*] BPF filter: '{BPF_FILTER}'")
print(f"[*] Press Ctrl+C to stop.\n")

sniff(
    iface=INTERFACE,    # Restrict capture to this interface only
    filter=BPF_FILTER,  # Kernel-level BPF filter
    prn=print_pkt,      # Callback invoked for each matching packet
)

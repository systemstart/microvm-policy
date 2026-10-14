#!/usr/bin/env python3
"""Generate a small pcap fixture for the egress-report flake check.

Shapes the traffic mix the summarizer has to classify:
  1. DNS query  A api.anthropic.com         -> a queried domain
  2. DNS answer api.anthropic.com=198.51.100.10 -> feeds the ip-to-name map
  3. TCP SYN to 198.51.100.10:443           -> attributed via that answer
  4. TLS ClientHello, SNI api.anthropic.com -> an SNI connection
  5. DNS query  A evil.example.com          -> the allowlist violation
  6. TCP SYN to 203.0.113.7:4444            -> no observed hostname (TCP)
  7. UDP packet to 203.0.113.9:123          -> no observed hostname (UDP)
  8. DNS query  AAAA v6.example.net         -> a queried domain
  9. DNS answer v6.example.net=2001:db8::10 -> feeds the ip-to-name map (AAAA)
 10. IPv6 TCP SYN to [2001:db8::10]:443     -> attributed via that answer
 11. IPv6 TCP SYN to [2001:db8::bad]:443    -> no observed hostname, [a]:p form
 12. inbound UDP reply 203.0.113.9 -> guest -> inbound, must count nothing
 13. DNS query  A claude-vm                 -> single label, resolver noise
"""
import struct
import sys

GUEST = bytes([10, 0, 2, 15])
RESOLVER = bytes([10, 0, 2, 3])
API_ADDR = bytes([198, 51, 100, 10])
GUEST6 = bytes.fromhex("fec0" + "0" * 26 + "15")
V6_KNOWN = bytes.fromhex("20010db8" + "0" * 20 + "0010")
V6_UNKNOWN = bytes.fromhex("20010db8" + "0" * 20 + "0bad")


def eth(payload, ethertype=0x0800):
    return bytes(6) + bytes(6) + struct.pack(">H", ethertype) + payload


def ipv6(src, dst, next_header, payload):
    hdr = struct.pack(">IHBB16s16s", 0x60000000, len(payload), next_header, 64, src, dst)
    return hdr + payload


def ipv4(src, dst, proto, payload):
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), 0x1234, 0x4000, 64, proto, 0, src, dst,
    )
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, flags, payload=b""):
    return (
        struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0)
        + payload
    )


def qname(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(txid, name, qtype=1):
    return (
        struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + qname(name)
        + struct.pack(">HH", qtype, 1)
    )


def dns_answer(txid, name, addr, qtype=1):
    question = qname(name) + struct.pack(">HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 300, len(addr)) + addr
    return struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def client_hello(sni):
    name = sni.encode()
    server_name_list = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack(">HH", 0, len(server_name_list)) + server_name_list
    exts = struct.pack(">H", len(ext)) + ext
    body = (
        struct.pack(">H", 0x0303)  # client_version
        + bytes(32)                # random
        + b"\x00"                  # session_id length
        + struct.pack(">H", 2) + b"\x13\x01"  # one cipher suite
        + b"\x01\x00"              # null compression
        + exts
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


packets = [
    eth(ipv4(GUEST, RESOLVER, 17, udp(40000, 53, dns_query(1, "api.anthropic.com")))),
    eth(ipv4(RESOLVER, GUEST, 17, udp(53, 40000, dns_answer(1, "api.anthropic.com", API_ADDR)))),
    eth(ipv4(GUEST, API_ADDR, 6, tcp(40001, 443, 0x02))),
    eth(ipv4(GUEST, API_ADDR, 6, tcp(40001, 443, 0x18, client_hello("api.anthropic.com")))),
    eth(ipv4(GUEST, RESOLVER, 17, udp(40002, 53, dns_query(2, "evil.example.com")))),
    eth(ipv4(GUEST, bytes([203, 0, 113, 7]), 6, tcp(40003, 4444, 0x02))),
    eth(ipv4(GUEST, bytes([203, 0, 113, 9]), 17, udp(40004, 123, bytes(48)))),
    eth(ipv4(GUEST, RESOLVER, 17, udp(40005, 53, dns_query(3, "v6.example.net", 28)))),
    eth(ipv4(RESOLVER, GUEST, 17, udp(53, 40005, dns_answer(3, "v6.example.net", V6_KNOWN, 28)))),
    eth(ipv6(GUEST6, V6_KNOWN, 6, tcp(40006, 443, 0x02)), 0x86DD),
    eth(ipv6(GUEST6, V6_UNKNOWN, 6, tcp(40007, 443, 0x02)), 0x86DD),
    eth(ipv4(bytes([203, 0, 113, 9]), GUEST, 17, udp(123, 40004, bytes(48)))),
    eth(ipv4(GUEST, RESOLVER, 17, udp(40008, 53, dns_query(4, "claude-vm")))),
]

with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, pkt in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(pkt), len(pkt)))
        f.write(pkt)


import sys
sys.path.append("../build/lib.linux-x86_64-3.4/")
import packet
import socket

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
					 socket.IPPROTO_RAW)
pkt = packet.udp()

pkt.ethernet_src = (0x6c, 0x62, 0x6d, 0x7c, 0x42, 0x2c)
pkt.ethernet_dst = (0x84, 0xc9, 0xb2, 0x5b, 0x53, 0x00)
pkt.ethernet_type = 0x0800

pkt.ip_hlen = 5
pkt.ip_version = 4
pkt.ip_dsf = 0
pkt.ip_len = 49 + 20
pkt.ip_identifier = 3005
pkt.ip_frag_off = 0x00
pkt.ip_ttl = 128
pkt.ip_proto = 17
pkt.ip_csum = 0
pkt.ip_source = "192.168.0.121"
pkt.ip_dest = "192.168.0.1"

pkt.udp_src = 4000
pkt.udp_dst = 8000
pkt.udp_len = 49
pkt.udp_csum = 0
pkt.udp_payload = b"A" * 41
pkt.calc_csum()

sock.sendto(pkt.to_bytes(), 0, ("enp2s0", 0))

import sys
sys.path.append("../build/lib.linux-x86_64-3.4/")
import packet
import socket

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
					 socket.IPPROTO_RAW)
pkt = packet.tcp()

pkt.ethernet_src = (0x6c, 0x62, 0x6d, 0x7c, 0x42, 0x2c)
pkt.ethernet_dst = (0x84, 0xc9, 0xb2, 0x5b, 0x53, 0x00)
pkt.ethernet_type = 0x0800

pkt.ip_hlen = 5
pkt.ip_version = 4
pkt.ip_dsf = 0
pkt.ip_len = 20 + 40
pkt.ip_identifier = 3005
pkt.ip_frag_off = 0x00
pkt.ip_ttl = 128
pkt.ip_proto = 0x0006
pkt.ip_csum = 0
pkt.ip_source = "192.168.0.121"
pkt.ip_dest = "192.168.0.1"

pkt.tcp_hlen = 20 >> 2
pkt.tcp_src = 1000
pkt.tcp_dst = 2000
pkt.tcp_seq = 0
pkt.tcp_seq_ack = 0
pkt.tcp_set_flags(syn = 1)
pkt.tcp_win = 20000
pkt.tcp_csum = 0
pkt.tcp_urg_ptr = 0
pkt.tcp_payload = b"A" * 20
pkt.calc_csum()
pkt.tcp_csum = 0x479f

sock.sendto(pkt.to_bytes(), 0, ("enp2s0", 0))
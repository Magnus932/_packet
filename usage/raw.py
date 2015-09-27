
import sys
sys.path.append("../build/lib.linux-x86_64-3.4/")
import packet
import socket

# Sending raw packets example from the data link
# layer. This example sends an ARP packet of type
# 'reply' to a destination host. For higher protocols
# the checksum algorithms are not made yet, so you need
# to calculate them in your head. HEHE
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
					 socket.IPPROTO_RAW)
pkt = packet.arp()

mac_src = (0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
mac_dst = (0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
pkt.ethernet_dst = mac_dst
pkt.ethernet_src = mac_src
pkt.ethernet_type = 0x0806

pkt.arp_hw_type = 0x01
pkt.arp_proto = 0x0800
pkt.arp_hw_size = 0x06
pkt.arp_proto_size = 0x04
pkt.arp_opcode = 0x02
pkt.arp_src_mac = mac_src
pkt.arp_src_ip = "XXXXXXXXXXXX"
pkt.arp_dst_mac = mac_dst
pkt.arp_dst_ip = "XXXXXXXXXXXX"

sock.sendto(pkt.to_bytes(), 0, ("enp2s0", 0))
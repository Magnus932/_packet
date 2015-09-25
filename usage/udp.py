
import sys
sys.path.append("../build/lib.linux-x86_64-3.4")
import packet

# Shows examples of how to use the udp type
handle = packet.ppcap()
handle.open_live("enp2s0", 1514, 0, -1)
handle.lookupnet("enp2s0")
handle.compile("udp")
handle.setfilter()

def generic_udp(pkt):
	print("mac src:%s -> mac dst:%s" % (pkt.ethernet_src,
									    pkt.ethernet_dst))
	print("ethernet type:0x%x" % pkt.ethernet_type)
	print("ip src:%s(%d) -> ip dst:%s(%d)" % (pkt.ip_source, pkt.udp_src,
											  pkt.ip_dest, pkt.udp_dst))
	print("udp csum:0x%x" % pkt.udp_csum)
	print("udp len:%d" % pkt.udp_len)
	print("udp payload:")
	print(pkt.udp_payload)
	print("------------------------------------------------------")

# Example using a callback
#def my_callback(pkt):
#	generic_udp(pkt)

#handle.loop(20, my_callback)
###########################

# Example using pulls
while (1):
	pkt = handle.next()
	if (pkt != None):
		generic_udp(pkt)

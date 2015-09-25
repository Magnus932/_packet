
import sys
sys.path.append("../build/lib.linux-x86_64-3.4/")
import packet

# Shows example using the tcp type
handle = packet.ppcap()

dev = handle.lookupdev()
handle.open_live(dev, 1514, 0, -1)
handle.lookupnet(dev)
handle.compile("tcp")
handle.setfilter()

def tcp_generic(pkt):
	tupl = (pkt.ip_source, pkt.tcp_src, pkt.ip_dest,
			pkt.tcp_dst)
	print("%s(%d) => %s(%d)" % tupl)
	print("seq => %d, ack => %d" % (pkt.tcp_seq, pkt.tcp_seq_ack))
	flags = pkt.tcp_get_flags()
	for i in flags:
		print("%s => %d" % (i, flags[i]))
	print(pkt.tcp_payload)
	print("---------------------------------------------")

while 1:
	pkt = handle.next()
	if not pkt:
		continue
	tcp_generic(pkt)
handle.close()
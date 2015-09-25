
import sys
sys.path.append("../build/lib.linux-x86_64-3.4")
import packet

# Shows examples of how to iterate through
# all the available devices, or finding the
# default device.
handle = packet.ppcap()

# Find all the present devices:
li = handle.findalldevs()
for i in li:
	print(i)

# Find the default device
dev = handle.lookupdev()
print(dev)

# Always close the handle when done
handle.close()

from distutils.core import setup, Extension

FILES = ["src/packetmodule.c", "src/ppcap.c",
		 "src/packet.c", "src/ethernet.c",
		 "src/arp.c", "src/ip.c",
		 "src/tcp.c", "src/udp.c"]

module = Extension("_packet", include_dirs = ["/usr/include", "."],
				   library_dirs = ["/usr/lib/"],
				   libraries = ["pcap"],
				   extra_compile_args = ["-Wno-unused-variable", "-Wno-pointer-sign"],
				   sources = FILES)

setup(name = "_packet", version = "1.0",
	  ext_modules = [module])

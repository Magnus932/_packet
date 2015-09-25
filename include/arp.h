
#ifndef INCLUDE_ARP_H
#define INCLUDE_ARP_H

#include "ethernet.h"

struct arp {
	u16 hw_type;
	u16 proto;
	u8 hw_size;
	u8 proto_size;
	u16 opcode;
	u8 src_mac[6];
	u32 src_ip;
	u8 dst_mac[6];
	u32 dst_ip;
} __attribute__ ((packed));

typedef struct {
	ethernet base_obj;
	struct arp __arp;
} arp;

#define arp_offset(x) (offsetof(arp, __arp) + \
					   offsetof(struct arp, x))
int arp_add_type(PyObject *module);
PyObject *create_arp_instance(int caplen,
							  const unsigned char *pkt);

#endif
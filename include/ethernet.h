
#ifndef INCLUDE_ETHERNET_H
#define INCLUDE_ETHERNET_H

#include "packet.h"

#define ETHERNET_DST_DESC		"Destination MAC address"
#define ETHERNET_SRC_DESC		"Source MAC address"
#define ETHERNET_TYP_DESC		"Protocol of the payload"

struct ethernet {
	u8 dst[6];
	u8 src[6];
	u16 type;
};

typedef struct {
	packet base_obj;
	struct ethernet __ethernet;
} ethernet;

#define ethernet_offset(x) (offsetof(ethernet, __ethernet) \
							+ offsetof(struct ethernet, x))
int ethernet_add_type(PyObject *module);
PyObject *create_ethernet_instance(int caplen,
								   const unsigned char *pkt);

#endif
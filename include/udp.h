
#ifndef INCLUDE_UDP_H
#define INCLUDE_UDP_H

#include "ip.h"

struct udp {
	u16 src;
	u16 dst;
	u16 len;
	u16 csum;
};

typedef struct {
	ip base_obj;
	struct udp __udp;
	PyObject *payload;
} udp;

#define udp_offset(x) (offsetof(udp, __udp) + \
					   offsetof(struct udp, x))
#define udp_payload_offset   (sizeof(struct ethernet) + \
							  sizeof(struct ip) + \
							  sizeof(struct udp))
int udp_add_type(PyObject *module);
PyObject *create_udp_instance(int caplen,
							  const unsigned char *pkt);

#endif
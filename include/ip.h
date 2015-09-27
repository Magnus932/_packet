
#ifndef INCLUDE_IP_H
#define INCLUDE_IP_H

#include "ethernet.h"

struct ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u32 hlen:4;
	u32 version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u32 version:4;
	u32 hlen:4;
#else
	#error "<bits/endian.h> broken"
#endif
	u8 dsf;
	u16 len;
	u16 identifier;
	u16 frag_off;
	u8 ttl;
	u8 proto;
	u16 csum;
	u32 source;
	u32 dest;
};

typedef struct {
	ethernet base_obj;
	struct ip __ip;
} ip;

#define IP_HLEN				(void *)0
#define IP_VERSION			(void *)1
#define IP_LEN 				(void *)2
#define IP_IDENTIFIER 		(void *)3
#define IP_FRAG_OFF 		(void *)4
#define IP_CSUM				(void *)5

#define ip_offset(x) (offsetof(ip, __ip) + \
					  offsetof(struct ip, x))
int ip_add_type(PyObject *module);
PyObject *create_ip_instance(int caplen,
							 const unsigned char *pkt);
char *ip_attr_string(void *closure);

#endif
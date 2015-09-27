
#ifndef INCLUDE_TCP_H
#define INCLUDE_TCP_H

#include "ip.h"

struct tcp {
	u16 src;
	u16 dst;
	u32 seq;
	u32 seq_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u32 nonce:1;
	u32 res:3;
	u32 hlen:4;
	u32 fin:1;
	u32 syn:1;
	u32 rst:1;
	u32 push:1;
	u32 ack:1;
	u32 urg:1;
	u32 echo:1;
	u32 cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u32 hlen:4;
	u32 res:3;
	u32 nonce:1;
	u32 cwr:1;
	u32 echo:1;
	u32 urg:1;
	u32 ack:1;
	u32 push:1;
	u32 rst:1;
	u32 syn:1;
	u32 fin:1;
#else
	#error "<bits/endian.h> broken"
#endif
	u16 win_size;
	u16 csum;
	u16 urg_ptr;
};

typedef struct {
	ip base_obj;
	struct tcp __tcp;
	PyObject *payload;
} tcp;

#define TCP_SRC			(void *)0
#define TCP_DST 		(void *)1
#define TCP_SEQ 		(void *)2
#define TCP_SEQ_ACK 	(void *)3
#define TCP_HLEN 		(void *)4
#define TCP_WIN 		(void *)5
#define TCP_CSUM 		(void *)6
#define TCP_URG_PTR 	(void *)7
#define TCP_PAYLOAD 	(void *)8

#define tcp_offset(x) (offsetof(tcp, __tcp) + \
					   offsetof(struct tcp, x))
#define tcp_payload_offset(x) (sizeof(struct ethernet) + \
							   sizeof(struct ip) + \
							   sizeof(struct tcp) + x)
int tcp_add_type(PyObject *module);
PyObject *create_tcp_instance(int caplen,
							  const unsigned char *pkt);
char *tcp_attr_string(void *closure);

#endif

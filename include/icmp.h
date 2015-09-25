
#ifndef INCLUDE_ICMP_H
#define INCLUDE_ICMP_H

#include "ip.h"

struct icmp {
	u8 type;
	u8 code;
	u16 csum;
	u16 identifier;
	u16 seq_num;
	u64 ts;
};

typedef struct {
	ip base_obj;
	struct icmp __icmp;
	union {
		PyObject *payload;
		struct {
			struct ip __ip;
			union {
				struct tcp __tcp;
				struct udp __udp;
			};
			PyObject *payload;
		} __packet;
	};
} icmp;

#define icmp_offset(x) (offsetof(icmp, __icmp) + \
						offsetof(struct icmp, x))
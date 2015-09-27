
#ifndef INCLUDE_PACKET_H
#define INCLUDE_PACKET_H

#include <Python.h>
#include <structmember.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "types.h"

#define PKT_IS_ETH_DESC		"Validates if a packet is of type " \
							"ethernet"
#define PKT_IS_ARP_DESC		"Validates if a packet is of type " \
							"arp"
#define PKT_IS_IP_DESC		"Validates if a packet is of type " \
							"ip"
#define PKT_IS_TCP_DESC		"Validates if a packet is of type " \
							"tcp"
#define PKT_IS_UDP_DESC		"Validates if a packet is of type " \
							"udp"

#define ETHERNET_CAST(x)	((ethernet *)x)
#define ARP_CAST(x)			((arp *)x)
#define IP_CAST(x)			((ip *)x)
#define UDP_CAST(x)			((udp *)x)
#define TCP_CAST(x)			((tcp *)x)

typedef struct {
	PyObject_HEAD
} packet;

#endif
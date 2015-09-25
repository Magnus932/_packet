
#include <Python.h>
#include <pcap/pcap.h>
#include <structmember.h>
#include "types.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

#define MIN_SNAPLEN				100

typedef struct {
	PyObject_HEAD
	pcap_t *handle;
	struct bpf_program fp;
	bpf_u_int32 netp, maskp;
	PyObject *callback;
} ppcap;
#define PROTO_ARP		0x0806
#define PROTO_IP		0x0800
#define PROTO_IPV6		0x86dd
#define PROTO_ICMP		0x0001
#define PROTO_TCP		0x0006
#define PROTO_UDP		0x0011

void ppcap_rcv_packet(u_char *user_data,
					  const struct pcap_pkthdr *hdr,
					  const u_char *packet);
static PyObject *ppcap_create(ppcap *self,
							  PyObject *args);
static PyObject *ppcap_activate(ppcap *self);
static PyObject *ppcap_open_live(ppcap *self,
								 PyObject *args);
static PyObject *ppcap_findalldevs(ppcap *self);
static PyObject *ppcap_lookupdev(ppcap *self);
static PyObject *ppcap_parse_pkt(struct pcap_pkthdr *pkthdr,
					      		 const u_char *packet);
static PyObject *ppcap_loop(ppcap *self, PyObject *args);
static PyObject *ppcap_next(ppcap *self);
static PyObject *ppcap_set_snaplen(ppcap *self,
								   PyObject *args);
static PyObject *ppcap_set_promisc(ppcap *self,
								   PyObject *args);
static PyObject *ppcap_set_timeout(ppcap *self,
								   PyObject *args);
static PyObject *ppcap_lookupnet(ppcap *self,
								 PyObject *args);
static PyObject *ppcap_compile(ppcap *self,
							   PyObject *args);
static PyObject *ppcap_setfilter(ppcap *self);
static PyObject *ppcap_close(ppcap *self);
int ppcap_isset_handle(pcap_t *handle)
{
	return (handle) ? 1 : 0;
}
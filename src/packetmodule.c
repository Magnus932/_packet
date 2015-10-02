
#include "include/packetmodule.h"

static PyModuleDef packet_module = {
	PyModuleDef_HEAD_INIT,
	"_packet", NULL,
	-1,
	NULL, NULL, NULL, NULL,
	NULL
};

PyObject *PyExc_Ppcap;

PyMODINIT_FUNC PyInit__packet(void)
{
	PyObject *module;

	module = PyModule_Create(&packet_module);
	if (!module)
		return NULL;
	if (!ppcap_add_type(module))
		return NULL;
	if (!packet_add_type(module))
		return NULL;
	if (!ethernet_add_type(module))
		return NULL;
	if (!arp_add_type(module))
		return NULL;
	if (!ip_add_type(module))
		return NULL;
	if (!tcp_add_type(module))
		return NULL;
	if (!udp_add_type(module))
		return NULL;
	/*
	 * Create the Ppcap exception.
	 */
	PyExc_Ppcap = PyErr_NewException("packet.PpcapException", NULL, NULL);
	
	return module;
}

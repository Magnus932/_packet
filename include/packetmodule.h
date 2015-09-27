
/*
 * File is only used as now, to get rid of the
 * -Wimplicit-function-declaration messages. Instead
 * of loading headers that are not really needed,
 * or shut it off.
 */
 
#ifndef INCLUDE_PACKETMODULE_H
#define INCLUDE_PACKETMODULE_H

#include <Python.h>

int ppcap_add_type(PyObject *module);
int packet_add_type(PyObject *module);
int ethernet_add_type(PyObject *module);
int arp_add_type(PyObject *module);
int ip_add_type(PyObject *module);
int tcp_add_type(PyObject *module);
int udp_add_type(PyObject *module);

#endif /* INCLUDE_PACKETMODULE_H */
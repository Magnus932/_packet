
#include "include/ppcap.h"

static PyMethodDef ppcap_methods[] = {
	{ "create", (PyCFunction)ppcap_create,
	   METH_VARARGS, NULL
	},
	{ "activate", (PyCFunction)ppcap_activate,
	   METH_NOARGS, NULL
	},
	{ "open_live", (PyCFunction)ppcap_open_live,
	   METH_VARARGS, NULL
	},
	{ "findalldevs", (PyCFunction)ppcap_findalldevs,
	   METH_NOARGS, NULL
	},
	{ "lookupdev", (PyCFunction)ppcap_lookupdev,
	   METH_NOARGS, NULL
	},
	{ "set_snaplen", (PyCFunction)ppcap_set_snaplen,
	   METH_VARARGS, NULL
	},
	{ "set_promisc", (PyCFunction)ppcap_set_promisc,
	   METH_VARARGS, NULL
	},
	{ "set_timeout", (PyCFunction)ppcap_set_timeout,
	   METH_VARARGS, NULL
	},
	{ "lookupnet", (PyCFunction)ppcap_lookupnet,
	   METH_VARARGS, NULL
	},
	{ "compile", (PyCFunction)ppcap_compile,
	   METH_VARARGS, NULL
	},
	{ "setfilter", (PyCFunction)ppcap_setfilter,
	   METH_NOARGS, NULL
	},
	{ "loop", (PyCFunction)ppcap_loop,
	   METH_VARARGS, NULL
	},
	{ "next", (PyCFunction)ppcap_next,
	   METH_NOARGS, NULL
	},
	{ "close", (PyCFunction)ppcap_close,
	   METH_NOARGS, NULL
	},
	{ NULL }
};

static PyTypeObject ppcap_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"ppcap.ppcap",             /* tp_name */
    sizeof(ppcap),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    0, 						   /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,   	   /* tp_flags */
    0,			               /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ppcap_methods,             /* tp_methods */
    0,			               /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      				   /* tp_init */
    0,                         /* tp_alloc */
    0,                 		   /* tp_new */
};

extern PyObject *PyExc_Ppcap;

void ppcap_rcv_packet(u_char *user_data,
					  const struct pcap_pkthdr *hdr,
					  const u_char *packet)
{
	PyObject *callback = (PyObject *)user_data;
	PyObject *obj;
	PyObject *retval;

	obj = ppcap_parse_pkt(hdr, packet);
	retval = PyObject_CallFunctionObjArgs(callback, obj, NULL);
	Py_DECREF(obj);
	Py_XDECREF(retval);
}

static PyObject *ppcap_create(ppcap *self,
							  PyObject *args)
{
	const char *device;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!PyArg_ParseTuple(args, "s", &device))
		return NULL;
	if (ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is already created");
		return NULL;
	}
	self->handle = pcap_create(device, errbuf);
	if (!self->handle) {
		PyErr_Format(PyExc_Ppcap, "%s", errbuf);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_activate(ppcap *self)
{
	int retval;

	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	retval = pcap_activate(self->handle);
	switch(retval) {
		case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
			fprintf(stderr, "timestamp not supported by the capture source\n");
		break;
		case PCAP_WARNING_PROMISC_NOTSUP:
		case PCAP_WARNING:
			fprintf(stderr, "%s\n", pcap_geterr(self->handle));
		break;
		case PCAP_ERROR_ACTIVATED:
			PyErr_SetString(PyExc_Ppcap, "handle has already been activated");
			return NULL;
		break;
		case PCAP_ERROR_PROMISC_PERM_DENIED:
			PyErr_SetString(PyExc_Ppcap, "process has not permission to put the"
							" capture device into promisc mode");
			return NULL;
		break;
		case PCAP_ERROR_RFMON_NOTSUP:
			PyErr_SetString(PyExc_Ppcap, "capture source does not support monitor mode");
			return NULL;
		break;
		case PCAP_ERROR_IFACE_NOT_UP:
			PyErr_SetString(PyExc_Ppcap, "capture source is not up");
			return NULL;
		break;
		case PCAP_ERROR_NO_SUCH_DEVICE:
		case PCAP_ERROR_PERM_DENIED:
		case PCAP_ERROR:
			PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
			return NULL;
		break;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_open_live(ppcap *self,
								 PyObject *args)
{
	const char *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	int snaplen;
	int promisc, ms;

	if (!PyArg_ParseTuple(args, "siii", &device, &snaplen,
						  &promisc, &ms))
		return NULL;
	if (ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is already created");
		return NULL;
	}
	if (snaplen < MIN_SNAPLEN) {
		PyErr_Format(PyExc_Ppcap, "snaplen must be >= %d",
					 MIN_SNAPLEN);
		return NULL;
	}
	self->handle = pcap_open_live(device, snaplen, promisc,
								  ms, errbuf);
	if (!self->handle) {
		PyErr_Format(PyExc_Ppcap, "%s", errbuf);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_findalldevs(ppcap *self)
{
	pcap_if_t *alldevsp, *ptr;
	char errbuf[PCAP_ERRBUF_SIZE], buf[1024];
	int num = 0;
	PyObject *list, *unicode;

	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		PyErr_Format(PyExc_Ppcap, "%s", errbuf);
		return NULL;
	}
	list = PyList_New(0);

	ptr = alldevsp;
	while (ptr) {
		snprintf(buf, 1023, "%d. device:%s (%s)\nstatus:", ++num,
				 ptr->name, (ptr->description) ? ptr->description :
				 "No description");
		if (ptr->flags & PCAP_IF_LOOPBACK)
			strncat(buf, "loopback, ", 10);
		if (ptr->flags & PCAP_IF_UP)
			strncat(buf, "up, ", 4);
		if (ptr->flags & PCAP_IF_RUNNING)
			strncat(buf, "running", 7);
		strncat(buf, "\n-------------------------------", 32);
		unicode = PyUnicode_FromStringAndSize(buf, strlen(buf));
		PyList_Append(list, unicode);

		ptr = ptr->next;
	}
	if (alldevsp)
		pcap_freealldevs(alldevsp);
	return list;
}

static PyObject *ppcap_lookupdev(ppcap *self)
{
	char *buf;
	char errbuf[PCAP_ERRBUF_SIZE];

	buf = pcap_lookupdev(errbuf);
	if (!buf) {
		PyErr_Format(PyExc_Ppcap, "%s", errbuf);
		return NULL;
	}
	return PyUnicode_FromStringAndSize(buf, strlen(buf));
}

static PyObject *ppcap_loop(ppcap *self, PyObject *args)
{
	PyObject *callback;
	int num_pkts;

	if (!PyArg_ParseTuple(args, "iO", &num_pkts, &callback))
		return NULL;
	if (!PyCallable_Check(callback)) {
		PyErr_SetString(PyExc_Ppcap, "Second argument is not a callable");
		return NULL;
	}
	Py_XDECREF(self->callback);
	Py_INCREF(callback);
	self->callback = callback;

	if (pcap_loop(self->handle, num_pkts, ppcap_rcv_packet,
				  (u_char *)self->callback) == -1) {
		PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_set_snaplen(ppcap *self,
								   PyObject *args)
{
	int snaplen;
	int retval;

	if (!PyArg_ParseTuple(args, "i", &snaplen))
		return NULL;
	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	if (snaplen < MIN_SNAPLEN) {
		PyErr_Format(PyExc_Ppcap, "snaplen must be >= %d",
					 MIN_SNAPLEN);
		return NULL;
	}
	retval = pcap_set_snaplen(self->handle, snaplen);
	if (retval == PCAP_ERROR_ACTIVATED) {
		PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_set_promisc(ppcap *self,
								   PyObject *args)
{
	int promisc;
	int retval;

	if (!PyArg_ParseTuple(args, "i", &promisc))
		return NULL;
	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	retval = pcap_set_promisc(self->handle, promisc);
	if (retval == PCAP_ERROR_ACTIVATED) {
		PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_set_timeout(ppcap *self,
								   PyObject *args)
{
	int to_ms;
	int retval;

	if (!PyArg_ParseTuple(args, "i", &to_ms))
		return NULL;
	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	retval = pcap_set_timeout(self->handle, to_ms);
	if (retval == PCAP_ERROR_ACTIVATED) {
		PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_lookupnet(ppcap *self,
								 PyObject *args)
{
	const char *device;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!PyArg_ParseTuple(args, "s", &device))
		return NULL;
	if (pcap_lookupnet(device, &self->netp, &self->maskp,
					   errbuf) == -1) {
		PyErr_Format(PyExc_Ppcap, "%s", errbuf);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_compile(ppcap *self,
							   PyObject *args)
{
	const char *filter;
	int optimize = 1;
	int retval;

	if (!PyArg_ParseTuple(args, "s|i", &filter, &optimize))
		return NULL;
	/*
	 * the ppcap object already contains the netmask which
	 * is required for compiling the filter. It also contains
	 * the bpf_program, which we will save the result in here.
	 */
	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	retval = pcap_compile(self->handle, &self->fp, filter,
						  optimize, self->maskp);
	if (retval == -1) {
		PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_setfilter(ppcap *self)
{
	int retval;

	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	retval = pcap_setfilter(self->handle, &self->fp);
	if (retval == -1) {
		PyErr_Format(PyExc_Ppcap, "%s", pcap_geterr(self->handle));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_parse_pkt(struct pcap_pkthdr *pkthdr,
					      		 const u_char *packet)
{
	PyObject *obj;
	struct ethernet *ether;
	struct ip *ips;
	u8 ip_version = 6;
	
	ether = (struct ethernet *)packet;
	switch(ntohs(ether->type)) {
		case PROTO_ARP:
			obj = create_arp_instance(pkthdr->caplen, packet);
		break;
		case PROTO_IPV6:
			obj = Py_None;
			Py_INCREF(obj);
		break;
		case PROTO_IP:
			ips = (struct ip *)(packet +
							    sizeof(struct ethernet));
			switch(ips->proto) {
				case PROTO_TCP:
					obj = create_tcp_instance(pkthdr->caplen, packet);
				break;
				case PROTO_UDP:
					obj = create_udp_instance(pkthdr->caplen, packet);
				break;
				default:
					obj = create_ip_instance(pkthdr->caplen, packet);
				break;
			}
		break;
		default:
			obj = create_ethernet_instance(pkthdr->caplen, packet);
		break;
	}
	return obj;
}

static PyObject *ppcap_next(ppcap *self)
{
	const u_char *packet;
	struct pcap_pkthdr pkthdr;
	PyObject *obj;

	if (!ppcap_isset_handle(self->handle)) {
		PyErr_SetString(PyExc_Ppcap, "pcap handle is not created");
		return NULL;
	}
	packet = pcap_next(self->handle, &pkthdr);
	if (packet) {
		obj = ppcap_parse_pkt(&pkthdr, packet);
		return obj;
	}
	Py_RETURN_NONE;
}

static PyObject *ppcap_close(ppcap *self)
{
	if (ppcap_isset_handle(self->handle))
		pcap_close(self->handle);

	Py_RETURN_NONE;
}

int ppcap_add_type(PyObject *module)
{
	ppcap_type.tp_new = PyType_GenericNew;
	if (PyType_Ready(&ppcap_type) < 0)
		return 0;
	Py_INCREF(&ppcap_type);
	PyModule_AddObject(module, "ppcap", (PyObject *)&ppcap_type);

	return 1;
}
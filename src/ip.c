
#include "include/ip.h"

static PyObject *ip_get_attr(ip *self,
							 void *closure);
static int ip_set_attr(ip *self, PyObject *value,
					   void *closure);
static PyObject *ip_get_source(ip *self,
							   void *closure);
static int ip_set_source(ip *self, PyObject *value,
				  		 void *closure);
static PyObject *ip_get_dest(ip *self,
					  		 void *closure);
static int ip_set_dest(ip *self, PyObject *value,
			    	   void *closure);
static PyObject *ip_calc_len(ip *self);
static PyObject *ip_calc_csum(ip *self);
static PyObject *ip_to_bytes(ip *self);

static PyMemberDef ip_members[] = {
	{ "ip_dsf", T_UBYTE, ip_offset(dsf),
	  0, NULL
	},
	{ "ip_ttl", T_UBYTE, ip_offset(ttl),
	  0, NULL
	},
	{ "ip_proto", T_UBYTE, ip_offset(proto),
	  0, NULL
	},
	{ NULL }
};

static PyMethodDef ip_methods[] = {
	{ "calc_len", (PyCFunction)ip_calc_len,
	   METH_NOARGS, NULL
	},
	{ "calc_csum", (PyCFunction)ip_calc_csum,
	   METH_NOARGS, NULL
	},
	{ "to_bytes", (PyCFunction)ip_to_bytes,
	   METH_NOARGS, NULL
	},
	{ NULL }
};

static PyGetSetDef ip_gs[] = {
	{ "ip_hlen", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, IP_HLEN
	},
	{ "ip_version", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, IP_VERSION
	},
	{ "ip_len", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, IP_LEN
	},
	{ "ip_identifier", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, IP_IDENTIFIER
	},
	{ "ip_frag_off", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, IP_FRAG_OFF
	},
	{ "ip_csum", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, IP_CSUM
	},
	{ "ip_source", (getter)ip_get_source,
	  (setter)ip_set_source, NULL, NULL
	},
	{ "ip_dest", (getter)ip_get_dest,
	  (setter)ip_set_dest, NULL, NULL
	},
	{ NULL }
};

PyTypeObject ip_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"packet.ip", 		       /* tp_name */
    sizeof(ip),		           /* tp_basicsize */
    0,                         /* tp_itemsize */
    0, 						   /* tp_dealloc */
    0,                         /* tp_print */
    0,				           /* tp_getclosure */
    0, 				           /* tp_setclosure */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getclosureo */
    0,                         /* tp_setclosureo */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
    Py_TPFLAGS_BASETYPE,  	   /* tp_flags */
    0,			               /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ip_methods,			       /* tp_methods */
    ip_members,				   /* tp_members */
    ip_gs,                     /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      				   /* tp_init */
    0,                         /* tp_alloc */
    0,                 		   /* tp_new */
};

extern PyTypeObject ethernet_type;

static PyObject *ip_get_attr(ip *self,
							 void *closure)
{
	if (closure == IP_HLEN)
		return PyLong_FromLong(self->__ip.hlen);
	if (closure == IP_VERSION)
		return PyLong_FromLong(self->__ip.version);
	if (closure == IP_LEN)
		return PyLong_FromLong(ntohs(self->__ip.len));
	if (closure == IP_IDENTIFIER)
		return PyLong_FromLong(ntohs(self->__ip.identifier));
	if (closure == IP_FRAG_OFF)
		return PyLong_FromLong(ntohs(self->__ip.frag_off));
	if (closure == IP_CSUM)
		return PyLong_FromLong(ntohs(self->__ip.csum));

	Py_RETURN_NONE;
}

static int ip_set_attr(ip *self, PyObject *value,
					   void *closure)
{
	if (!value) {
		PyErr_Format(PyExc_AttributeError, "attribute '%s' can not"
					 " be deleted", ip_attr_string(closure));
		return -1;
	}
	if (!PyLong_Check(value)) {
		PyErr_Format(PyExc_TypeError, "attribute '%s' expects"
					 " type 'int'", ip_attr_string(closure));
		return -1;
	}
	if (closure == IP_HLEN)
		self->__ip.hlen = PyLong_AsLong(value);
	else if (closure == IP_VERSION)
		self->__ip.version = PyLong_AsLong(value);
	else if (closure == IP_LEN)
		self->__ip.len = htons(PyLong_AsLong(value));
	else if (closure == IP_IDENTIFIER)
		self->__ip.identifier = htons(PyLong_AsLong(value));
	else if (closure == IP_FRAG_OFF)
		self->__ip.frag_off = htons(PyLong_AsLong(value));
	else if (closure == IP_CSUM)
		self->__ip.csum = htons(PyLong_AsLong(value));

	return 0;
}

static PyObject *ip_get_source(ip *self,
							   void *closure)
{
	char *buf;
	struct in_addr in;

	memcpy(&in, &self->__ip.source, sizeof(int));
	buf = inet_ntoa(in);

	return PyUnicode_FromStringAndSize(buf, strlen(buf));
}

static int ip_set_source(ip *self, PyObject *value,
						 void *closure)
{
	PyObject *obj;
	in_addr_t ip;

	if (!value) {
		PyErr_SetString(PyExc_AttributeError, "attribute 'ip_source'"
						" can not be deleted");
		return -1;
	}
	if (!PyUnicode_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "attribute 'ip_source' expects"
						" type 'string'");
		return -1;
	}
	obj = PyUnicode_AsASCIIString(value);
	if (!obj)
		return -1;
	ip = inet_addr(PyBytes_AsString(obj));
	if (ip == -1) {
		PyErr_Format(PyExc_Exception, "%s", strerror(errno));
		Py_DECREF(obj);
		return -1;
	}
	self->__ip.source = ip;
	Py_DECREF(obj);

	return 0;
}

static PyObject *ip_get_dest(ip *self,
							 void *closure)
{
	char *buf;
	struct in_addr in;

	memcpy(&in, &self->__ip.dest, sizeof(int));
	buf = inet_ntoa(in);

	return PyUnicode_FromStringAndSize(buf, strlen(buf));
}

static int ip_set_dest(ip *self, PyObject *value,
					   void *closure)
{
	PyObject *obj;
	in_addr_t ip;

	if (!value) {
		PyErr_SetString(PyExc_AttributeError, "closureibute 'ip_dest'"
						" can not be deleted");
		return -1;
	}
	if (!PyUnicode_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "closureibute 'ip_dest' expects "
						"type 'string'");
		return -1;
	}
	obj = PyUnicode_AsASCIIString(value);
	if (!obj)
		return -1;
	ip = inet_addr(PyBytes_AsString(obj));
	if (ip == -1) {
		PyErr_Format(PyExc_Exception, "%s", strerror(errno));
		Py_DECREF(obj);
		return -1;
	}
	self->__ip.dest = ip;
	Py_DECREF(obj);

	return 0;
}

int ip_add_type(PyObject *module)
{
	ip_type.tp_base = &ethernet_type;
	if (PyType_Ready(&ip_type) < 0)
		return 0;
	Py_INCREF(&ip_type);
	PyModule_AddObject(module, "ip", (PyObject *)&ip_type);

	return 1;
}

PyObject *create_ip_instance(int caplen,
							 const unsigned char *pkt)
{
	PyObject *obj;

	obj = ip_type.tp_new(&ip_type, NULL, NULL);
	memcpy(&ETHERNET_CAST(obj)->__ethernet, pkt,
		   sizeof(struct ethernet));
	memcpy(&IP_CAST(obj)->__ip,
		   (pkt + sizeof(struct ethernet)),
		    sizeof(struct ip));
	return obj;
}

static PyObject *ip_to_bytes(ip *self)
{
	PyObject *obj;
	int size;
	char *buf;

	size = sizeof(struct ethernet) + sizeof(struct ip);
	buf = (char *)malloc(size);

	memcpy(buf, &ETHERNET_CAST(self)->__ethernet,
		   sizeof(struct ethernet));
	memcpy(buf + sizeof(struct ethernet),
		   &self->__ip,
		   sizeof(struct ip));
	obj = PyBytes_FromStringAndSize(buf, size);
	free(buf);

	return obj;
}

char *ip_attr_string(void *closure)
{
	if (closure == IP_HLEN)
		return "ip_hlen";
	if (closure == IP_VERSION)
		return "ip_version";
	if (closure == IP_LEN)
		return "ip_len";
	if (closure == IP_IDENTIFIER)
		return "ip_identifier";
	if (closure == IP_FRAG_OFF)
		return "ip_frag_off";
	if (closure == IP_CSUM)
		return "ip_csum";

	return NULL;
}

void __ip_calc_len(ip *self, Py_ssize_t _len)
{
	Py_ssize_t len = 20;

	if (_len)
		len += _len;
	self->__ip.len = htons(len);
}

static PyObject *ip_calc_len(ip *self)
{
	__ip_calc_len(self, 0);

	Py_RETURN_NONE;
}

void __ip_calc_csum(struct ip *ips)
{
	int i, sum = 0;

	ips->csum = 0;
	for (i = 0; i < sizeof(struct ip) / 2; i++)
		sum += ((unsigned short *)ips)[i];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	ips->csum = (unsigned short)~sum; 
}

static PyObject *ip_calc_csum(ip *self)
{
	__ip_calc_csum(&self->__ip);

	Py_RETURN_NONE;
}


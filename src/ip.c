
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

static PyGetSetDef ip_gs[] = {
	{ "ip_hlen", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, "ip_hlen"
	},
	{ "ip_version", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, "ip_version"
	},
	{ "ip_len", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, "ip_len"
	},
	{ "ip_identifier", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, "ip_identifier"
	},
	{ "ip_frag_off", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, "ip_frag_off"
	},
	{ "ip_csum", (getter)ip_get_attr,
	  (setter)ip_set_attr, NULL, "ip_csum"
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
	"ppcap.ip", 		       /* tp_name */
    sizeof(ip),		           /* tp_basicsize */
    0,                         /* tp_itemsize */
    0, 						   /* tp_dealloc */
    0,                         /* tp_print */
    0,				           /* tp_getattr */
    0, 				           /* tp_setattr */
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
    Py_TPFLAGS_DEFAULT |
    Py_TPFLAGS_BASETYPE,  	   /* tp_flags */
    0,			               /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    0,			               /* tp_methods */
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
	if (!strncmp(closure, "ip_hlen", strlen(closure)))
		return PyLong_FromLong(self->__ip.hlen);
	if (!strncmp(closure, "ip_version", strlen(closure)))
		return PyLong_FromLong(self->__ip.version);
	if (!strncmp(closure, "ip_len", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__ip.len));
	if (!strncmp(closure, "ip_identifier", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__ip.identifier));
	if (!strncmp(closure, "ip_frag_off", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__ip.frag_off));
	if (!strncmp(closure, "ip_csum", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__ip.csum));

	Py_RETURN_NONE;
}

static int ip_set_attr(ip *self, PyObject *value,
					   void *closure)
{
	if (!value) {
		PyErr_Format(PyExc_AttributeError, "attribute '%s' can not"
					 " be deleted", (char *)closure);
		return -1;
	}
	if (!PyLong_Check(value)) {
		PyErr_Format(PyExc_TypeError, "attribute '%s' expects"
					 " type 'int'", (char *)closure);
		return -1;
	}
	if (!strncmp(closure, "ip_hlen", strlen(closure)))
		self->__ip.hlen = PyLong_AsLong(value);
	else if (!strncmp(closure, "ip_version", strlen(closure)))
		self->__ip.version = PyLong_AsLong(value);
	else if (!strncmp(closure, "ip_len", strlen(closure)))
		self->__ip.len = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "ip_identifier", strlen(closure)))
		self->__ip.identifier = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "ip_frag_off", strlen(closure)))
		self->__ip.frag_off = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "ip_csum", strlen(closure)))
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
		PyErr_SetString(PyExc_AttributeError, "attribute 'ip_dest'"
						" can not be deleted");
		return -1;
	}
	if (!PyUnicode_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "attribute 'ip_dest' expects "
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
	memcpy(&((ethernet *)obj)->__ethernet, pkt,
		   sizeof(struct ethernet));
	memcpy(&((ip *)obj)->__ip,
		   (pkt + sizeof(struct ethernet)),
		    sizeof(struct ip));
	return obj;
}
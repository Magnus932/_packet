
#include "include/tcp.h"

static PyObject *tcp_get_attr(tcp *self,
							  void *closure);
static int tcp_set_attr(tcp *self, PyObject *value,
						void *closure);
static int tcp_set_payload(tcp *self, PyObject *value,
						   void *closure);
static PyObject *tcp_get_flags(tcp *self);
static PyObject *tcp_set_flags(tcp *self, PyObject *args,
							   PyObject *kwds);
static void tcp_dealloc(tcp *self);

static PyMethodDef tcp_methods[] = {
	{ "tcp_get_flags", (PyCFunction)tcp_get_flags,
	   METH_NOARGS, NULL
	},
	{ "tcp_set_flags", (PyCFunction)tcp_set_flags,
	   METH_VARARGS | METH_KEYWORDS, NULL
	},
	{ NULL }
};

static PyGetSetDef tcp_gs[] = {
	{ "tcp_src", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_src"
	},
	{ "tcp_dst", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_dst"
	},
	{ "tcp_seq", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_seq"
	},
	{ "tcp_seq_ack", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_seq_ack"
	},
	{ "tcp_hlen", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_hlen"
	},
	{ "tcp_win", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_win"
	},
	{ "tcp_csum", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_csum"
	},
	{ "tcp_urg_ptr", (getter)tcp_get_attr,
	  (setter)tcp_set_attr, NULL, "tcp_urg_ptr"
	},
	{ "tcp_payload", (getter)tcp_get_attr,
	  (setter)tcp_set_payload, NULL, "tcp_payload"
	},
	{ NULL }
};

PyTypeObject tcp_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"ppcap.tcp",               /* tp_name */
    sizeof(tcp),               /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)tcp_dealloc,   /* tp_dealloc */
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
    Py_TPFLAGS_DEFAULT |
    Py_TPFLAGS_BASETYPE,  	   /* tp_flags */
    0,			               /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    tcp_methods,  			   /* tp_methods */
    0,                    	   /* tp_members */
    tcp_gs,  	               /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      				   /* tp_init */
    0,                         /* tp_alloc */
    0,                 		   /* tp_new */
};

extern PyTypeObject ip_type;

static PyObject *tcp_get_attr(tcp *self,
							  void *closure)
{
	if (!strncmp(closure, "tcp_src", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__tcp.src));
	if (!strncmp(closure, "tcp_dst", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__tcp.dst));
	if (!strncmp(closure, "tcp_seq", strlen(closure)))
		return PyLong_FromLong(ntohl(self->__tcp.seq));
	if (!strncmp(closure, "tcp_seq_ack", strlen(closure)))
		return PyLong_FromLong(ntohl(self->__tcp.seq_ack));
	if (!strncmp(closure, "tcp_hlen", strlen(closure)))
		return PyLong_FromLong(self->__tcp.hlen << 2);
	if (!strncmp(closure, "tcp_win", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__tcp.win_size));
	if (!strncmp(closure, "tcp_csum", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__tcp.csum));
	if (!strncmp(closure, "tcp_urg_ptr", strlen(closure)))
		return PyLong_FromLong(ntohs(self->__tcp.urg_ptr));
	if (!strncmp(closure, "tcp_payload", strlen(closure)))
		if (self->payload) {
			Py_INCREF(self->payload);
			return self->payload;
		}

	Py_RETURN_NONE;
}

static int tcp_set_attr(tcp *self, PyObject *value,
						void *closure)
{
	if (!value) {
		PyErr_Format(PyExc_AttributeError, "attribute '%s' can not be"
					 " deleted", (char *)closure);
		return -1;
	}
	if (!PyLong_Check(value)) {
		PyErr_Format(PyExc_TypeError, "attribute '%s' only accepts"
					 " a type of 'int'");
		return -1;
	}
	if (!strncmp(closure, "tcp_src", strlen(closure)))
		self->__tcp.src = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "tcp_dst", strlen(closure)))
		self->__tcp.dst = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "tcp_seq", strlen(closure)))
		self->__tcp.seq = htonl(PyLong_AsLong(value));
	else if (!strncmp(closure, "tcp_seq_ack", strlen(closure)))
		self->__tcp.seq_ack = htonl(PyLong_AsLong(value));
	else if (!strncmp(closure, "tcp_hlen", strlen(closure)))
		self->__tcp.hlen = PyLong_AsLong(value);
	else if (!strncmp(closure, "tcp_win", strlen(closure)))
		self->__tcp.win_size = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "tcp_csum", strlen(closure)))
		self->__tcp.csum = htons(PyLong_AsLong(value));
	else if (!strncmp(closure, "tcp_urg_ptr", strlen(closure)))
		self->__tcp.urg_ptr = htons(PyLong_AsLong(value));

	return 0;
}

static int tcp_set_payload(tcp *self, PyObject *value,
						   void *closure)
{
	if (!value) {
		PyErr_SetString(PyExc_AttributeError, "attribute 'tcp_payload'"
						" can not be deleted");
		return -1;
	}
	if (!PyBytes_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "attribute 'tcp_payload' only"
						" accepts a type of 'bytes'");
		return -1;
	}
	Py_XDECREF(self->payload);
	Py_INCREF(value);
	self->payload = value;
	
	return 0;
}

static PyObject *tcp_get_flags(tcp *self)
{
	PyObject *obj, *flag;

	obj = PyDict_New();
	if (!obj)
		return NULL;
	flag = PyLong_FromLong(self->__tcp.nonce);
	if (PyDict_SetItemString(obj, "nonce", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.cwr);
	if (PyDict_SetItemString(obj, "cwr", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.echo);
	if (PyDict_SetItemString(obj, "echo", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.urg);
	if (PyDict_SetItemString(obj, "urg", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.ack);
	if (PyDict_SetItemString(obj, "ack", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.push);
	if (PyDict_SetItemString(obj, "push", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.rst);
	if (PyDict_SetItemString(obj, "rst", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.syn);
	if (PyDict_SetItemString(obj, "syn", flag) == -1)
		goto err;

	flag = PyLong_FromLong(self->__tcp.fin);
	if (PyDict_SetItemString(obj, "fin", flag) == -1)
		goto err;

	return obj;
err:
	Py_DECREF(obj);
	return NULL;
}

static PyObject *tcp_set_flags(tcp *self, PyObject *args,
							   PyObject *kwds)
{
	u8 nonce = 0, cwr = 0, echo = 0, urg = 0;
	u8 ack = 0, push = 0, rst = 0, syn = 0, fin = 0;
	static char *kw[] = { "nonce", "cwr", "echo", "urg",
						  "ack", "push", "rst", "syn", "fin" };

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|BBBBBBBBB", kw,
									 &nonce, &cwr, &echo, &urg,
									 &ack, &push, &rst, &syn, &fin))
		return NULL;
	self->__tcp.nonce = nonce;
	self->__tcp.cwr = cwr;
	self->__tcp.echo = echo;
	self->__tcp.urg = urg;
	self->__tcp.ack = ack;
	self->__tcp.push = push;
	self->__tcp.rst = rst;
	self->__tcp.syn = syn;
	self->__tcp.fin = fin;

	Py_RETURN_NONE;
}

static void tcp_dealloc(tcp *self)
{
	Py_XDECREF(self->payload);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

int tcp_add_type(PyObject *module)
{
	tcp_type.tp_base = &ip_type;
	if (PyType_Ready(&tcp_type) < 0)
		return 0;
	Py_INCREF(&tcp_type);
	PyModule_AddObject(module, "tcp", (PyObject *)&tcp_type);

	return 1;
}

PyObject *create_tcp_instance(int caplen,
							  const unsigned char *pkt)
{
	PyObject *obj;
	const char *payload;
	int offset;

	obj = tcp_type.tp_new(&tcp_type, NULL, NULL);
	memcpy(&((ethernet *)obj)->__ethernet, pkt,
		   sizeof(struct ethernet));
	memcpy(&((ip *)obj)->__ip,
		   (pkt + sizeof(struct ethernet)),
		    sizeof(struct ip));
	memcpy(&((tcp *)obj)->__tcp,
		   (pkt + sizeof(struct ethernet) + sizeof(struct ip)),
		    sizeof(struct tcp));
	offset = (((tcp *)obj)->__tcp.hlen << 2) - sizeof(struct tcp);
	payload = (pkt + tcp_payload_offset(offset));
	((tcp *)obj)->payload = PyBytes_FromStringAndSize(payload,
													  caplen - tcp_payload_offset(offset));
	if (!((tcp *)obj)->payload) {
		Py_DECREF(obj);
		return NULL;
	}
	return obj;
}
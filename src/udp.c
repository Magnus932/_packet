
#include "include/udp.h"

static PyObject *udp_get_attr(udp *self,
                              void *closure);
static int udp_set_attr(udp *self, PyObject *value,
                        void *closure);
static int udp_set_payload(udp *self, PyObject *value,
                           void *closure);
static void udp_dealloc(udp *self);

static PyGetSetDef udp_gs[] = {
    { "udp_src", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, "udp_src"
    },
    { "udp_dst", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, "udp_dst"
    },
    { "udp_len", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, "udp_len"
    },
    { "udp_csum", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, "udp_csum"
    },
    { "udp_payload", (getter)udp_get_attr,
      (setter)udp_set_payload, NULL, "udp_payload"
    },
    { NULL }
};

PyTypeObject udp_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"ppcap.udp",               /* tp_name */
    sizeof(udp),               /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)udp_dealloc,   /* tp_dealloc */
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
    0,  			           /* tp_methods */
    0,                    	   /* tp_members */
    udp_gs,                    /* tp_getset */
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

static PyObject *udp_get_attr(udp *self,
                              void *closure)
{
    if (!strncmp(closure, "udp_src", strlen(closure)))
        return PyLong_FromLong(ntohs(self->__udp.src));
    if (!strncmp(closure, "udp_dst", strlen(closure)))
        return PyLong_FromLong(ntohs(self->__udp.dst));
    if (!strncmp(closure, "udp_len", strlen(closure)))
        return PyLong_FromLong(ntohs(self->__udp.len));
    if (!strncmp(closure, "udp_csum", strlen(closure)))
        return PyLong_FromLong(ntohs(self->__udp.csum));
    if (!strncmp(closure, "udp_payload", strlen(closure)))
        if (self->payload) {
            Py_INCREF(self->payload);
            return self->payload;
        }
    /*
     * Return Py_RETURN_NONE to shut up the
     * compiler. This will never run.
     */
    Py_RETURN_NONE;
}

static int udp_set_attr(udp *self, PyObject *value,
                        void *closure)
{
    if (!value) {
        PyErr_Format(PyExc_AttributeError, "attribute '%s' can not"
                     " be deleted", (char *)closure);
        return -1;
    }
    if (!PyLong_Check(value)) {
        PyErr_Format(PyExc_TypeError, "attribute '%s' only accepts"
                     " a type of 'int'", (char *)closure);
        return -1;
    }
    if (!strncmp(closure, "udp_src", strlen(closure)))
        self->__udp.src = htons(PyLong_AsLong(value));
    else if (!strncmp(closure, "udp_dst", strlen(closure)))
        self->__udp.dst = htons(PyLong_AsLong(value));
    else if (!strncmp(closure, "udp_len", strlen(closure)))
        self->__udp.len = htons(PyLong_AsLong(value));
    else if (!strncmp(closure, "udp_csum", strlen(closure)))
        self->__udp.csum = htons(PyLong_AsLong(value));
    
    return 0;
}

static int udp_set_payload(udp *self, PyObject *value,
                           void *closure)
{
    if (!value) {
        PyErr_SetString(PyExc_AttributeError, "attribute udp_payload"
                        " can not be deleted");
        return -1;
    }
    if (!PyBytes_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "attribute udp_payload only"
                        " accepts a type of 'bytes'");
        return -1;
    }
    Py_XDECREF(self->payload);
    self->payload = value;

    return 0;
}

static void udp_dealloc(udp *self)
{
    Py_XDECREF(self->payload);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

int udp_add_type(PyObject *module)
{
	udp_type.tp_base = &ip_type;
	if (PyType_Ready(&udp_type) < 0)
		return 0;
	Py_INCREF(&udp_type);
	PyModule_AddObject(module, "udp", (PyObject *)&udp_type);

	return 1;
}

PyObject *create_udp_instance(int caplen,
                              const unsigned char *pkt)
{
    PyObject *obj;
    const unsigned char *payload;

    obj = udp_type.tp_new(&udp_type, NULL, NULL);
    memcpy(&((ethernet *)obj)->__ethernet, pkt,
           sizeof(struct ethernet));
    memcpy(&((ip *)obj)->__ip,
           (pkt + sizeof(struct ethernet)),
            sizeof(struct ip));
    memcpy(&((udp *)obj)->__udp,
           (pkt + sizeof(struct ethernet) + sizeof(struct ip)),
            sizeof(struct udp));  
    payload = (pkt + udp_payload_offset);
    ((udp *)obj)->payload = PyBytes_FromStringAndSize(payload,
                                                      caplen - udp_payload_offset);
    return obj;
}
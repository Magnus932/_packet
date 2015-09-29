
#include "include/udp.h"

static PyObject *udp_get_attr(udp *self,
                              void *closure);
static int udp_set_attr(udp *self, PyObject *value,
                        void *closure);
static int udp_set_payload(udp *self, PyObject *value,
                           void *closure);
static PyObject *udp_calc_len(udp *self);
static PyObject *udp_calc_csum(udp *self);
static PyObject *udp_to_bytes(udp *self);
static void udp_dealloc(udp *self);

static PyMethodDef udp_methods[] = {
    { "calc_len", (PyCFunction)udp_calc_len,
       METH_NOARGS, NULL
    },
    { "calc_csum", (PyCFunction)udp_calc_csum,
       METH_NOARGS, NULL
    },
    { "to_bytes", (PyCFunction)udp_to_bytes,
       METH_NOARGS, NULL
    },
    { NULL }
};

static PyGetSetDef udp_gs[] = {
    { "udp_src", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, UDP_SRC
    },
    { "udp_dst", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, UDP_DST
    },
    { "udp_len", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, UDP_LEN
    },
    { "udp_csum", (getter)udp_get_attr,
      (setter)udp_set_attr, NULL, UDP_CSUM
    },
    { "udp_payload", (getter)udp_get_attr,
      (setter)udp_set_payload, NULL, UDP_PAYLOAD
    },
    { NULL }
};

PyTypeObject udp_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"packet.udp",              /* tp_name */
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
    udp_methods,  			   /* tp_methods */
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
    if (closure == UDP_SRC)
        return PyLong_FromLong(ntohs(self->__udp.src));
    if (closure == UDP_DST)
        return PyLong_FromLong(ntohs(self->__udp.dst));
    if (closure == UDP_LEN)
        return PyLong_FromLong(ntohs(self->__udp.len));
    if (closure == UDP_CSUM)
        return PyLong_FromLong(ntohs(self->__udp.csum));
    if (closure == UDP_PAYLOAD)
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
                     " be deleted", udp_attr_string(closure));
        return -1;
    }
    if (!PyLong_Check(value)) {
        PyErr_Format(PyExc_TypeError, "attribute '%s' only accepts"
                     " a type of 'int'", udp_attr_string(closure));
        return -1;
    }
    if (closure == UDP_SRC)
        self->__udp.src = htons(PyLong_AsLong(value));
    else if (closure == UDP_DST)
        self->__udp.dst = htons(PyLong_AsLong(value));
    else if (closure == UDP_LEN)
        self->__udp.len = htons(PyLong_AsLong(value));
    else if (closure == UDP_CSUM)
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
    memcpy(&ETHERNET_CAST(obj)->__ethernet, pkt,
           sizeof(struct ethernet));
    memcpy(&IP_CAST(obj)->__ip,
           (pkt + sizeof(struct ethernet)),
            sizeof(struct ip));
    memcpy(&UDP_CAST(obj)->__udp,
           (pkt + sizeof(struct ethernet) + sizeof(struct ip)),
            sizeof(struct udp));  
    payload = (pkt + udp_payload_offset);
    ((udp *)obj)->payload = PyBytes_FromStringAndSize(payload,
                                                      caplen - udp_payload_offset);
    return obj;
}

static PyObject *udp_to_bytes(udp *self)
{
    PyObject *obj;
    Py_ssize_t size, psize;
    char *buf, *pbuf;

    size = sizeof(struct ethernet) + sizeof(struct ip) +
           sizeof(struct udp);
    if (self->payload)
        size += PyBytes_Size(self->payload);
    buf = (char *)malloc(size);

    memcpy(buf, &ETHERNET_CAST(self)->__ethernet,
           sizeof(struct ethernet));
    memcpy((buf + sizeof(struct ethernet)),
           &IP_CAST(self)->__ip,
           sizeof(struct ip));
    memcpy((buf + sizeof(struct ethernet) +
            sizeof(struct ip)),
            &self->__udp,
            sizeof(struct udp));
    if (self->payload) {
        if (PyBytes_AsStringAndSize(self->payload,
                                    &pbuf, &psize) == -1) {
            free(buf);
            return NULL;
        }
        memcpy((buf + sizeof(struct ethernet) +
               sizeof(struct ip) +
               sizeof(struct udp)),
               pbuf, psize);
    }
    obj = PyBytes_FromStringAndSize(buf, size);
    free(buf);
    return obj;
}

char *udp_attr_string(void *closure)
{
    if (closure == UDP_SRC)
        return "udp_src";
    if (closure == UDP_DST)
        return "udp_dst";
    if (closure == UDP_LEN)
        return "udp_len";
    if (closure == UDP_CSUM)
        return "udp_csum";
    return NULL;
}

static PyObject *udp_calc_len(udp *self)
{
    Py_ssize_t len = 8;

    if (self->payload)
        len += PyBytes_Size(self->payload);
    self->__udp.len = htons(len);

    __ip_calc_len(IP_CAST(self), len);

    Py_RETURN_NONE;
}

/*
 * High order bits are checked at the end
 * of the subroutine. I felt like its faster this
 * way instead of checking for a high bit while
 * iterating. As long as the packet is <= MTU
 * 32 bits should be enough to hold the calculations
 * until the end. If above, the checksum calculation
 * will overflow 'sum' in the long run. If you plan on
 * sending >= MTU on the lo interface, you should probably
 * add a: if (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
 * line in the data section, or check for 0x80000000 using the AND
 * operator ( Less usage of the CPU ).
 */
u16 __udp_calc_csum(struct udp_pseudo *__pse, char *data,
                    Py_ssize_t len)
{
    int i, sum = 0;

    for (i = 0; i < sizeof(struct udp_pseudo) / 2; i++)
        sum += ((unsigned short *)__pse)[i];
    if (data)
        for (i = 0; i < len / 2; i++)
            sum += ((unsigned short *)data)[i];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (u16)~sum;
}

static PyObject *udp_calc_csum(udp *self)
{
    struct udp_pseudo __pse;
    Py_ssize_t len;
    char *data = NULL;

    __pse.source = IP_CAST(self)->__ip.source;
    __pse.dest = IP_CAST(self)->__ip.dest;
    __pse.zero = 0;
    __pse.proto = IP_CAST(self)->__ip.proto;
    __pse.len = self->__udp.len;
    memcpy(&__pse.udp_hdr, &self->__udp,
           sizeof(struct udp));

    if (self->payload)
        PyBytes_AsStringAndSize(self->payload, &data, &len);
    self->__udp.csum = __udp_calc_csum(&__pse, data, (len % 2) ?
                                       len + 1 : len);
    __ip_calc_csum(&IP_CAST(self)->__ip);

    Py_RETURN_NONE;
}
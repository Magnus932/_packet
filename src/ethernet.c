
#include "include/ethernet.h"

static PyObject *ethernet_get_dst(ethernet *self,
                                  void *closure);
static int ethernet_set_dst(ethernet *self,
                            PyObject *value,
                            void *closure);
static PyObject *ethernet_get_src(ethernet *self,
                                  void *closure);
static int ethernet_set_src(ethernet *self,
                            PyObject *value,
                            void *closure);
static PyObject *ethernet_get_type(ethernet *self,
                                   void *closure);
static int ethernet_set_type(ethernet *self,
                             PyObject *value,
                             void *closure);

static PyGetSetDef ethernet_gs[] = {
    { "ethernet_dst", (getter)ethernet_get_dst,
      (setter)ethernet_set_dst, ETHERNET_DST_DESC,
       NULL
    },
    { "ethernet_src", (getter)ethernet_get_src,
      (setter)ethernet_set_src, ETHERNET_SRC_DESC,
       NULL
    },
    { "ethernet_type", (getter)ethernet_get_type,
      (setter)ethernet_set_type, ETHERNET_TYP_DESC,
       NULL
    },
    { NULL }
};

PyTypeObject ethernet_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
	  "ppcap.ethernet",          /* tp_name */
    sizeof(ethernet),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    0, 						             /* tp_dealloc */
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
    0,			                   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    0,			                   /* tp_methods */
    0,                         /* tp_members */
    ethernet_gs,               /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      				           /* tp_init */
    0,                         /* tp_alloc */
    0,                 		     /* tp_new */
};

extern PyTypeObject packet_type;

static PyObject *ethernet_get_dst(ethernet *self,
                                  void *closure)
{
    char buf[1024];

    snprintf(buf, 1023, "%x:%x:%x:%x:%x:%x",
             self->__ethernet.dst[0],
             self->__ethernet.dst[1],
             self->__ethernet.dst[2],
             self->__ethernet.dst[3],
             self->__ethernet.dst[4],
             self->__ethernet.dst[5]);
    return PyUnicode_FromStringAndSize(buf, strlen(buf));
}

static int ethernet_set_dst(ethernet *self,
                            PyObject *value,
                            void *closure)
{
    u8 a, b, c, d, e, f;

    if (!value) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'ethernet_dst' can"
                        " not be deleted");
        return -1;
    }
    if (!PyTuple_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "attribute 'ethernet_dst' expects"
                        " type 'tuple'");
        return -1;
    }
    if (!PyArg_ParseTuple(value, "BBBBBB", &a, &b, &c, &d,
                          &e, &f))
        return -1;
    self->__ethernet.dst[0] = a;
    self->__ethernet.dst[1] = b;
    self->__ethernet.dst[2] = c;
    self->__ethernet.dst[3] = d;
    self->__ethernet.dst[4] = e;
    self->__ethernet.dst[5] = f;

    return 0;
}

static PyObject *ethernet_get_src(ethernet *self,
                                  void *closure)
{
    char buf[1024];

    snprintf(buf, 1023, "%x:%x:%x:%x:%x:%x",
             self->__ethernet.src[0],
             self->__ethernet.src[1],
             self->__ethernet.src[2],
             self->__ethernet.src[3],
             self->__ethernet.src[4],
             self->__ethernet.src[5]);
    return PyUnicode_FromStringAndSize(buf, strlen(buf));
}

static int ethernet_set_src(ethernet *self,
                            PyObject *value,
                            void *closure)
{
    u8 a, b, c, d, e, f;

    if (!value) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'ethernet_src' can"
                        " not be deleted");
        return -1;
    }
    if (!PyTuple_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "attribute 'ethernet_src' expects"
                        " type 'tuple'");
        return -1;
    }
    if (!PyArg_ParseTuple(value, "BBBBBB", &a, &b, &c, &d,
                          &e, &f))
        return -1;
    self->__ethernet.src[0] = a;
    self->__ethernet.src[1] = b;
    self->__ethernet.src[2] = c;
    self->__ethernet.src[3] = d;
    self->__ethernet.src[4] = e;
    self->__ethernet.src[5] = f;

    return 0;
}

static PyObject *ethernet_get_type(ethernet *self,
                                   void *closure)
{
    return PyLong_FromLong(ntohs(self->__ethernet.type));
}

static int ethernet_set_type(ethernet *self,
                             PyObject *value,
                             void *closure)
{
    if (!value) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'ethernet_type'"
                        " can not be deleted");
        return -1;
    }
    if (!PyLong_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "attribute 'ethernet_type' expects"
                        " type 'int'");
        return -1;
    }
    self->__ethernet.type = htons(PyLong_AsLong(value));

    return 0;
}

int ethernet_add_type(PyObject *module)
{
    ethernet_type.tp_base = &packet_type;
    if (PyType_Ready(&ethernet_type) < 0)
        return 0;
    Py_INCREF(&ethernet_type);
    PyModule_AddObject(module, "ethernet", (PyObject *)&ethernet_type);

    return 1;
}

PyObject *create_ethernet_instance(int caplen,
                                   const unsigned char *pkt)
{
    PyObject *obj;

    obj = ethernet_type.tp_new(&ethernet_type, NULL, NULL);
    memcpy(&((ethernet *)obj)->__ethernet, pkt,
           sizeof(struct ethernet));
    return obj;
}
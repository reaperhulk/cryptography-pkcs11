# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import collections

import six


Attribute = collections.namedtuple("Attribute", ["type", "value"])
CKAttributes = collections.namedtuple("CKAttributes", ["template", "cffivals"])


def build_attributes(attrs, backend):
    attributes = backend._ffi.new("CK_ATTRIBUTE[{0}]".format(len(attrs)))
    val_list = []
    for index, attr in enumerate(attrs):
        attributes[index].type = attr.type
        if isinstance(attr.value, bool):
            val_list.append(backend._ffi.new("unsigned char *",
                            int(attr.value)))
            attributes[index].value_len = 1  # sizeof(char) is 1
        elif isinstance(attr.value, int):
            # second because bools are also considered ints
            val_list.append(backend._ffi.new("CK_ULONG *", attr.value))
            attributes[index].value_len = 8
        elif isinstance(attr.value, six.binary_type):
            val_list.append(backend._ffi.new("char []", attr.value))
            attributes[index].value_len = len(attr.value)
        elif isinstance(attr.value, backend._ffi.CData):
            val_list.append(attr.value)
            attributes[index].value_len = backend._ffi.sizeof(
                attr.value
            )
        else:
            raise TypeError("Unknown attribute type provided.")

        attributes[index].value = val_list[-1]

    return CKAttributes(attributes, val_list)


# TODO: this is all untested for now
def key_handle_from_attributes(attributes, backend):
    # TODO: need a public API for building attribute templates
    session = backend._session_pool.acquire()
    rv = backend._lib.C_FindObjectsInit(
        session[0], attributes.template, len(attributes.template)
    )
    backend._check_error(rv)

    count = backend._ffi.new("CK_ULONG *")
    obj_handle_ptr = backend._ffi.new("CK_OBJECT_HANDLE[2]")
    rv = backend._lib.C_FindObjects(session[0], obj_handle_ptr, 2, count)
    backend._check_error(rv)
    handle = None
    if count[0] == 1:
        handle = obj_handle_ptr[0]
    rv = backend._lib.C_FindObjectsFinal(session[0])
    backend._check_error(rv)
    if count[0] > 1:
        raise SystemError
    return KeyHandle(handle, backend)


# TODO: document that this is a session only handle. no persistence
# TODO: this doesn't error when passing invalid key sizes for AES.
# TODO: handle other key types.
def key_handle_from_bytes(data, backend):
    session = backend._session_pool.acquire()
    attrs = build_attributes([
        Attribute(backend._binding.CKA_CLASS, backend._binding.CKO_SECRET_KEY),
        Attribute(backend._binding.CKA_KEY_TYPE, backend._binding.CKK_AES),
        Attribute(backend._binding.CKA_VALUE, data),
        Attribute(backend._binding.CKA_TOKEN, False),  # don't persist it
        Attribute(backend._binding.CKA_ENCRYPT, True),
        Attribute(backend._binding.CKA_DECRYPT, True),
    ], backend)
    object_handle = backend._ffi.new("CK_OBJECT_HANDLE *")
    res = backend._lib.C_CreateObject(
        session[0], attrs.template, len(attrs.template), object_handle
    )
    backend._check_error(res)
    return KeyHandle(object_handle[0], backend)


class KeyHandle(object):
    def __init__(self, handle, backend):
        self._handle = handle
        self._backend = backend
        session = backend._session_pool.acquire()
        length = backend._ffi.new("CK_ULONG *")
        attrs = build_attributes([
            Attribute(backend._binding.CKA_VALUE_LEN, length),
        ], backend)
        res = backend._lib.C_GetAttributeValue(
            session[0], self._handle, attrs.template, len(attrs.template)
        )
        backend._check_error(res)
        self._length = length[0]

    # TODO: This will only work for symmetric keys. Maybe this needs to be
    # a SymmetricKeyHandle?
    def __len__(self):
        return self._length

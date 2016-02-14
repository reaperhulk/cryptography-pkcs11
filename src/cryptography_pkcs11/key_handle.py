# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import six


class CKAttributes(object):
    def __init__(self, template, cffivals):
        self.template = template
        self._cffivals = cffivals


def build_attributes(attrs, backend):
    attributes = backend._ffi.new("CK_ATTRIBUTE[{0}]".format(len(attrs)))
    # We build and append to the val_list so that the cdata wrappers we create
    # do not fall out of scope and cause the underlying memory to be gc'd
    val_list = []
    for index, attr in enumerate(attrs):
        attributes[index].type = attr[0]
        if isinstance(attr[1], bool):
            val_list.append(backend._ffi.new("unsigned char *", int(attr[1])))
            attributes[index].value_len = 1  # sizeof(char) is 1
        elif isinstance(attr[1], int):
            # second because bools are also considered ints
            val_list.append(backend._ffi.new("CK_ULONG *", attr[1]))
            attributes[index].value_len = 8
        elif isinstance(attr[1], six.binary_type):
            val_list.append(backend._ffi.new("char []", attr[1]))
            attributes[index].value_len = len(attr[1])
        elif isinstance(attr[1], backend._ffi.CData):
            val_list.append(attr[1])
            attributes[index].value_len = backend._ffi.sizeof(attr[1])
        else:
            raise TypeError("Unknown attribute type provided.")

        attributes[index].value = val_list[-1]

    return CKAttributes(attributes, val_list)


# TODO: this is all untested for now
def key_handle_from_attributes(attributes, backend):
    # TODO: need a public API for building attribute templates
    session = backend._session_pool.acquire_and_init(
        backend, backend._lib.C_FindObjectsInit, attributes.template,
        len(attributes.template)
    )

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
    attrs = build_attributes([
        (backend._binding.CKA_CLASS, backend._binding.CKO_SECRET_KEY),
        (backend._binding.CKA_KEY_TYPE, backend._binding.CKK_AES),
        (backend._binding.CKA_VALUE, data),
        (backend._binding.CKA_TOKEN, False),  # don't persist it
        (backend._binding.CKA_ENCRYPT, True),
        (backend._binding.CKA_DECRYPT, True),
    ], backend)
    object_handle = backend._ffi.new("CK_OBJECT_HANDLE *")
    session = backend._session_pool.acquire_and_init(
        backend, backend._lib.C_CreateObject, attrs.template,
        len(attrs.template), object_handle
    )
    return KeyHandle(object_handle[0], session, backend)


class KeyHandle(object):
    def __init__(self, handle, session, backend):
        self._handle = handle
        self._backend = backend
        self._session = session
        length = backend._ffi.new("CK_ULONG *")
        attrs = build_attributes([
            (backend._binding.CKA_VALUE_LEN, length),
        ], backend)
        res = backend._lib.C_GetAttributeValue(
            self._session[0], self._handle, attrs.template, len(attrs.template)
        )
        backend._check_error(res)
        self._length = length[0]

    # TODO: This will only work for symmetric keys. Maybe this needs to be
    # a SymmetricKeyHandle?
    def __len__(self):
        return self._length

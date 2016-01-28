# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import cffi


ffi = cffi.FFI()
ffi.cdef("""
typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_STATE;
typedef unsigned long CK_USER_TYPE;
typedef unsigned char * CK_UTF8CHAR_PTR;
typedef ... *CK_NOTIFY;
typedef unsigned long ck_attribute_type_t;
struct ck_attribute {
    ck_attribute_type_t type;
    void *value;
    unsigned long value_len;
};
typedef struct ck_attribute CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;
typedef unsigned long ck_mechanism_type_t;
struct ck_mechanism {
    ck_mechanism_type_t mechanism;
    void *parameter;
    unsigned long parameter_len;
};
typedef struct ck_mechanism CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef struct ck_session_info {
    CK_SLOT_ID slot_id;
    CK_STATE state;
    CK_FLAGS flags;
    unsigned long device_error;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;


CK_RV C_Initialize(void *);
CK_RV C_OpenSession(CK_SLOT_ID, CK_FLAGS, void *, CK_NOTIFY,
                    CK_SESSION_HANDLE *);
CK_RV C_CloseSession(CK_SESSION_HANDLE);
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
CK_RV C_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR,
              CK_ULONG);
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                          CK_ATTRIBUTE *, CK_ULONG);
CK_RV C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
CK_RV C_FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG,
                    CK_ULONG *);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE);
CK_RV C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *,
                    CK_ULONG, CK_OBJECT_HANDLE *);
CK_RV C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE);
CK_RV C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE);
CK_RV C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                CK_ULONG_PTR);
CK_RV C_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                 CK_OBJECT_HANDLE);
CK_RV C_Sign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
             CK_ULONG_PTR);
CK_RV C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                   CK_OBJECT_HANDLE);
CK_RV C_Verify(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
               CK_ULONG);
CK_RV C_DigestInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
CK_RV C_DigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV C_DigestFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

CK_RV C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                          CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
""")

p11_path = os.environ.get("CRYPTOGRAPHY_PKCS11_PATH")
if not p11_path:
    raise ValueError(
        "You must supply the absolute path to a PKCS11 shared object with the "
        "CRYPTOGRAPHY_PKCS11_PATH environment variable"
    )

lib = ffi.dlopen(p11_path)
res = lib.C_Initialize(ffi.NULL)
# TODO: import lock should make this safe, except subinterpreters ruin all
if res != 0:
    raise RuntimeError("Unable to initialize PKCS11 library")


class Binding(object):
    """
    PKCS11 API wrapper.
    """
    lib = lib
    ffi = ffi

    # easiest place to get these is not the spec, but OpenSC's header!
    # https://github.com/OpenSC/OpenSC/blob/master/src/pkcs11/pkcs11.h
    CKF_SERIAL_SESSION = 1 << 2
    CKF_RW_SESSION = 1 << 1

    CKU_SO = 0
    CKU_USER = 1

    CKM_MD5 = 0x210
    CKM_RIPEMD160 = 0x240
    CKM_SHA_1 = 0x220
    CKM_SHA256 = 0x250
    CKM_SHA384 = 0x260
    CKM_SHA512 = 0x270

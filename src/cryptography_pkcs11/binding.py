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
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
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
typedef void *CK_VOID_PTR;
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
    CK_MECHANISM_TYPE hashAlg;
    CK_RSA_PKCS_MGF_TYPE mgf;
    CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
    CK_VOID_PTR pSourceData;
    CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;
typedef struct ck_rsa_pkcs_pss_params {
  CK_MECHANISM_TYPE hashAlg;
  CK_RSA_PKCS_MGF_TYPE mgf;
  CK_ULONG salt_len;
} CK_RSA_PKCS_PSS_PARAMS;

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
CK_RV C_FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG,
                    CK_ULONG *);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE);
CK_RV C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *,
                    CK_ULONG, CK_OBJECT_HANDLE_PTR);
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
                        CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG,
                        CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
CK_RV C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE);
CK_RV C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                      CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_EncryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE);
CK_RV C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                CK_ULONG_PTR);
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                      CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_DecryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                 CK_OBJECT_HANDLE);
CK_RV C_SignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV C_SignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                   CK_OBJECT_HANDLE);
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV C_VerifyFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV C_DigestInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
CK_RV C_DigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV C_DigestFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

CK_RV C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                          CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);

CK_RV C_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                     CK_OBJECT_HANDLE_PTR);
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                          CK_ATTRIBUTE_PTR, CK_ULONG);
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

    CKF_SERIAL_SESSION = 1 << 2
    CKF_RW_SESSION = 1 << 1

    CKU_SO = 0
    CKU_USER = 1

    CKG_MGF1_SHA1 = 1
    CKG_MGF1_SHA224 = 5
    CKG_MGF1_SHA256 = 2
    CKG_MGF1_SHA384 = 3
    CKG_MGF1_SHA512 = 4

    CKK_RSA = 0
    CKK_DSA = 1
    CKK_DH = 2
    CKK_ECDSA = 3
    CKK_EC = 3
    CKK_AES = 0x1f
    CKK_DES3 = 0x15

    CKM_MD5 = 0x210
    CKM_SHA_1 = 0x220
    CKM_SHA224 = 0x255
    CKM_SHA256 = 0x250
    CKM_SHA384 = 0x260
    CKM_SHA512 = 0x270

    CKM_SHA1_RSA_PKCS = 6
    CKM_SHA224_RSA_PKCS = 0x46
    CKM_SHA256_RSA_PKCS = 0x40
    CKM_SHA384_RSA_PKCS = 0x41
    CKM_SHA512_RSA_PKCS = 0x42
    CKM_SHA1_RSA_PKCS_PSS = 0xe
    CKM_SHA224_RSA_PKCS_PSS = 0x47
    CKM_SHA256_RSA_PKCS_PSS = 0x43
    CKM_SHA384_RSA_PKCS_PSS = 0x44
    CKM_SHA512_RSA_PKCS_PSS = 0x45

    CKM_RSA_PKCS_KEY_PAIR_GEN = 0
    CKM_RSA_PKCS = 1
    CKM_RSA_PKCS_OAEP = 9
    CKM_DES3_ECB = 0x132
    CKM_DES3_CBC = 0x133
    CKM_AES_ECB = 0x1081
    CKM_AES_CBC = 0x1082
    CKM_AES_CTR = 0x1086
    CKM_AES_GCM = 0x1087

    CKO_DATA = 0
    CKO_CERTIFICATE = 1
    CKO_PUBLIC_KEY = 2
    CKO_PRIVATE_KEY = 3
    CKO_SECRET_KEY = 4

    CKA_CLASS = 0
    CKA_TOKEN = 1
    CKA_PRIVATE = 2
    CKA_LABEL = 3
    CKA_APPLICATION = 0x10
    CKA_VALUE = 0x11
    CKA_OBJECT_ID = 0x12
    CKA_CERTIFICATE_TYPE = 0x80
    CKA_ISSUER = 0x81
    CKA_SERIAL_NUMBER = 0x82
    CKA_AC_ISSUER = 0x83
    CKA_OWNER = 0x84
    CKA_ATTR_TYPES = 0x85
    CKA_TRUSTED = 0x86
    CKA_CERTIFICATE_CATEGORY = 0x87
    CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x88
    CKA_URL = 0x89
    CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x8a
    CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x8b
    CKA_CHECK_VALUE = 0x90
    CKA_KEY_TYPE = 0x100
    CKA_SUBJECT = 0x101
    CKA_ID = 0x102
    CKA_SENSITIVE = 0x103
    CKA_ENCRYPT = 0x104
    CKA_DECRYPT = 0x105
    CKA_WRAP = 0x106
    CKA_UNWRAP = 0x107
    CKA_SIGN = 0x108
    CKA_SIGN_RECOVER = 0x109
    CKA_VERIFY = 0x10a
    CKA_VERIFY_RECOVER = 0x10b
    CKA_DERIVE = 0x10c
    CKA_START_DATE = 0x110
    CKA_END_DATE = 0x111
    CKA_MODULUS = 0x120
    CKA_MODULUS_BITS = 0x121
    CKA_PUBLIC_EXPONENT = 0x122
    CKA_PRIVATE_EXPONENT = 0x123
    CKA_PRIME_1 = 0x124
    CKA_PRIME_2 = 0x125
    CKA_EXPONENT_1 = 0x126
    CKA_EXPONENT_2 = 0x127
    CKA_COEFFICIENT = 0x128
    CKA_PRIME = 0x130
    CKA_SUBPRIME = 0x131
    CKA_BASE = 0x132
    CKA_PRIME_BITS = 0x133
    CKA_SUB_PRIME_BITS = 0x134
    CKA_VALUE_BITS = 0x160
    CKA_VALUE_LEN = 0x161
    CKA_EXTRACTABLE = 0x162
    CKA_LOCAL = 0x163
    CKA_NEVER_EXTRACTABLE = 0x164
    CKA_ALWAYS_SENSITIVE = 0x165
    CKA_KEY_GEN_MECHANISM = 0x166
    CKA_MODIFIABLE = 0x170
    CKA_ECDSA_PARAMS = 0x180
    CKA_EC_PARAMS = 0x180
    CKA_EC_POINT = 0x181
    CKA_SECONDARY_AUTH = 0x200
    CKA_AUTH_PIN_FLAGS = 0x201
    CKA_ALWAYS_AUTHENTICATE = 0x202
    CKA_WRAP_WITH_TRUSTED = 0x210
    CKA_HW_FEATURE_TYPE = 0x300
    CKA_RESET_ON_INIT = 0x301
    CKA_HAS_RESET = 0x302
    CKA_PIXEL_X = 0x400
    CKA_PIXEL_Y = 0x401
    CKA_RESOLUTION = 0x402
    CKA_CHAR_ROWS = 0x403
    CKA_CHAR_COLUMNS = 0x404
    CKA_COLOR = 0x405
    CKA_BITS_PER_PIXEL = 0x406
    CKA_CHAR_SETS = 0x480
    CKA_ENCODING_METHODS = 0x481
    CKA_MIME_TYPES = 0x482
    CKA_MECHANISM_TYPE = 0x500
    CKA_REQUIRED_CMS_ATTRIBUTES = 0x501
    CKA_DEFAULT_CMS_ATTRIBUTES = 0x502
    CKA_SUPPORTED_CMS_ATTRIBUTES = 0x503

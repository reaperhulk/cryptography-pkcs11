# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import collections
import math

from cryptography import utils
from cryptography.exceptions import (
    InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    AsymmetricSignatureContext, AsymmetricVerificationContext, rsa
)
from cryptography.hazmat.primitives.asymmetric.padding import (
    AsymmetricPadding, MGF1, OAEP, PKCS1v15, PSS
)

Attribute = collections.namedtuple("Attribute", ["type", "value"])


# TODO: stolen from openssl backend
def _get_rsa_pss_salt_length(pss, key_size, digest_size):
    salt = pss._salt_length

    if salt is MGF1.MAX_LENGTH or salt is PSS.MAX_LENGTH:
        # bit length - 1 per RFC 3447
        emlen = int(math.ceil((key_size - 1) / 8.0))
        # emlen = (key_size + 7) // 8
        salt_length = emlen - digest_size - 2 - 20  # TODO: -20 added
        assert salt_length >= 0
        return salt_length
    else:
        return salt


def _check_enc_dec(padding):
    if not isinstance(padding, AsymmetricPadding):
        raise TypeError(
            "Padding must be an instance of AsymmetricPadding."
        )

        if isinstance(padding, OAEP):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend.",
                    _Reasons.UNSUPPORTED_MGF
                )
            if not isinstance(padding._mgf._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend supports only SHA1 inside MGF1 when "
                    "using OAEP.",
                    _Reasons.UNSUPPORTED_HASH
                )


@utils.register_interface(rsa.RSAPublicKeyWithSerialization)
class _RSAPublicKey(object):
    def __init__(self, backend, handle):
        self._backend = backend
        self._handle = handle

    def verifier(self, signature, padding, algorithm):
        return _RSAVerificationContext(
            self._backend, self, signature, padding, algorithm
        )

    def encrypt(self, plaintext, padding):
        _check_enc_dec(padding)
        mech = self._backend._ffi.new("CK_MECHANISM *")

        if isinstance(padding, PKCS1v15):
            mech.mechanism = self._backend._binding.CKM_RSA_PKCS
        elif isinstance(padding, OAEP):
            if padding._label is not None and padding._label != b"":
                raise ValueError("This backend does not support OAEP labels.")

            if not isinstance(padding._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend only supports SHA1 when using OAEP.",
                    _Reasons.UNSUPPORTED_HASH
                )

            mech.mechanism = self._backend._binding.CKM_RSA_PKCS_OAEP
            oaep_params = self._backend._ffi.new("CK_RSA_PKCS_OAEP_PARAMS *")
            oaep_params.hashAlg = self._backend._binding.CKM_SHA_1
            oaep_params.mgf = self._backend._binding.CKG_MGF1_SHA1
            oaep_params.source = 1  # apparently this is CKZ_DATA_SPECIFIED
            mech.parameter = oaep_params
            mech.parameter_len = 40  # size of that struct
        else:
            raise NotImplementedError

        session = self._backend._session_pool.acquire()
        res = self._backend._lib.C_EncryptInit(session[0], mech, self._handle)
        self._backend._check_error(res)
        # TODO: size this properly. Right now it's large enough for a
        # 2048-bit key.
        buf = self._backend._ffi.new("unsigned char[]", 256)
        buflen = self._backend._ffi.new("CK_ULONG *", 256)
        res = self._backend._lib.C_Encrypt(
            session[0], plaintext, len(plaintext), buf, buflen
        )
        self._backend._check_error(res)

        return self._backend._ffi.buffer(buf, buflen[0])[:]

    @property
    def key_size(self):
        # TODO: cache this. and also handle non-bye aligned keys
        attrs = self._backend._build_attributes([
            Attribute(
                self._backend._binding.CKA_MODULUS, self._backend._ffi.NULL
            ),
        ])
        session = self._backend._session_pool.acquire()
        res = self._backend._lib.C_GetAttributeValue(
            session[0], self._handle, attrs.template, len(attrs.template)
        )
        self._backend._check_error(res)
        key_size = attrs.template[0].value_len

        return key_size * 8

    def public_numbers(self):
        pass

    def public_bytes(self, encoding, format):
        pass


@utils.register_interface(rsa.RSAPrivateKey)
class _RSAPrivateKey(object):
    def __init__(self, backend, handle):
        self._backend = backend
        # TODO: consider using ffi.gc to clean up open handles
        self._handle = handle

    def signer(self, padding, algorithm):
        return _RSASignatureContext(self._backend, self, padding, algorithm)

    def decrypt(self, ciphertext, padding):
        _check_enc_dec(padding)
        mech = self._backend._ffi.new("CK_MECHANISM *")

        if isinstance(padding, PKCS1v15):
            mech.mechanism = self._backend._binding.CKM_RSA_PKCS
        elif isinstance(padding, OAEP):
            if padding._label is not None and padding._label != b"":
                raise ValueError("This backend does not support OAEP labels.")

            if not isinstance(padding._algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This backend only supports SHA1 when using OAEP.",
                    _Reasons.UNSUPPORTED_HASH
                )

            mech.mechanism = self._backend._binding.CKM_RSA_PKCS_OAEP
            oaep_params = self._backend._ffi.new("CK_RSA_PKCS_OAEP_PARAMS *")
            oaep_params.hashAlg = self._backend._binding.CKM_SHA_1
            oaep_params.mgf = self._backend._binding.CKG_MGF1_SHA1
            oaep_params.source = 1  # apparently this is CKZ_DATA_SPECIFIED
            mech.parameter = oaep_params
            mech.parameter_len = 40  # size of that struct
        else:
            raise NotImplementedError

        session = self._backend._session_pool.acquire()
        res = self._backend._lib.C_DecryptInit(
            session[0], mech, self._handle
        )
        self._backend._check_error(res)
        # TODO: size this properly. Right now it's large enough for a
        # 2048-bit key.
        buf = self._backend._ffi.new("unsigned char[]", 256)
        buflen = self._backend._ffi.new("CK_ULONG *", 256)
        res = self._backend._lib.C_Decrypt(
            session[0], ciphertext, len(ciphertext), buf, buflen
        )
        if res != 0:
            raise ValueError("Decryption failed")

        return self._backend._ffi.buffer(buf, buflen[0])[:]

    def public_key(self):
        # TODO: These buffers could be dynamically sized in the future, but
        # it would require two calls to the PKCS11 layer. Right now it will
        # work with a single call as long as the key is 8192-bit or smaller and
        # the modulus isn't some ludicrous value.
        attrs = self._backend._build_attributes([
            Attribute(
                self._backend._binding.CKA_MODULUS,
                self._backend._ffi.new("unsigned char[]", 1024)
            ),
            Attribute(
                self._backend._binding.CKA_PUBLIC_EXPONENT,
                self._backend._ffi.new("unsigned char[]", 1024)
            ),
        ])
        session = self._backend._session_pool.acquire()
        res = self._backend._lib.C_GetAttributeValue(
            session[0], self._handle, attrs.template, len(attrs.template)
        )
        self._backend._check_error(res)
        # okay, now we get to create a new object handle!
        n = utils.int_from_bytes(
            self._backend._ffi.buffer(
                attrs.template[0].value, attrs.template[0].value_len
            )[:],
            'big'
        )
        e = utils.int_from_bytes(
            self._backend._ffi.buffer(
                attrs.template[1].value, attrs.template[1].value_len
            )[:],
            'big'
        )

        return self._backend.load_rsa_public_numbers(
            rsa.RSAPublicNumbers(e, n)
        )

    @property
    def key_size(self):
        # TODO: cache this. and also handle non-bye aligned keys
        attrs = self._backend._build_attributes([
            Attribute(
                self._backend._binding.CKA_MODULUS, self._backend._ffi.NULL
            ),
        ])
        session = self._backend._session_pool.acquire()
        res = self._backend._lib.C_GetAttributeValue(
            session[0], self._handle, attrs.template, len(attrs.template)
        )
        self._backend._check_error(res)
        key_size = attrs.template[0].value_len

        return key_size * 8


@utils.register_interface(AsymmetricSignatureContext)
class _RSASignatureContext(object):
    def __init__(self, backend, private_key, padding, algorithm):
        self._backend = backend
        self._private_key = private_key
        self._padding = padding
        self._algorithm = algorithm
        self._session = _sign_verify_init(
            backend, self._backend._lib.C_SignInit, padding, private_key,
            algorithm
        )

    def update(self, data):
        res = self._backend._lib.C_SignUpdate(
            self._session[0], data, len(data)
        )
        self._backend._check_error(res)

    def finalize(self):
        # TODO: size this properly. Right now it's large enough for a
        # 2048-bit key.
        buf = self._backend._ffi.new("unsigned char[]", 256)
        buflen = self._backend._ffi.new("CK_ULONG *", 256)
        res = self._backend._lib.C_SignFinal(self._session[0], buf, buflen)
        if res != 0:
            raise ValueError("Signature failed")

        return self._backend._ffi.buffer(buf, buflen[0])[:]


@utils.register_interface(AsymmetricVerificationContext)
class _RSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, padding, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._padding = padding
        self._algorithm = algorithm
        self._signature = signature
        self._session = _sign_verify_init(
            backend, self._backend._lib.C_VerifyInit, padding, public_key,
            algorithm
        )

    def update(self, data):
        res = self._backend._lib.C_VerifyUpdate(
            self._session[0], data, len(data)
        )
        self._backend._check_error(res)

    def verify(self):
        buf = self._backend._ffi.new("unsigned char[]", self._signature)
        res = self._backend._lib.C_VerifyFinal(
            self._session[0], buf, len(self._signature)
        )
        if res != 0:
            raise InvalidSignature


def _sign_verify_init(backend, func, padding, key, algorithm):
    if not isinstance(padding, AsymmetricPadding):
        raise TypeError("Expected provider of AsymmetricPadding.")

    mech = backend._ffi.new("CK_MECHANISM *")
    if isinstance(padding, PKCS1v15):
        # TODO: probably not this dict.
        mech.mechanism = {
            "sha1": backend._binding.CKM_SHA1_RSA_PKCS,
            "sha256": backend._binding.CKM_SHA256_RSA_PKCS,
            "sha384": backend._binding.CKM_SHA384_RSA_PKCS,
            "sha512": backend._binding.CKM_SHA512_RSA_PKCS,
        }[algorithm.name]
    elif isinstance(padding, PSS):
        if not isinstance(padding._mgf, MGF1):
            raise UnsupportedAlgorithm(
                "Only MGF1 is supported by this backend.",
                _Reasons.UNSUPPORTED_MGF
            )

        # Size of key in bytes - 2 is the maximum
        # PSS signature length (salt length is checked later)
        if ((key.key_size + 7) // 8 -
                algorithm.digest_size - 2 < 0):
            raise ValueError("Digest too large for key size. Use a larger "
                             "key.")

        salt_length = _get_rsa_pss_salt_length(
            padding, key.key_size, algorithm.digest_size
        )
        params = backend._ffi.new("CK_RSA_PKCS_PSS_PARAMS *")
        # TODO: better than this hash mapping?
        params.hashAlg = backend._hash_mapping[algorithm.name]
        params.mgf = backend._binding.CKG_MGF1_SHA1
        params.salt_len = salt_length
        # TODO: probably not this hash
        mech.mechanism = {
            "sha1": backend._binding.CKM_SHA1_RSA_PKCS_PSS,
            "sha256": backend._binding.CKM_SHA256_RSA_PKCS_PSS,
            "sha384": backend._binding.CKM_SHA384_RSA_PKCS_PSS,
            "sha512": backend._binding.CKM_SHA512_RSA_PKCS_PSS
        }[algorithm.name]
        mech.parameter = params
        mech.parameter_len = 24
    else:
        raise UnsupportedAlgorithm(
            "{0} is not supported by this backend.".format(padding.name),
            _Reasons.UNSUPPORTED_PADDING
        )
    session = backend._session_pool.acquire()
    res = func(session[0], mech, key._handle)
    backend._check_error(res)
    return session

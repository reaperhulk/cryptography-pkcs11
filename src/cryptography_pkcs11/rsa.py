# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import math

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    AsymmetricSignatureContext, AsymmetricVerificationContext, rsa
)
from cryptography.hazmat.primitives.asymmetric.padding import (
    AsymmetricPadding, MGF1, OAEP, PKCS1v15, PSS
)

from cryptography_pkcs11.key_handle import Attribute, build_attributes


# TODO: stolen from openssl backend
def _get_rsa_pss_salt_length(pss, key_size, digest_size):
    salt = pss._salt_length

    if salt is MGF1.MAX_LENGTH or salt is PSS.MAX_LENGTH:
        # bit length - 1 per RFC 3447
        emlen = int(math.ceil((key_size - 1) / 8.0))
        salt_length = emlen - digest_size - 2
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
        if not isinstance(signature, bytes):
            raise TypeError("signature must be bytes.")

        return _RSAVerificationContext(
            self._backend, self, signature, padding, algorithm
        )

    def encrypt(self, plaintext, padding):
        res, buf, buflen = _enc_dec(
            self._backend, padding, self._backend._lib.C_EncryptInit,
            self._backend._lib.C_Encrypt, self._handle, plaintext
        )
        if res != 0:
            raise ValueError(
                "Encryption failed. This is commonly due to the data size "
                "being too large for the key"
            )

        return self._backend._ffi.buffer(buf, buflen[0])[:]

    def public_numbers(self):
        e, n = _get_e_n(self._backend, self._handle)
        return rsa.RSAPublicNumbers(e, n)

    @property
    def key_size(self):
        return _key_size(self._backend, self._handle)

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
        res, buf, buflen = _enc_dec(
            self._backend, padding, self._backend._lib.C_DecryptInit,
            self._backend._lib.C_Decrypt, self._handle, ciphertext
        )
        if res != 0:
            raise ValueError("Decryption failed")

        return self._backend._ffi.buffer(buf, buflen[0])[:]

    def public_key(self):
        e, n = _get_e_n(self._backend, self._handle)
        return self._backend.load_rsa_public_numbers(
            rsa.RSAPublicNumbers(e, n)
        )

    @property
    def key_size(self):
        return _key_size(self._backend, self._handle)


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
        if self._session is None:
            raise AlreadyFinalized("Context has already been finalized.")

        res = self._backend._lib.C_SignUpdate(
            self._session[0], data, len(data)
        )
        self._backend._check_error(res)

    def finalize(self):
        if self._session is None:
            raise AlreadyFinalized("Context has already been finalized.")

        # TODO: size this properly. Right now it's large enough for a
        # 2048-bit key.
        buf = self._backend._ffi.new("unsigned char[]", 256)
        buflen = self._backend._ffi.new("CK_ULONG *", 256)
        res = self._backend._lib.C_SignFinal(self._session[0], buf, buflen)
        self._session = None
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
        if self._session is None:
            raise AlreadyFinalized("Context has already been finalized.")

        res = self._backend._lib.C_VerifyUpdate(
            self._session[0], data, len(data)
        )
        self._backend._check_error(res)

    def verify(self):
        if self._session is None:
            raise AlreadyFinalized("Context has already been finalized.")

        buf = self._backend._ffi.new("unsigned char[]", self._signature)
        res = self._backend._lib.C_VerifyFinal(
            self._session[0], buf, len(self._signature)
        )
        self._session = None
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
            "sha224": backend._binding.CKM_SHA224_RSA_PKCS,
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
        params.mgf = {
            "sha1": backend._binding.CKG_MGF1_SHA1,
            "sha224": backend._binding.CKG_MGF1_SHA224,
            "sha256": backend._binding.CKG_MGF1_SHA256,
            "sha384": backend._binding.CKG_MGF1_SHA384,
            "sha512": backend._binding.CKG_MGF1_SHA512,
        }[padding._mgf._algorithm.name]
        params.salt_len = salt_length
        # TODO: probably not this hash
        mech.mechanism = {
            "sha1": backend._binding.CKM_SHA1_RSA_PKCS_PSS,
            "sha224": backend._binding.CKM_SHA224_RSA_PKCS_PSS,
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
    session = backend._session_pool.acquire_and_init(
        backend, func, mech, key._handle
    )
    # TODO: probably modify acquire and init to be able to raise diff errors
    # if res != 0:
    #  raise ValueError("Error code {} received from PKCS11".format(hex(res)))

    return session


def _enc_dec(backend, padding, init, operation, handle, data):
    _check_enc_dec(padding)
    mech = backend._ffi.new("CK_MECHANISM *")

    if isinstance(padding, PKCS1v15):
        mech.mechanism = backend._binding.CKM_RSA_PKCS
    elif isinstance(padding, OAEP):
        if padding._label is not None and padding._label != b"":
            raise ValueError("This backend does not support OAEP labels.")

        if not isinstance(padding._algorithm, hashes.SHA1):
            raise UnsupportedAlgorithm(
                "This backend only supports SHA1 when using OAEP.",
                _Reasons.UNSUPPORTED_HASH
            )

        mech.mechanism = backend._binding.CKM_RSA_PKCS_OAEP
        oaep_params = backend._ffi.new("CK_RSA_PKCS_OAEP_PARAMS *")
        oaep_params.hashAlg = backend._binding.CKM_SHA_1
        oaep_params.mgf = backend._binding.CKG_MGF1_SHA1
        oaep_params.source = 1  # apparently this is CKZ_DATA_SPECIFIED
        mech.parameter = oaep_params
        mech.parameter_len = 40  # size of that struct
    else:
        raise UnsupportedAlgorithm(
            "{0} is not supported by this backend.".format(padding.name),
            _Reasons.UNSUPPORTED_PADDING
        )

    session = backend._session_pool.acquire_and_init(
        backend, init, mech, handle
    )
    # TODO: size this properly. Right now it's large enough for a
    # 2048-bit key.
    buf = backend._ffi.new("unsigned char[]", 256)
    buflen = backend._ffi.new("CK_ULONG *", 256)
    res = operation(session[0], data, len(data), buf, buflen)
    return (res, buf, buflen)


def _get_e_n(backend, handle):
        # TODO: These buffers could be dynamically sized in the future, but
        # it would require two calls to the PKCS11 layer. Right now it will
        # work with a single call as long as the key is 8192-bit or smaller and
        # the modulus isn't some ludicrous value.
        attrs = build_attributes([
            Attribute(
                backend._binding.CKA_MODULUS,
                backend._ffi.new("unsigned char[]", 1024)
            ),
            Attribute(
                backend._binding.CKA_PUBLIC_EXPONENT,
                backend._ffi.new("unsigned char[]", 64)
            ),
        ], backend)
        session = backend._session_pool.acquire()
        res = backend._lib.C_GetAttributeValue(
            session[0], handle, attrs.template, len(attrs.template)
        )
        backend._check_error(res)
        n = utils.int_from_bytes(
            backend._ffi.buffer(
                attrs.template[0].value, attrs.template[0].value_len
            )[:],
            'big'
        )
        e = utils.int_from_bytes(
            backend._ffi.buffer(
                attrs.template[1].value, attrs.template[1].value_len
            )[:],
            'big'
        )

        return e, n


def _key_size(backend, handle):
    # TODO: cache this. and also handle non-bye aligned keys
    e, n = _get_e_n(backend, handle)
    return n.bit_length()

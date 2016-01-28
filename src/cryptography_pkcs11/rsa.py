# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import (
    AsymmetricPadding, MGF1, OAEP, PKCS1v15
)


@utils.register_interface(rsa.RSAPublicKeyWithSerialization)
class _RSAPublicKey(object):
    def __init__(self, backend, handle):
        self._backend = backend
        self._handle = handle

    def verifier(self, signature, padding, algorithm):
        pass

    def encrypt(self, plaintext, padding):
        if not isinstance(padding, AsymmetricPadding):
            raise TypeError(
                "Padding must be an instance of AsymmetricPadding."
            )

        session = self._backend._session_pool.acquire()
        mech = self._backend._ffi.new("CK_MECHANISM *")

        if isinstance(padding, PKCS1v15):
            mech.mechanism = self._backend._binding.CKM_RSA_PKCS
        elif isinstance(padding, OAEP):
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
        try:
            res = self._backend._lib.C_EncryptInit(
                session, mech, self._handle
            )
            self._backend._check_error(res)
            # TODO: size this properly. Right now it's large enough for a
            # 2048-bit key.
            buf = self._backend._ffi.new("unsigned char[]", 256)
            buflen = self._backend._ffi.new("CK_ULONG *", 256)
            res = self._backend._lib.C_Encrypt(
                session, plaintext, len(plaintext), buf, buflen
            )
            self._backend._check_error(res)
        finally:
            self._backend._session_pool.release(session)

        return self._backend._ffi.buffer(buf, buflen[0])[:]

    @property
    def key_size(self):
        pass

    def public_numbers(self):
        pass

    def public_bytes(self, encoding, format):
        pass

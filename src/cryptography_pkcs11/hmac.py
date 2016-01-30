# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


from cryptography import utils
from cryptography.exceptions import (
    InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.primitives import constant_time, hashes, interfaces

from cryptography_pkcs11.key_handle import KeyHandle, key_handle_from_bytes


@utils.register_interface(interfaces.MACContext)
@utils.register_interface(hashes.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, session=None):
        self._algorithm = algorithm
        self._backend = backend
        if isinstance(key, KeyHandle):
            self._key = key
        else:
            # TODO: pass the key type at some point
            self._key = key_handle_from_bytes(key, backend)

        if session is None:
            try:
                ckm = {
                    "md5": backend._binding.CKM_MD5_HMAC,
                    "sha1": backend._binding.CKM_SHA1_HMAC,
                    "sha224": backend._binding.CKM_SHA224_HMAC,
                    "sha256": backend._binding.CKM_SHA256_HMAC,
                    "sha384": backend._binding.CKM_SHA384_HMAC,
                    "sha512": backend._binding.CKM_SHA512_HMAC,
                }[self.algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend.".format(
                        algorithm.name),
                    _Reasons.UNSUPPORTED_HASH
                )

            session = self._backend._session_pool.acquire()
            mech = self._backend._ffi.new("CK_MECHANISM *")
            mech.mechanism = ckm
            res = self._backend._lib.C_SignInit(
                session[0], mech, self._key._handle
            )
            self._backend._check_error(res)

        self._session = session

    algorithm = utils.read_only_property("_algorithm")

    def copy(self):
        raise NotImplementedError

    def update(self, data):
        res = self._backend._lib.C_SignUpdate(
            self._session[0], data, len(data)
        )
        self._backend._check_error(res)

    def finalize(self):
        buf = self._backend._ffi.new(
            "unsigned char[]", self.algorithm.digest_size
        )
        buflen = self._backend._ffi.new(
            "CK_ULONG *", self.algorithm.digest_size
        )
        res = self._backend._lib.C_SignFinal(self._session[0], buf, buflen)
        self._backend._check_error(res)
        self._backend._session_pool.release(self._session)
        self._session = None
        assert buflen[0] == self.algorithm.digest_size
        return self._backend._ffi.buffer(buf, buflen[0])[:]

    # TODO: maybe do this in the HSM.
    def verify(self, signature):
        digest = self.finalize()
        if not constant_time.bytes_eq(digest, signature):
            raise InvalidSignature("Signature did not match digest.")

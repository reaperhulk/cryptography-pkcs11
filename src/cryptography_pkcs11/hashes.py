# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import hashes


@utils.register_interface(hashes.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self._algorithm = algorithm
        self._backend = backend

        if ctx is None:
            try:
                ckm = self._backend._hash_mapping[self.algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend.".format(
                        algorithm.name),
                    _Reasons.UNSUPPORTED_HASH
                )

            ctx = self._backend._session_pool.acquire()
            mech = self._backend._ffi.new("CK_MECHANISM *")
            mech.mechanism = ckm
            res = self._backend._lib.C_DigestInit(ctx[0], mech)
            self._backend._check_error(res)

        self._ctx = ctx

    algorithm = utils.read_only_property("_algorithm")

    def copy(self):
        raise NotImplementedError
        # TODO: size this buffer more appropriately and find a way to test
        # that this works since SoftHSM doesn't support these functions.
        buf = self._backend._ffi.new("unsigned char[]", 500)
        buflen = self._backend._ffi.new("CK_ULONG *", len(buf))
        res = self._backend._lib.C_GetOperationState(self._ctx[0], buf, buflen)
        self._backend._check_error(res)
        new_ctx = self._backend._session_pool.acquire()
        res = self._backend._lib.C_SetOperationState(
            new_ctx[0], buf, buflen[0], 0, 0
        )
        self._backend._check_error(res)
        return _HashContext(self._backend, self._algorithm, new_ctx)

    def update(self, data):
        res = self._backend._lib.C_DigestUpdate(self._ctx[0], data, len(data))
        self._backend._check_error(res)

    def finalize(self):
        buf = self._backend._ffi.new(
            "unsigned char[]", self.algorithm.digest_size
        )
        buflen = self._backend._ffi.new(
            "CK_ULONG *", self.algorithm.digest_size
        )
        res = self._backend._lib.C_DigestFinal(self._ctx[0], buf, buflen)
        self._backend._check_error(res)
        self._backend._session_pool.release(self._ctx)
        self._ctx = None
        assert buflen[0] == self.algorithm.digest_size
        return self._backend._ffi.buffer(buf, buflen[0])[:]

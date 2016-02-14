# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import modes

from cryptography_pkcs11.key_handle import KeyHandle, key_handle_from_bytes


@utils.register_interface(ciphers.CipherContext)
class _CipherContext(object):
    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        # TODO: softhsm only supports AES/3DES with ECB/CBC
        if not backend.cipher_supported(cipher, mode):
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend.".format(
                    cipher.name, mode.name if mode else mode),
                _Reasons.UNSUPPORTED_CIPHER
            )

        if isinstance(cipher, KeyHandle):
            self._key_handle = cipher.key
        else:
            self._key_handle = key_handle_from_bytes(cipher.key, backend)

        self._cipher = cipher
        self._mode = mode
        self._operation = operation
        self._buffer = b""

        if isinstance(self._cipher, ciphers.BlockCipherAlgorithm):
            self._block_size = self._cipher.block_size // 8
        else:
            self._block_size = 1

        if isinstance(mode, modes.ModeWithInitializationVector):
            iv_nonce = self._backend._ffi.new(
                "CK_BYTE[]", mode.initialization_vector
            )
            iv_nonce_len = len(mode.initialization_vector)
        elif isinstance(mode, modes.ModeWithNonce):
            iv_nonce = self._backend._ffi.new("CK_BYTE[]", mode.nonce)
            iv_nonce_len = len(mode.nonce)
        else:
            iv_nonce = self._backend._ffi.NULL
            iv_nonce_len = 0

        mech = self._backend._ffi.new("CK_MECHANISM *")
        mech.mechanism = self._get_mechanism(cipher, mode)
        mech.parameter = iv_nonce
        mech.parameter_len = iv_nonce_len
        self._session = self._backend._session_pool.acquire_and_init(
            backend, self._operation["init"], mech, self._key_handle._handle
        )

    def _get_mechanism(self, cipher, mode):
        return {
            "aes-ecb": self._backend._binding.CKM_AES_ECB,
            "aes-cbc": self._backend._binding.CKM_AES_CBC,
            "3des-ecb": self._backend._binding.CKM_DES3_ECB,
            "3des-cbc": self._backend._binding.CKM_DES3_CBC,
        }["{0}-{1}".format(cipher.name.lower(), mode.name.lower())]

    def update(self, data):
        # Some PKCS11 implementations care deeply about having data be provided
        # in block aligned fashion. This ugly code will buffer non-block
        # aligned data and add it to the next update call.
        if len(data) % self._block_size != 0 or self._buffer != b"":
            concatenated_data = self._buffer + data
            remainder = len(concatenated_data) % self._block_size
            if remainder != 0:
                self._buffer = concatenated_data[-remainder:]
                data = concatenated_data[:-remainder]
            else:
                data = concatenated_data
                self._buffer = b""

        return self._raw_update(data)

    def _raw_update(self, data):
        buflen = len(data) + self._block_size - 1
        buf = self._backend._ffi.new("CK_BYTE[]", buflen)
        outlen = self._backend._ffi.new("CK_ULONG *", buflen)
        res = self._operation["update"](
            self._session[0], data, len(data), buf, outlen)
        if res == 0x21:  # CKR_DATA_LEN_RANGE. Catches non-block aligned data
            raise ValueError(
                "The length of the provided data is not a multiple of "
                "the block length."
            )
        self._backend._check_error(res)

        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def finalize(self):
        # Since we buffer update calls we need to make sure we flush the buffer
        # before finalizing. If there's data left over and the mechanism
        # can't handle that, well, don't do that.
        data = self._raw_update(self._buffer)
        buf = self._backend._ffi.new("CK_BYTE[]", self._block_size)
        outlen = self._backend._ffi.new("CK_ULONG *")
        res = self._operation["final"](self._session[0], buf, outlen)
        self._backend._check_error(res)
        self._session.operation_active = False
        self._session = None

        return data + self._backend._ffi.buffer(buf)[:outlen[0]]

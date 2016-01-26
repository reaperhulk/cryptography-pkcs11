# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

from cryptography import utils
from cryptography.hazmat.backends.interfaces import HashBackend


from cryptography_pkcs11.binding import Binding
from cryptography_pkcs11.hashes import _HashContext


@utils.register_interface(HashBackend)
class Backend(object):
    """
    PKCS11 API wrapper.
    """
    name = "pkcs11"

    def __init__(self, slot_id=None, flags=None, user_type=None,
                 password=None):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib
        if slot_id is None:
            slot_id = int(os.environ.get("CRYPTOGRAPHY_PKCS11_SLOT_ID"))

        if slot_id is None:
            raise ValueError("slot_id must not be None")

        if flags is None:
            flags = int(os.environ.get("CRYPTOGRAPHY_PKCS11_FLAGS"))

        if user_type is None:
            user_type = int(os.environ.get("CRYPTOGRAPHY_PKCS11_USER_TYPE"))

        if password is None:
            password = os.environ.get("CRYPTOGRAPHY_PKCS11_PASSWORD")

        # TODO: close the session via gc?
        self._session = self._open_session(slot_id, flags)
        self._login(self._session, password)

        self._hash_mapping = {
            "md5": self._binding.CKM_MD5,
            "sha1": self._binding.CKM_SHA_1,
            "sha256": self._binding.CKM_SHA256,
            "sha384": self._binding.CKM_SHA384,
            "sha512": self._binding.CKM_SHA512,
        }

    def _open_session(self, slot_id, flags):
        # TODO: use the flags that are passed
        session_ptr = self._ffi.new("CK_SESSION_HANDLE *")
        flags = self._binding.CKF_SERIAL_SESSION | self._binding.CKF_RW_SESSION
        res = self._lib.C_OpenSession(
            slot_id, flags, self._ffi.NULL, self._ffi.NULL, session_ptr
        )
        self._check_error(res)
        return session_ptr[0]

    def _login(self, session, password):
        res = self._lib.C_Login(
            session, self._binding.CKU_USER, password, len(password)
        )
        self._check_error(res)

    def _check_error(self, return_code):
        if return_code != 0:
            raise SystemError("Expected CKR_OK, got {0}".format(return_code))

    def hash_supported(self, algorithm):
        return algorithm.name in self._hash_mapping

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)


backend = Backend()

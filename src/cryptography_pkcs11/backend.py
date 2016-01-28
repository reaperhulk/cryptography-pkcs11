# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import threading

from cryptography import utils
from cryptography.hazmat.backends.interfaces import HashBackend


from cryptography_pkcs11.binding import Binding
from cryptography_pkcs11.hashes import _HashContext


class PKCS11SessionPool(object):
    def __init__(self, backend, pool_size=10, slot_id=None, flags=None,
                 user_type=None, password=None):
        if slot_id is None:
            slot_id = int(os.environ.get("CRYPTOGRAPHY_PKCS11_SLOT_ID"))

        if slot_id is None:
            raise ValueError("slot_id must not be None")

        if flags is None:
            flags = int(os.environ.get("CRYPTOGRAPHY_PKCS11_FLAGS"))

        if flags is None:
            raise ValueError("flags must not be None")

        if user_type is None:
            user_type = int(os.environ.get("CRYPTOGRAPHY_PKCS11_USER_TYPE"))

        if user_type is None:
            raise ValueError("user_type must not be None")

        if password is None:
            password = os.environ.get("CRYPTOGRAPHY_PKCS11_PASSWORD")

        if password is None:
            raise ValueError("password must not be None")

        self._backend = backend

        # TODO: document that this semaphore is used to cause it to block
        # if the caller runs out of sessions.
        self._session_semaphore = threading.Semaphore(pool_size)
        self._session = []
        # TODO: set a min/max pool size. This will also need an increment size
        for _ in range(pool_size):
            session = self._open_session(slot_id, flags)
            self._login(session, password)
            self._session.append(session)

    def _open_session(self, slot_id, flags):
        # TODO: use the flags that are passed
        session_ptr = self._backend._ffi.new("CK_SESSION_HANDLE *")
        flags = (self._backend._binding.CKF_SERIAL_SESSION |
                 self._backend._binding.CKF_RW_SESSION)
        # TODO: close the session via gc?
        res = self._backend._lib.C_OpenSession(
            slot_id, flags, self._backend._ffi.NULL, self._backend._ffi.NULL,
            session_ptr
        )
        self._backend._check_error(res)
        return session_ptr[0]

    def _login(self, session, password):
        res = self._backend._lib.C_Login(
            session, self._backend._binding.CKU_USER, password, len(password)
        )
        # TODO: real error handling here. 0 is CKR_OK and 256 is
        # CKR_USER_ALREADY_LOGGED_IN. SoftHSM only requires you to log in
        # once per slot. I can't remember if that's true of Safenet, but I
        # don't think it is.
        if res != 0 and res != 256:
            raise SystemError("Failed to login")

    def acquire(self):
        self._session_semaphore.acquire()
        # TODO: this is not a good way to do this.
        return self._session.pop()

    def release(self, session):
        self._session_semaphore.release()
        return self._session.append(session)


@utils.register_interface(HashBackend)
class Backend(object):
    """
    PKCS11 API wrapper.
    """
    name = "pkcs11"

    def __init__(self, session_pool=None):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib
        if session_pool is None:
            self._session_pool = PKCS11SessionPool(self)

        self._hash_mapping = {
            "md5": self._binding.CKM_MD5,
            "sha1": self._binding.CKM_SHA_1,
            "sha256": self._binding.CKM_SHA256,
            "sha384": self._binding.CKM_SHA384,
            "sha512": self._binding.CKM_SHA512,
        }

    def _check_error(self, return_code):
        if return_code != 0:
            raise SystemError("Expected CKR_OK, got {0}".format(return_code))

    def hash_supported(self, algorithm):
        return algorithm.name in self._hash_mapping

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)


backend = Backend()

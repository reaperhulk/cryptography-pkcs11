# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import threading


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

        self._slot_id = slot_id
        self._password = password
        self._flags = flags

        self._backend = backend

        # TODO: document that this semaphore is used to cause it to block
        # if the caller runs out of sessions.
        self._session_semaphore = threading.Semaphore(pool_size)
        self._session = []
        # TODO: set a min/max pool size. This will also need an increment size
        for _ in range(pool_size):
            session = self._open_session(slot_id, flags)
            self._login(session[0], password)
            self._session.append(session)

    def _open_session(self, slot_id, flags):
        session_ptr = self._backend._ffi.new("CK_SESSION_HANDLE *")
        # TODO: revisit abusing cffi's gc to handle session management...
        session_ptr = self._backend._ffi.gc(session_ptr, self.release)
        res = self._backend._lib.C_OpenSession(
            slot_id, flags, self._backend._ffi.NULL, self._backend._ffi.NULL,
            session_ptr
        )
        self._backend._check_error(res)
        return session_ptr

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
        if not self._session_semaphore.acquire(blocking=False):
            # TODO: handle session exhaustion better. Not blocking is just
            # to prevent deadlocks...
            raise SystemError("Out of sessions")

        # TODO: this is not a good way to do this.
        session = self._session.pop()
        return session

    def acquire_and_init(self, backend, func, *args):
        session = self.acquire()
        res = func(session[0], *args)
        if res == 0x90:  # CKR_OPERATION_ACTIVE
            self.destroy(session)
            session = self.acquire()
            res = func(session[0], *args)

        backend._check_error(res)
        return session

    def release(self, session):
        new_sess = self._backend._ffi.new("CK_SESSION_HANDLE *", session[0])
        new_sess = self._backend._ffi.gc(new_sess, self.release)
        self._session.append(new_sess)
        self._session_semaphore.release()

    def destroy(self, session):
        # TODO: close the session being destroyed
        new_session = self._open_session(self._slot_id, self._flags)
        self._login(new_session[0], self._password)
        self._session.append(new_session)
        self._session_semaphore.release()

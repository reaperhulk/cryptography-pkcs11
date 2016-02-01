# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import threading
import weakref


class PKCS11Error(Exception):
    def __init__(self, msg, err_code):
        super(PKCS11Error, self).__init__(msg)
        self._err_code = err_code


class PKCS11Session(object):
    def __init__(self, backend, pool, slot_id, flags, user_type, password):
        self._pool = weakref.ref(pool)
        self._backend = backend
        session_ptr = self._backend._ffi.new("CK_SESSION_HANDLE *")
        res = self._backend._lib.C_OpenSession(
            slot_id, flags, self._backend._ffi.NULL, self._backend._ffi.NULL,
            session_ptr
        )
        self._backend._check_error(res)
        self._handle = session_ptr[0]
        res = self._backend._lib.C_Login(
            self._handle, user_type, password, len(password)
        )
        # TODO: real error handling here. 0 is CKR_OK and 256 is
        # CKR_USER_ALREADY_LOGGED_IN. SoftHSM only requires you to log in
        # once per slot. I can't remember if that's true of Safenet, but I
        # don't think it is.
        if res != 0 and res != 256:
            raise PKCS11Error("Failed to login", res)

    def __del__(self):
        if self._pool():
            self._pool().release(self)

    def __getitem__(self, idx):
        return self._handle


class PKCS11SessionPool(object):
    def __init__(self, backend, pool_size=10, slot_id=None, flags=None,
                 user_type=None, password=None):
        if pool_size <= 0:
            raise ValueError("pool_size must be greater than zero")

        if slot_id is None:
            slot_id = os.environ.get("CRYPTOGRAPHY_PKCS11_SLOT_ID")
            if slot_id is None:
                raise ValueError("slot_id must not be None")

        if flags is None:
            flags = os.environ.get("CRYPTOGRAPHY_PKCS11_FLAGS")
            if flags is None:
                raise ValueError("flags must not be None")

        if user_type is None:
            user_type = os.environ.get("CRYPTOGRAPHY_PKCS11_USER_TYPE")
            if user_type is None:
                raise ValueError("user_type must not be None")

        if password is None:
            password = os.environ.get("CRYPTOGRAPHY_PKCS11_PASSWORD")
            if password is None:
                raise ValueError("password must not be None")

        # We store all this so we can destroy/create new sessions.
        self._slot_id = int(slot_id)
        self._flags = int(flags)
        self._password = password
        self._user_type = int(user_type)
        self.pool_size = pool_size

        self._backend = backend

        # TODO: document that this semaphore is used to cause it to block
        # if the caller runs out of sessions.
        self._session_semaphore = threading.Semaphore(pool_size)
        self._session = []

        for _ in range(self.pool_size):
            session = PKCS11Session(
                self._backend, self, self._slot_id, self._flags,
                self._user_type, self._password
            )
            self._session.append(session)

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
        self._session.append(session)
        self._session_semaphore.release()

    def destroy(self, session):
        # TODO: close the session being destroyed
        session = PKCS11Session(
            self._backend, self, self._slot_id, self._flags,
            self._user_type, self._password
        )
        self._login(session[0])
        self._session.append(session)
        self._session_semaphore.release()

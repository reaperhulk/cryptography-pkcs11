# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

from cryptography.hazmat.primitives import hashes

import pytest

from cryptography_pkcs11.backend import backend
from cryptography_pkcs11.session_pool import PKCS11Error, PKCS11SessionPool


class TestPKCS11SessionPool(object):
    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "pool_size": 10, "slot_id": None, "flags": 6,
                "user_type": 1, "password": "pass"
            }, {
                "pool_size": 10, "slot_id": 0, "flags": None,
                "user_type": 1, "password": "pass"
            }, {
                "pool_size": 10, "slot_id": 0, "flags": 6,
                "user_type": None, "password": "pass"
            }, {
                "pool_size": 10, "slot_id": 0, "flags": 6,
                "user_type": 1, "password": None
            }, {
                "pool_size": 0, "slot_id": 0, "flags": 6,
                "user_type": 1, "password": "pass"
            }
        ]
    )
    def test_missing_init_values_no_env_vars(self, kwargs, monkeypatch):
        monkeypatch.setattr(os, "environ", {})
        with pytest.raises(ValueError):
            PKCS11SessionPool(
                backend, **kwargs
            )

    def test_failed_login(self, monkeypatch):
        """
        Tries to log in using an invalid user type
        """
        monkeypatch.setattr(os, "environ", {})
        with pytest.raises(PKCS11Error) as exc_info:
            PKCS11SessionPool(
                backend, pool_size=10, slot_id=0, flags=6,
                user_type=3, password="wrong"
            )

        assert exc_info.value.args[0] == "Failed to login"

    def test_destroy_session(self):
        """
        Inits a session for hashing, deletes the context, then immediately
        inits another one. Due to the way session management works this will
        give the second context the same session, which will fail with
        CKR_OPERATION_ACTIVE and trigger the destroy codepath.
        """
        ctx = hashes.Hash(hashes.SHA1(), backend)
        del(ctx)
        ctx = hashes.Hash(hashes.SHA1(), backend)
        ctx.update(b"test")
        assert ctx.finalize() == (
            b"\xa9J\x8f\xe5\xcc\xb1\x9b\xa6\x1cL\x08s\xd3\x91\xe9\x87\x98/\xbb"
            b"\xd3"
        )

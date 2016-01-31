# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography_pkcs11.session_pool import PKCS11SessionPool


class DummyBackend(object):
    pass


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
    def test_missing_init_values(self, kwargs):
        backend = DummyBackend()
        with pytest.raises(ValueError):
            PKCS11SessionPool(
                backend, **kwargs
            )

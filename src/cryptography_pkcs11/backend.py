# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import threading

from cryptography import utils
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, RSABackend
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import (
    MGF1, OAEP, PKCS1v15, PSS
)
from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES
from cryptography.hazmat.primitives.ciphers.modes import CBC, CTR, ECB

from cryptography_pkcs11.binding import Binding
from cryptography_pkcs11.ciphers import _CipherContext
from cryptography_pkcs11.hashes import _HashContext
from cryptography_pkcs11.key_handle import Attribute, build_attributes
from cryptography_pkcs11.rsa import _RSAPrivateKey, _RSAPublicKey


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
            self._login(session[0], password)
            self._session.append(session)

    def _open_session(self, slot_id, flags):
        # TODO: use the flags that are passed
        session_ptr = self._backend._ffi.new("CK_SESSION_HANDLE *")
        # TODO: revisit abusing cffi's gc to handle session management...
        session_ptr = self._backend._ffi.gc(session_ptr, self.release)
        flags = (self._backend._binding.CKF_SERIAL_SESSION |
                 self._backend._binding.CKF_RW_SESSION)
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

    def release(self, session):
        self._session_semaphore.release()
        new_sess = self._backend._ffi.new("CK_SESSION_HANDLE *", session[0])
        new_sess = self._backend._ffi.gc(new_sess, self.release)
        return self._session.append(new_sess)


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(RSABackend)
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
            "sha224": self._binding.CKM_SHA224,
            "sha256": self._binding.CKM_SHA256,
            "sha384": self._binding.CKM_SHA384,
            "sha512": self._binding.CKM_SHA512,
        }

    def _check_error(self, return_code):
        if return_code != 0:
            raise SystemError(
                "Expected CKR_OK, got {0}".format(hex(return_code))
            )

    def hash_supported(self, algorithm):
        return algorithm.name in self._hash_mapping

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def generate_rsa_private_key(self, public_exponent, key_size):
        # TODO: we need to be able to pass templates in. right now all keys
        # are generated as session only and exportable. And this is all
        # untested so far
        session = self._session_pool.acquire()
        public_handle = self._ffi.new("CK_OBJECT_HANDLE *")
        private_handle = self._ffi.new("CK_OBJECT_HANDLE *")
        mech = self._ffi.new("CK_MECHANISM *")
        mech.mechanism = self._binding.CKM_RSA_PKCS_KEY_PAIR_GEN
        pub_attrs = build_attributes([
            Attribute(
                self._binding.CKA_PUBLIC_EXPONENT,
                utils.int_to_bytes(public_exponent)
            ),
            Attribute(self._binding.CKA_MODULUS_BITS, key_size),
            Attribute(self._binding.CKA_TOKEN, True),  # don't persist it
            Attribute(self._binding.CKA_ENCRYPT, True),
            Attribute(self._binding.CKA_VERIFY, True),
            Attribute(self._binding.CKA_EXTRACTABLE, True)
        ], self)
        priv_attrs = build_attributes([
            Attribute(self._binding.CKA_TOKEN, False),  # don't persist it
            Attribute(self._binding.CKA_PRIVATE, True),
            Attribute(self._binding.CKA_SENSITIVE, False),
            Attribute(self._binding.CKA_ENCRYPT, True),
            Attribute(self._binding.CKA_DECRYPT, True),
            Attribute(self._binding.CKA_SIGN, True),
            Attribute(self._binding.CKA_VERIFY, True),
            Attribute(self._binding.CKA_EXTRACTABLE, True)
        ], self)
        # TODO: remember that you can get the public key values from
        # CKA_MODULUS and CKA_PUBLIC_EXPONENT. but you can't perform
        # operations on them so we probably still need to think of these as
        # keypairs
        res = self._lib.C_GenerateKeyPair(
            session[0], mech, pub_attrs.template, len(pub_attrs.template),
            priv_attrs.template, len(priv_attrs.template), public_handle,
            private_handle
        )
        self._check_error(res)

        return _RSAPrivateKey(self, private_handle[0])

    def rsa_padding_supported(self, padding):
        if isinstance(padding, PKCS1v15):
            return True
        elif isinstance(padding, PSS) and isinstance(padding._mgf, MGF1):
            return self.hash_supported(padding._mgf._algorithm)
        elif isinstance(padding, OAEP) and isinstance(padding._mgf, MGF1):
            return isinstance(padding._mgf._algorithm, hashes.SHA1)
        else:
            return False

    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        # TODO
        return False

    def load_rsa_private_numbers(self, numbers):
        attrs = build_attributes([
            Attribute(self._binding.CKA_TOKEN, False),  # don't persist it
            Attribute(self._binding.CKA_CLASS, self._binding.CKO_PRIVATE_KEY),
            Attribute(self._binding.CKA_KEY_TYPE, self._binding.CKK_RSA),
            Attribute(
                self._binding.CKA_MODULUS,
                utils.int_to_bytes(numbers.public_numbers.n)
            ),
            Attribute(
                self._binding.CKA_PUBLIC_EXPONENT,
                utils.int_to_bytes(numbers.public_numbers.e)
            ),
            Attribute(
                self._binding.CKA_PRIVATE_EXPONENT,
                utils.int_to_bytes(numbers.d)
            ),
            Attribute(
                self._binding.CKA_PRIME_1,
                utils.int_to_bytes(numbers.p)
            ),
            Attribute(
                self._binding.CKA_PRIME_2,
                utils.int_to_bytes(numbers.q)
            ),
            Attribute(
                self._binding.CKA_EXPONENT_1,
                utils.int_to_bytes(numbers.dmp1)
            ),
            Attribute(
                self._binding.CKA_EXPONENT_2,
                utils.int_to_bytes(numbers.dmq1)
            ),
            Attribute(
                self._binding.CKA_COEFFICIENT,
                utils.int_to_bytes(numbers.iqmp)
            ),
        ], self)

        session = self._session_pool.acquire()
        # TODO: do we want to delete the object from the session when it
        # is no longer in scope?
        object_handle = self._ffi.new("CK_OBJECT_HANDLE *")
        res = self._lib.C_CreateObject(
            session[0], attrs.template, len(attrs.template), object_handle
        )
        self._check_error(res)

        return _RSAPrivateKey(self, object_handle[0])

    def load_rsa_public_numbers(self, numbers):
        attrs = build_attributes([
            Attribute(self._binding.CKA_TOKEN, False),  # don't persist it
            Attribute(self._binding.CKA_CLASS, self._binding.CKO_PUBLIC_KEY),
            Attribute(self._binding.CKA_KEY_TYPE, self._binding.CKK_RSA),
            Attribute(
                self._binding.CKA_MODULUS, utils.int_to_bytes(numbers.n)
            ),
            Attribute(
                self._binding.CKA_PUBLIC_EXPONENT,
                utils.int_to_bytes(numbers.e)
            ),
        ], self)

        session = self._session_pool.acquire()
        # TODO: do we want to delete the object from the session when it
        # is no longer in scope?
        object_handle = self._ffi.new("CK_OBJECT_HANDLE *")
        res = self._lib.C_CreateObject(
            session[0], attrs.template, len(attrs.template), object_handle
        )
        self._check_error(res)

        return _RSAPublicKey(self, object_handle[0])

    def cipher_supported(self, cipher, mode):
        # TODO: softhsm only supports AES and 3DES with ECB/CBC
        return (
            isinstance(cipher, (AES, TripleDES)) and
            isinstance(mode, (ECB, CBC))
        )

    def create_symmetric_encryption_ctx(self, cipher, mode):
        operation = {
            "init": self._lib.C_EncryptInit,
            "update": self._lib.C_EncryptUpdate,
            "final": self._lib.C_EncryptFinal
        }
        return _CipherContext(self, cipher, mode, operation)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        operation = {
            "init": self._lib.C_DecryptInit,
            "update": self._lib.C_DecryptUpdate,
            "final": self._lib.C_DecryptFinal
        }
        return _CipherContext(self, cipher, mode, operation)


backend = Backend()

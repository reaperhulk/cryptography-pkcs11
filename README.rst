Cryptography-pkcs11
===================

.. image:: https://travis-ci.org/reaperhulk/cryptography-pkcs11.svg?branch=master
    :target: https://travis-ci.org/reaperhulk/cryptography-pkcs11

.. image:: https://codecov.io/github/reaperhulk/cryptography-pkcs11/coverage.svg?branch=master
    :target: https://codecov.io/github/reaperhulk/cryptography-pkcs11?branch=master

**At this time this should be considered experimental software and not ready
for any sort of production use.**

This is an experimental backend for using PKCS11 modules with `cryptography`_.
And when I say experimental I mean "do not touch this with a ten foot pole
right now".

Usage
-----

You'll need to set more than a few environment variables:

* CRYPTOGRAPHY_PKCS11_PATH - The path to the PKCS11 shared object
* CRYPTOGRAPHY_PKCS11_SLOT_ID
* CRYPTOGRAPHY_PKCS11_FLAGS
* CRYPTOGRAPHY_PKCS11_USER_TYPE
* CRYPTOGRAPHY_PKCS11_PASSWORD

If you want to test this with SoftHSM you'll also need ``SOFTHSM2_CONF``.

Then, if all is well you can import the backend and hash a thing.

.. code-block:: pycon

    >>> from cryptography_pkcs11.backend import backend


Supported Interfaces
--------------------

* HashBackend (except copy)
* HMACBackend (except copy)
* RSABackend (skipped tests)

  * ``test_pss_minimum_key_size_for_digest`` - The test uses SHA1 MGF1 and SHA512
    hash. SoftHSM doesn't allow your MGF1 hash to not match the signing hash
    algorithm.
  * ``test_pss_verify_salt_length_too_long`` - Errors during init when the test
    expects it to error during final verification.
  * ``test_pss_signing_salt_length_too_long`` - Errors during init when the test
    expects it to error during signing.

* CipherBackend (AES ECB/CBC, 3DES ECB/CBC only)

Issues
------

* Session management still needs improvement.

  * Session objects are presumed to be available to all sessions, which is
    only true if you don't close sessions.
  * No ``CKA_TOKEN`` False objects are ever deleted, so device memory will run
    out over time if you run the test suite repeatedly.
  * Sessions that generate exceptions during an active operation are destroyed
    and a new session is opened to take their place. This is a blocking
    operation.
* Generating or loading a key with ``CKA_TOKEN`` True is not supported at all
  yet.
* When adding the ``pkcs11`` entry point for multibackend it is injected as the
  first element in the array. This is probably not desirable.

.. _`cryptography`: https://cryptography.io/

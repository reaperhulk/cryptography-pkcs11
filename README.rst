Cryptography-pkcs11
===================

.. image:: https://travis-ci.org/reaperhulk/cryptography-pkcs11.svg?branch=master
    :target: https://travis-ci.org/reaperhulk/cryptography-pkcs11

.. image:: https://codecov.io/github/reaperhulk/cryptography-pkcs11/coverage.svg?branch=master
    :target: https://codecov.io/github/reaperhulk/cryptography-pkcs11?branch=master

**At this time this should be considered experimental software and not ready for
any sort of production use.**

This is an experimental backend for using PKCS11 modules with `cryptography`_. And when
I say experimental I mean "do not touch this with a ten foot pole right now".

Usage
-----

You'll need to set more than a few environment variables:

* CRYPTOGRAPHY_PKCS11_PATH - The path to the PKCS11 shared object
* CRYPTOGRAPHY_PKCS11_SLOT_ID
* CRYPTOGRAPHY_PKCS11_FLAGS
* CRYPTOGRAPHY_PKCS11_USER_TYPE
* CRYPTOGRAPHY_PKCS11_PASSWORD

If you want to test this with SoftHSM you'll also need `SOFTHSM2_CONF`.

Then, if all is well you can import the backend and hash a thing.

.. code-block:: pycon

    >>> from cryptography_pkcs11.backend import backend


Issues
------

* Very few backends are supported. None fully.
* Session management is still pretty terrible.
* Generating or loading a key with `CKA_TOKEN` True is not supported at all yet.
* Assumptions about the ability to share key handles across sessions are made.
  Whether this is true across all PKCS11 implementations is not clear.
* When adding the ``pkcs11`` entry point for multibackend it is injected as the
  first element in the array. This is probably not desirable.

.. _`cryptography`: https://cryptography.io/

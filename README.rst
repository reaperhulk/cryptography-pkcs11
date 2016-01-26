Cryptography-pkcs11
===================

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

* Right now only ``HashBackend`` is supported.
* When adding the ``pkcs11`` entry point for multibackend it is injected as the
  first element in the array. This is probably not desirable.
* It only barely works for hashes and there are a lot of broken edge cases due to
  PKCS11's love of session level state.

.. _`cryptography`: https://cryptography.io/

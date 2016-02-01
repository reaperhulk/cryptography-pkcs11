# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from contextlib import contextmanager

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import pytest

from cryptography_pkcs11.backend import backend


RSA_KEY_512 = rsa.RSAPrivateNumbers(
    p=int(
        "d57846898d5c0de249c08467586cb458fa9bc417cdf297f73cfc52281b787cd9", 16
    ),
    q=int(
        "d10f71229e87e010eb363db6a85fd07df72d985b73c42786191f2ce9134afb2d", 16
    ),
    d=int(
        "272869352cacf9c866c4e107acc95d4c608ca91460a93d28588d51cfccc07f449"
        "18bbe7660f9f16adc2b4ed36ca310ef3d63b79bd447456e3505736a45a6ed21", 16
    ),
    dmp1=int(
        "addff2ec7564c6b64bc670d250b6f24b0b8db6b2810099813b7e7658cecf5c39", 16
    ),
    dmq1=int(
        "463ae9c6b77aedcac1397781e50e4afc060d4b216dc2778494ebe42a6850c81", 16
    ),
    iqmp=int(
        "54deef8548f65cad1d411527a32dcb8e712d3e128e4e0ff118663fae82a758f4", 16
    ),
    public_numbers=rsa.RSAPublicNumbers(
        e=65537,
        n=int(
            "ae5411f963c50e3267fafcf76381c8b1e5f7b741fdb2a544bcf48bd607b10c991"
            "90caeb8011dc22cf83d921da55ec32bd05cac3ee02ca5e1dbef93952850b525",
            16
        ),
    )
)


@contextmanager
def raises_unsupported_algorithm(reason):
    with pytest.raises(UnsupportedAlgorithm) as exc_info:
        yield exc_info

    assert exc_info.value._reason is reason


class TestBackend(object):
    def test_unsupported_oaep_label(self):
        private_key = RSA_KEY_512.private_key(backend)
        with pytest.raises(ValueError):
            private_key.decrypt(
                b"0" * 64,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=b"label"
                )
            )

    def test_unsupported_mgf1_hash_algorithm(self):
        private_key = RSA_KEY_512.private_key(backend)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            private_key.decrypt(
                b"0" * 64,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

    def test_unsupported_oaep_hash_algorithm(self):
        private_key = RSA_KEY_512.private_key(backend)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            private_key.decrypt(
                b"0" * 64,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

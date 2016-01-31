#!/usr/bin/env python

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import sys

from setuptools import find_packages, setup


base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

about = {}
with open(os.path.join(src_dir, "cryptography_pkcs11", "__about__.py")) as f:
    exec(f.read(), about)


requirements = ["cryptography"]
setup_requirements = []
test_requirements = []


backends = [
    "pkcs11 = cryptography_pkcs11.backend:backend"
]

with open(os.path.join(base_dir, "README.rst")) as f:
    long_description = f.read()


setup(
    name=about["__title__"],
    version=about["__version__"],

    description=about["__summary__"],
    long_description=long_description,
    license=about["__license__"],
    url=about["__uri__"],

    author=about["__author__"],
    author_email=about["__email__"],

    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
    ],

    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=requirements,
    tests_require=test_requirements,
    extras_require={
        "docs-test": [
            "doc8",
            "pyenchant",
            "readme_renderer",
            "sphinx",
            "sphinx_rtd_theme",
            "sphinxcontrib-spelling",
        ],
        "pep8-test": [
            "flake8",
            "flake8-import-order",
            "pep8-naming",
        ],
    },
    ext_package="cryptography_pkcs11",
    zip_safe=True,
    entry_points={
        "cryptography.backends": backends,
    }
)

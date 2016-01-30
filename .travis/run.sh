#!/bin/bash

set -e
set -x

source ~/.venv/bin/activate

if [[ "$(uname -s)" == 'Darwin' ]]; then
    export LDFLAGS="/usr/local/opt/openssl/lib/libssl.a /usr/local/opt/openssl/lib/libcrypto.a"
    export CFLAGS="-I/usr/local/opt/openssl/include"
fi

tox

#!/bin/bash

set -e
set -x

mkdir -p $HOME/tokens
echo """directories.tokendir = $HOME/tokens
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
# log.level = DEBUG
#""" > $HOME/softhsm2.conf
if [[ "$(uname -s)" == 'Darwin' ]]; then
    brew update
    brew install softhsm
    curl -O https://bootstrap.pypa.io/get-pip.py
    python get-pip.py --user
    python -m pip install --user virtualenv
else
    sudo apt-add-repository -y ppa:pkg-opendnssec/ppa
    sudo apt-get update -qq
    sudo apt-get install libenchant-dev
    sudo apt-get install -y softhsm2
    pip install virtualenv
fi

softhsm2-util  --init-token --slot 0 --label testing --pin 1111 --so-pin 1234

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install tox codecov

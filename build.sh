#!/bin/sh

# Generate keys if not available yet
if [ ! -f common/cert.pem ] || [ ! -f common/key.pem ]; then
    cd common
    echo 'PEM keys need to be generated. Follow the prompt and enter information.'
    ./gen-ssl-cert.sh
    cd ..
fi

# Recursively make
make clean all

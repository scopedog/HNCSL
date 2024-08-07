#!/bin/sh

# Generate SSL keys

openssl req -nodes -new -x509 -keyout key.pem -out cert.pem

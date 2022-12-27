#!/bin/bash

python3 -m venv venv --system-site-packages
source venv/bin/activate
pip3 install -q -r requirements.txt

python3 ./update-udmpro-dns.py -N https://unifi.lan:443 -S unifi --verbose

deactivate
rm -rf ./venv

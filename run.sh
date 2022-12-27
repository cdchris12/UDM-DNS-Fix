#!/bin/bash

script_dir="$( dirname -- "$BASH_SOURCE"; )";
venv_dir="$(mktemp -d)"

python3 -m venv ${venv_dir} --system-site-packages
source ${venv_dir}/bin/activate
pip3 install -q -r ${script_dir}/requirements.txt

python3 ${script_dir}/update-udmpro-dns.py -N https://unifi.lan:443 -S unifi --verbose

deactivate
rm -rf ${venv_dir}

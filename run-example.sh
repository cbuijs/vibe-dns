#!/bin/bash

/usr/local/bin/python3.14 -m venv dns-filter-venv
source dns-filter-venv/bin/activate

pip install --upgrade pip

python3 server.py --config config.yaml

deactivate

exit 0


#!/bin/bash

/usr/local/bin/python3.14 -m venv dns-filter-venv
source dns-filter-venv/bin/activate

python3 server.py --config config.yaml

deactivate

exit 0


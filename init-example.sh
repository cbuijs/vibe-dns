#!/bin/bash

/usr/local/bin/python3.14 -m venv dns-filter-venv
source dns-filter-venv/bin/activate

pip install --upgrade pip
grep -vE "^(#.*|[[:blank:]]*)$" requirements.txt | awk -F"[>=]" '{ print $1 }' | xargs pip install --upgrade
pip freeze > requirements.freeze.txt

wget "https://ipinfo.io/data/ipinfo_lite.json.gz?_src=frontend&token=<TOKEN>" -O - | zcat > ipinfo_lite.json
python3 geoip_compiler.py --json ipinfo_lite.json --unified-output geoip_unified.db --export-rules geoip.txt

deactivate

exit 0


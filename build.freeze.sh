#!/bin/sh

rm frozen_requirements.txt
rm -rf build/freeze/freeze_env/
mkdir -p build/freeze
python3 -m venv build/freeze/freeze_env/
# shellcheck disable=SC1091
. build/freeze/freeze_env/bin/activate
pip3 --disable-pip-version-check -q install wheel
pip3 --disable-pip-version-check -q install -r requirements.txt
pip3 --disable-pip-version-check -q freeze -l > frozen_requirements.txt

rm frozen_test_requirements.txt
rm -rf build/freeze/freeze_env/
mkdir -p build/freeze
python3 -m venv build/freeze/freeze_env/
# shellcheck disable=SC1091
. build/freeze/freeze_env/bin/activate
pip3 --disable-pip-version-check -q install wheel
pip3 --disable-pip-version-check -q install -r test_requirements.txt
pip3 --disable-pip-version-check -q freeze -l > frozen_test_requirements.txt

#!/bin/sh

python3 -m twine upload --skip-existing --non-interactive -u "__token__" -p "$TWINE_PASSWORD_TEST" --repository-url "https://test.pypi.org/legacy/" dist/*

echo -n "Look good (y/n)? "
read answer
if [ "$answer" != "${answer#[Yy]}" ] ;then
    python3 -m twine upload --skip-existing --non-interactive -u "__token__" -p "$TWINE_PASSWORD" ./dist/*
fi
"""setup.py: setuptools control."""


import re
from setuptools import setup


version = re.search(
    r'(VERSION = "(\d.\d.\d)")',
    open("pvpn_cli/constants.py").read(),
    re.M
    ).group(2)


with open("README.md", "rb") as f:
    long_descr = f.read().decode("utf-8")


setup(
    name="pvpn_cli",
    packages=["pvpn_cli"],
    entry_points={
        "console_scripts": ["protonvpn-cli = pvpn_cli.cli:main"]
        },
    version=version,
    data_files=[("pvpn_cli", ["pvpn_cli/country_codes.json"])],
    description="Linux command-line client for ProtonVPN",
    long_description=long_descr,
    author="Proton Technologies AG",
    author_email="contact@protonvpn.com",
    license="GPLv3",
    url="https://github.com/protonvpn/protonvpn-cli-ng",
    install_requires=[
        "requests",
        "docopt",
        "pythondialog",
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
)

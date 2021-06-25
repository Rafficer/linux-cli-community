"""setup.py: setuptools control."""


import re
import os
from setuptools import setup

try:
    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md'), encoding='utf-8') as f:
        long_descr = '\n' + f.read()
except FileNotFoundError:
    long_descr = """
    The official Linux CLI for ProtonVPN.

    For further information and a usage guide, please view the project page:

    https://github.com/ProtonVPN/linux-cli
    """

version = re.search(
    r'(VERSION = "(\d.\d.\d+)")',
    open("protonvpn_cli/constants.py").read(),
    re.M
).group(2)

setup(
    name="protonvpn_cli",
    packages=["protonvpn_cli"],
    entry_points={
        "console_scripts": ["protonvpn = protonvpn_cli.cli:main"]
    },
    include_package_data=True,
    version=version,
    description="Linux command-line client for ProtonVPN",
    long_description=long_descr,
    long_description_content_type="text/markdown",
    author="Proton Technologies AG",
    author_email="contact@protonvpn.com",
    license="GPLv3",
    url="https://github.com/protonvpn/linux-cli-community",
    package_data={
        "protonvpn_cli": ["templates/*"]
    },
    install_requires=[
        "requests",
        "docopt",
        "pythondialog",
        "jinja2",
        "distro",
    ],
    python_requires=">=3.5",
    classifiers=[
        "Development Status :: 4 - Beta",
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

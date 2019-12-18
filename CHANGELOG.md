# ProtonVPN-CLI Changelog

## Table of Contents

- [ProtonVPN-CLI Changelog](#protonvpn-cli-changelog)
  - [Table of Contents](#table-of-contents)
  - [v2.2.0](#v220)
  - [v2.1.2](#v212)
  - [v2.1.1](#v211)
  - [v2.1.0](#v210)
  - [v2.0.0](#v200)
  - [v0.1.0](#v010)

## v2.2.0

  - Feature: Wait for connection when using auto-connect
  - Enhancement: Option to allow access to LAN with Kill Switch
  - Enhancement: Inform user about this document when displaying update notification
  - Bug fix: Potential IPv6 leak when reconnecting the network interface with an active connection
  - Bug fix: Error when trying to connect after reinitializing the profile with an active connection
  - Bug fix: Configuration value spelling when changing default protocol
  - Bug fix: Wrong API in update check

## v2.1.2

- Enhancement: Clearer logging of command line arguments
- Enhancement: Improved version printout (`protonvpn -v`)
- Bug fix: Not following `/etc/resolv.conf` symlinks
- Bug fix: Crash when using `protonvpn connect <servername>` with an invalid servername
- Bug fix: Wrong status printout when Kill Switch is active
- Documentation: Remove duplicate information from USAGE.md in README.md and shorten it
- Documentation: Add installation guide for Python virtual environments
- Documentation: Add setuptools dependency

## v2.1.1

- Enhancement: Better dialog for changing DNS management settings
- Bug fix: Fixed spelling of "Kill Switch" throughout the program
- Documentation: Addition of an extensive usage guide
- Documentation: Addition of a changelog

## v2.1.0

- Enhancement: Server tiers in dialog menu
- Bug fix: Active Kill Switch was blocking `protonvpn reconnect`
- Bug fix: Kill Switch preventing access to localhost
- Bug fix: Typos in prints
- Documentation: Adding install instructions for SUSE
- Documentation: Fix pip syntax for updating the program
- Misc: python_requires attribute in setup.py

## v2.0.0

- Initial release

## v0.1.0

- Pre-Release for claiming the project on [PyPI](https://pypi.org)

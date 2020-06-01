# ProtonVPN-CLI Changelog

## Table of Contents

- [v2.2.4](#v224)
- [v2.2.3](#v223)
- [v2.2.2](#v222)
- [v2.2.1](#v221)
- [v2.2.0](#v220)
- [v2.1.2](#v212)
- [v2.1.1](#v211)
- [v2.1.0](#v210)
- [v2.0.0](#v200)
- [v0.1.0](#v010)

## v2.2.4

- Bug fix: Failing to connect when choosing a server via dialog menu

## v2.2.3

- Enhancement: Option to define API domain via config
- Enhancement: Improve wording on connection failure
- Bug fix: Error during connection when IPv6 is disabled system-wide
- Bug fix: Unable to change DNS in containers
- Bug fix: `pgrep` not working on some distros

## v2.2.2

- Enhancement: Display usage statistics in status
- Bug fix: Kill Switch activation failed due to missing configuration value

## v2.2.1

- Enhancement: Switch API endpoint to api.protonvpn.ch
- Enhancement: Disallow usage of Kill Switch and Split Tunneling simultaneously
- Bug fix: Wrong indentation in multiple print statements
- Bug fix: Failed to detect that it was executed by root on certain Distros
- Bug fix: Error when try to use `protonvpn status` and connected to a Tor server
- Bug fix: Error when an invalid server selection was made
- Bug fix: Error on Split Tunneling activation when no IPs were entered
- Bug fix: False positives in OpenVPN process detection
- Documentation: Added Contribution Guide

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

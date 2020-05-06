<h1 align="center">ProtonVPN-CLI</h1>
<p align="center">
  <img src="https://i.imgur.com/tDrwkX5l.png" alt="Logo"></img>
</p>

<p align="center">
    <a href="https://pepy.tech/project/protonvpn-cli"><img alt="Downloads" src="https://pepy.tech/badge/protonvpn-cli"></a>
    <img alt="GitHub" src="https://img.shields.io/github/license/ProtonVPN/linux-cli">
    <a href="https://pepy.tech/project/protonvpn-cli/week"><img alt="Downloads per Week" src="https://pepy.tech/badge/protonvpn-cli/week"></a>
    <br>
    <a href="https://twitter.com/ProtonVPN"><img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/ProtonVPN?style=social"></a>
    <a href="https://www.reddit.com/r/ProtonVPN"><img alt="Subreddit subscribers" src="https://img.shields.io/reddit/subreddit-subscribers/ProtonVPN?label=Join%20r%2FProtonVPN&style=social"></a>
</p>

<h3 align="center">A Linux CLI for ProtonVPN. Written in Python.</h3>

ProtonVPN-CLI is a full rewrite of the [bash protonvpn-cli](https://github.com/ProtonVPN/protonvpn-cli/blob/master/protonvpn-cli.sh) in Python, which adds more features and functionality with the purpose of improving readability, speed and reliability.

## Installation & Updating

For more detailed information on installing, updating and uninstalling, please view the extensive [usage guide](https://github.com/ProtonVPN/linux-cli/blob/master/USAGE.md#installation--updating).

### Installing Dependencies

**Dependencies:**

- openvpn
- dialog (optional, needed for interactive selection)
- pip for python3 (pip3)
- python3.5+
- setuptools for python3 (python3-setuptools)

Depending on your distribution, run the appropriate following command to install the necessary dependencies

| **Distro**                              | **Command**                                                        |
|:----------------------------------------|:------------------------------------------------                   |
|Fedora/CentOS/RHEL                       | `sudo dnf install -y openvpn dialog python3-pip python3-setuptools`|
|Ubuntu/Linux Mint/Debian and derivatives | `sudo apt install -y openvpn dialog python3-pip python3-setuptools`|
|OpenSUSE/SLES                            | `sudo zypper in -y openvpn dialog python3-pip python3-setuptools`  |
|Arch Linux/Manjaro                       | `sudo pacman -S openvpn dialog python-pip python-setuptools`       |

### Installing ProtonVPN-CLI

Installation happens via Python's package manager PIP.

*Note: Make sure to run pip with sudo, so it installs globally and recognizes the command with sudo*

`sudo pip3 install protonvpn-cli`

### Updating ProtonVPN-CLI

`sudo pip3 install protonvpn-cli --upgrade`

### Manual Installation from source

*Disclaimer: If you are unsure about what you're doing, please follow the [normal installation guide](https://github.com/ProtonVPN/linux-cli/blob/master/USAGE.md#installation--updating).*

It is recommended to do the manual installation in a virtual environment. Especially if it serves the purpose of developing.

1. Clone this repository

    `git clone https://github.com/protonvpn/linux-cli`

2. Step into the directory

   `cd linux-cli`

3. Install

    `pip3 install -e .`

For updating, you just need to pull the latest version of the repository with git.

### How to use

#### For more detailed information, see the extensive [usage guide](https://github.com/ProtonVPN/linux-cli/blob/master/USAGE.md).

| **Command**                       | **Description**                                       |
|:----------------------------------|:------------------------------------------------------|
|`protonvpn init`                   | Initialize ProtonVPN profile.                         |
|`protonvpn connect, c`             | Select a ProtonVPN server and connect to it.          |
|`protonvpn c [servername]`         | Connect to a specified server.                        |
|`protonvpn c -r`                   | Connect to a random server.                           |
|`protonvpn c -f`                   | Connect to the fastest server.                        |
|`protonvpn c --p2p`                | Connect to the fastest P2P server.                    |
|`protonvpn c --cc [countrycode]`   | Connect to the fastest server in a specified country. |
|`protonvpn c --sc`                 | Connect to the fastest Secure Core server.            |
|`protonvpn reconnect, r`           | Reconnect or connect to the last server used.         |
|`protonvpn disconnect, d`          | Disconnect the current session.                       |
|`protonvpn status, s`              | Print connection status.                              |
|`protonvpn configure`              | Change CLI configuration.                             |
|`protonvpn refresh`                | Refresh OpenVPN configuration and server data.        |
|`protonvpn examples`               | Print example commands.                               |
|`protonvpn --version`              | Display version.                                      |
|`protonvpn --help`                 | Show help message.                                    |

All connect options can be used with the `-p` flag to explicitly specify which transmission protocol is used for that connection (either `udp` or `tcp`).

## Contributing

If you want to contribute to this project, please read the [contribution guide](https://github.com/ProtonVPN/linux-cli/blob/master/CONTRIBUTING.md).

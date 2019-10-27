# ProtonVPN-CLI

![protonvpn-cli](https://i.imgur.com/tDrwkX5l.png)

### A Linux CLI for ProtonVPN. Written in Python.

ProtonVPN-CLI is a full rewrite of the [bash protonvpn-cli](https://github.com/ProtonVPN/protonvpn-cli/blob/master/protonvpn-cli.sh) in Python, which adds more features and functionality with the purpose of improving readability, speed and reliability.

## Installation and Updating

### Installation

**Dependencies:**

* openvpn
* dialog (optional, needed for interactive selection)
* python3.5+
* pip for python3 (pip3)

On Fedora/CentOS/RHEL:

`sudo dnf install -y openvpn dialog python3-pip`

`sudo pip3 install protonvpn-cli`

On Debian/Ubuntu/Linux Mint and derivatives:

`sudo apt install -y openvpn dialog python3-pip`

`sudo pip3 install protonvpn-cli`

On SUSE:

`sudo zypper in -y openvpn dialog python3-pip`

`sudo pip3 install protonvpn-cli`

On Arch/Manjaro:

`sudo pacman -S openvpn dialog python-pip`

`sudo pip3 install protonvpn-cli`

Make sure to run pip as sudo, so it installs globally and recognizes the command with sudo.

### Updating

Updating works via PIP as well

`sudo pip3 install protonvpn-cli --upgrade`

### Manual Installation from source

1. Clone this repository or download the zip file

    `git clone https://github.com/protonvpn/protonvpn-cli-ng`

    or

    `unzip protonvpn-cli-ng-master.zip`

2. Step into the directory
   
   `cd protonvpn-cli-ng`

3. Install (make sure to use sudo to install globally)

    `sudo pip3 install .`

## How to use

### Brief list of commands

| **Command**                       | **Description**                                       |
|:----------------------------------|:------------------------------------------------------|
|`protonvpn init`                   | Initialize ProtonVPN profile.                         |
|`protonvpn connect, c`             | Select a ProtonVPN server and connect to it.          |
|`protonvpn c [servername]`         | Connect to a specified server.                        |
|`protonvpn c -r`                   | Connect to a random server.                           |
|`protonvpn c -f`                   | Connect to the fastest server.                        |
|`protonvpn c --p2p`                | Connect to the fastest P2P server.                    |
|`protonvpn c --cc [countrycode]`   | Connect to the fastest server in a specified country. |
|`protonvpn c --sc`                 | Connect to the fastest Secure-Core server.            |
|`protonvpn reconnect, r`           | Reconnect or connect to the last used server.         |
|`protonvpn disconnect, d`          | Disconnect the current session.                       |
|`protonvpn status, s`              | Print connection status.                              |
|`protonvpn configure`              | Change CLI configuration.                             |
|`protonvpn refresh`                | Refresh OpenVPN configuration and server data.        |
|`protonvpn examples`               | Print example commands.                               |
|`protonvpn --version`              | Display version.                                      |
|`protonvpn --help`                 | Show help message.                                    |

All connect options can be used with the `-p` flag to explicitly specify the Protocol (either `udp` or `tcp`).
### Extensive explanation

You can see the full list of commands by running `protonvpn --help` and a list of examples by running `protonvpn examples`.

**Most of the commands need to be run as root, so use sudo with the commands in this guide!**

Before using any other commands, you need to initialize your profile:

`protonvpn init`

To connect to a server you always need the `connect` option (or just `c`):

`protonvpn connect`

Running it just like that will give you a menu that let's you select the country, server and protocol interactively:

![country-selection](https://i.imgur.com/lRwx67E.png)

![server-selection](https://i.imgur.com/lRwx67E.png)

If you specify a server name after connect, you can directly connect to a server of your choice:

`protonvpn connect US-NY#6`

The server name can be written in a few different ways. For example, `usny6`, `us-ny-6` or `usny-06` are all valid formats.

To connect to the fastest server, you can use the `--fastest` or `-f` flag:

`protonvpn c --fastest`

`protonvpn c -f`

You can use the `--random` or `-r` flag to connect to a random server:

`protonvpn c -r`

There are a few methods of fastest connect. You can connect to the fastest server of a country, the fastest Secure-Core server, the fastest P2P server or the fastest Tor server.

Fastest server in a country (replace UK with the code of the desired country, e.g. `US` for USA, `JP` for Japan, `AU` for Australia, etc.):

`protonvpn c --cc UK`

Fastest Secure-Core server:

`protonvpn c --sc`

Fastest P2P/torrent server:

`protonvpn c --p2p`

Fastest Tor server:

`protonvpn c --tor`

All connection methods (except the interactive menu) can be used with the `-p` flag to choose a protocol. Possible values are either `TCP` or `UDP` If that flag is not used it will use the default protcol specified in the initialization:

Connect to the fastest server with TCP:

`protonvpn c -f -p TCP`

Connect to a random server with UDP:

`protonvpn c -rp UDP`

To disconnect the VPN, you need to use the `disconnect` or `d` option:

`protonvpn disconnect`

`protonvpn d`

If you're having trouble with your connection, e.g. because you switched networks or your device woke up from sleeping, you can easily reconnect to the last server with the `reconnect` or `r` option:

`protonvpn reconnect`

`protonvpn r`

If you want to see the status and information of your current connection, you can use the `status` or `s` option, which doesn't require root:

`protonvpn status`

`protonvpn s`

![status-example](https://i.imgur.com/8YRp2oS.png)

If you want to change different values that you've set during initialization, you can do this with the `configure` option, just follow the prompts to change your username/password, default protocol and so on:

`protonvpn configure`

![configuration-example](https://i.imgur.com/JjdoPm7.png)

## Uninstallation

If you want to uninstall ProtonVPN-CLI, run `configure` first and purge the configuration. Then uninstall through the package manager you used for installation.

For PIP this would be

`sudo pip3 uninstall protonvpn-cli`

Bye Bye 😔

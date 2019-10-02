# ProtonVPN-CLI

![protonvpn-cli](https://i.imgur.com/tDrwkX5l.png)

## *Disclaimer*

**!! This is a work in progress and not considered production ready at this stage. Use at your own risk. !!**

### A Linux CLI for ProtonVPN. Written in Python.

ProtonVPN-CLI is a full rewrite of the [bash protonvpn-cli](https://github.com/ProtonVPN/protonvpn-cli/blob/master/protonvpn-cli.sh) in Python to improve readability, speed and reliability as well as add more functionality and features.

## Installation and Updating

*WIP - Likely via PIP*

Required system packages:

* openvpn
* dialog (optional, needed for interactive selection)

On Fedora/CentOS/RHEL:

`sudo dnf install -y openvpn dialog`

On Debian/Ubuntu/Linux Mint and derivatives:

`sudo apt install -y openvpn dialog`

On Arch/Manjaro:

`sudo pacman -S openvpn dialog`

## How to use

You can see a full set of commands and examples by running `pvpn-cli --help`.

**Most of the commands need to be run as root, so use sudo with the commands in this guide!**

Before using any other commands, you need to initialize your profile:

`pvpn-cli init`

To connect to a server you always need the `connect` option (or just `c`):

`pvpn-cli connect`

Running it just like that will give you a menu that let's you select the country, server and protocol interactively:

![country-selection](https://i.imgur.com/7WGmwbN.png)

![server-selection](https://i.imgur.com/jbXP43z.png)

If you specify a servername after connect, you can directly connect to a server of your choice:

`pvpn-cli connect US-NY#6`

The servername can be written in a few different formats. `usny6`, `us-ny-6`, `usny-06` all work.

To connect to the fastest server, you can use the `--fastest` or `-f` flag:

`pvpn-cli c --fastest`

`pvpn-cli c -f`

There's also a flag to connect to a completely random server, `--random` or `-r`:

`pvpn-cli c -r`

There are a few methods of fastest connect. You can connect to the fastest server of a country, the fastest Secure-Core server, the fastest P2P server or the fastest Tor server.

Fastest server in a country (replace UK with the code of the desired country, e.g. `US` for USA, `JP` for Japan, `AU` for Australia, etc.):

`pvpn-cli c --cc UK`

Fastest Secure-Core server:

`pvpn-cli c --sc`

Fastest P2P/torrent server:

`pvpn-cli c --p2p`

Fastest Tor server:

`pvpn-cli c --tor`

All connection methods (except the interactive menu) can be used with the `-p` flag to choose a protocol. Possible values are either `TCP` or `UDP` If that flag is not used it will use the default protcol specified in the initialization:

Connect to the fastest server with TCP:

`pvpn-cli c -f -p TCP`

Connect to a random server with UDP:

`pvpn-cli c -rp UDP`

To disconnect the VPN, you need to use the `disconnect` or `d` option:

`pvpn-cli disconnect`

`pvpn-cli d`

If you're having trouble with your connection, e.g. because you switched networks or your device woke up from sleeping, you can easily reconnect to the last server with the `reconnect` or `r` option:

`pvpn-cli reconnect`

`pvpn-cli r`

If you want to see the status and information of your current connection, you can use the `status` or `s` option, which doesn't require root:

`pvpn-cli status`

`pvpn-cli s`

![status-example](https://i.imgur.com/RBUG2C3.png)

If you want to change different values that you've set during initialization, you can do this with the `configure` option, just follow the prompts to change your username/password, default protocol and so on:

`pvpn-cli configure`

Finally, to uninstall pvpn-cli, use the `uninstall` option. It will entirely remove the program and configuration from your device 😔:

`pvpn-cli uninstall`


## Getting started (dev)

These instructions will help you to get a copy of the project up and running on your local environment for development, testing and verification purposes.

### Prerequisites

System packages:

* Python 3.5+
* pip
* openvpn
* dialog

Python Packages:

* docopt
* requests
* pythondialog

### Installation

1. Clone this project:

    `git clone https://github.com/rafficer/pvpn-cli`

2. Install the virtualenv package

    `pip3 install virtualenv`

3. Create a virtual environment

    `cd pvpn-cli`
    
    `virtualenv .venv`

4. Enter the virtualenv

    `source .venv/bin/activate`

5. Install the necessary python packages

    `pip3.7 install --user -r requirements.txt`

6. You can the use it by running
    
    `sudo .venv/bin/python -m pvpn_cli <options>`

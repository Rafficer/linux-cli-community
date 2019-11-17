# ProtonVPN-CLI Usage Documentation

This document provides an extensive guide on how to install and use ProtonVPN-CLI as well as explanations about advanced features and optional enhancements.

## Table of Contents

- [ProtonVPN-CLI Usage Documentation](#protonvpn-cli-usage-documentation)
  - [Table of Contents](#table-of-contents)
  - [Installation & Updating](#installation--updating)
    - [Installing Dependencies](#installing-dependencies)
    - [Installing ProtonVPN-CLI](#installing-protonvpn-cli)
    - [Updating ProtonVPN-CLI](#updating-protonvpn-cli)
    - [Initialization](#initialization)
    - [Uninstallation](#uninstallation)
    - [Example Installation on Ubuntu 18.04](#example-installation-on-ubuntu-1804)
  - [Commands](#commands)
    - [List of all Commands](#list-of-all-commands)
    - [Command Explanations](#command-explanations)
  - [Features](#features)
    - [DNS Management](#dns-management)
      - [DNS Leak Protection](#dns-leak-protection)
      - [Custom DNS](#custom-dns)
      - [Disabling DNS Management](#disabling-dns-management)
    - [IPv6 Leak Protection](#ipv6-leak-protection)
    - [Kill Switch](#kill-switch)
    - [Split Tunneling](#split-tunneling)
  - [Enhancements](#enhancements)
    - [Disable sudo password query](#disable-sudo-password-query)
    - [Configure alias for quicker access](#configure-alias-for-quicker-access)
    - [Auto-connect on boot](#auto-connect-on-boot)
      - [via Systemd Service](#via-systemd-service)

## Installation & Updating

### Installing Dependencies

**Dependencies:**

- openvpn
- dialog (optional, needed for interactive selection)
- pip for python3 (pip3)
- python3.5+

Run the following command to install the dependencies on your distribution

| **Distro**                              | **Command**                                     |
|:----------------------------------------|:------------------------------------------------|
|Fedora/CentOS/RHEL                       | `sudo dnf install -y openvpn dialog python3-pip`|
|Ubuntu/Linux Mint/Debian and derivatives | `sudo apt install -y openvpn dialog python3-pip`|
|OpenSUSE/SLES                            | `sudo zypper in -y openvpn dialog python3-pip`  |
|Arch Linux/Manjaro                       | `sudo pacman -S openvpn dialog python-pip`      |

### Installing ProtonVPN-CLI

Installation happens via Python's package manager PIP.

*Note: Make sure to run pip with sudo, so it installs globally and recognizes the command with sudo*

`sudo pip3 install protonvpn-cli`

### Updating ProtonVPN-CLI

`sudo pip3 install protonvpn-cli --upgrade`

### Initialization

Before being able to use ProtonVPN-CLI you need to initialize it. For this run `sudo protonvpn init` and follow the prompts on the screen.

### Uninstallation

If you want to uninstall ProtonVPN-CLI, run `configure` first and purge the configuration. Then uninstall through the package manager you used for installation.

For PIP this would be

`sudo pip3 uninstall protonvpn-cli`

Bye Bye 😔

### Example Installation on Ubuntu 18.04

1. Installing dependencies

    To install ProtonVPN-CLI's dependencies, open a terminal and type `sudo apt install -y dialog openvpn python3-pip` and confirm with Enter. Wait for the installations to finish

2. Installing ProtonVPN-CLI

    To install ProtonVPN-CLI type `sudo pip3 install protonvpn-cli` in the terminal and confirm with Enter again. This should look something like this:

    ![ubuntu-pip-install](https://i.imgur.com/jSuftoe.png)

3. Initialize the ProtonVPN profile

    Now you have access to the `protonvpn` command. Before using ProtonVPN-CLI you need to initialize your profile. For this type `sudo protonvpn init`

    This will first ask you for your OpenVPN username and password. You can find them on https://account.protonvpn.com/account

    ![openvpn-pass](https://i.imgur.com/EdZ01T9.png)

    Enter these details in the prompts

    ![ubuntu-pass-entry](https://i.imgur.com/Vrcq2oO.png)

    Next you need to select your plan. If you are a trial user currently, select `3) Plus`.

    ![ubuntu-plan](https://i.imgur.com/oQpgeSo.png)

    *IMPORTANT: after the trial expires, you need to reconfigure your plan to 1) Free. To set this up, enter `sudo protonvpn configure`. Then select `2) ProtonVPN Plan`. Finally, select `1) Free`.*

    Now you need to choose the default protocol you want to use. UDP is typically the faster option, while TCP is a more reliable protocol that's better suited for unstable connections and in restricted networks. The default selection is UDP.

    ![ubuntu-proto](https://i.imgur.com/qmcebSO.png)

    Finally, confirm your input with `y`

    ![ubuntu-confirm](https://i.imgur.com/P6nRR4u.png)

4. Connect to ProtonVPN

    Now you can connect to ProtonVPN. For example, you can let ProtonVPN-CLI find the fastest server for you. Just type `sudo protonvpn connect -f` and a connection will be established.

    ![ubuntu-connected](https://i.imgur.com/VJVacKe.png)

## Commands

### List of all Commands

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

### Command Explanations

You can see the full list of commands by running `protonvpn --help` and a list of examples by running `protonvpn examples`.

**Most of the commands need to be run as root, so use sudo with the commands in this guide!**

Before using any other commands, you need to initialize your profile:

`protonvpn init`

To connect to a server you always need the `connect` option (or just `c`):

`protonvpn connect`

Running it just like that will give you a menu that let's you select the country, server and protocol interactively:

![country-selection](https://i.imgur.com/jjJh09J.png)

![server-selection](https://i.imgur.com/uXfcHMI.png)

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

![status-example](https://i.imgur.com/5tm5nOJ.png)

If you want to change different values that you've set during initialization, you can do this with the `configure` option, just follow the prompts to change your username/password, default protocol and so on:

`protonvpn configure`

![configuration-example](https://i.imgur.com/tHSkBxk.png)

## Features

### DNS Management

#### DNS Leak Protection

ProtonVPN-CLI features a DNS Leak Protection feature, which makes sure that you will use ProtonVPN's DNS Servers. This protects you from third parties (like your ISP) being able to see your DNS queries and therefore invading your privacy.

ProtonVPN-CLI accomplishes this by updating the `/etc/resolv.conf` file when you connect to a VPN server and make sure that only ProtonVPN's DNS Server is written in this file. It will also backup the previous state of `/etc/resolv.conf` to revert all changes upon disconnection.

Please note that when you change network (different Wifi) while being connected, `/etc/resolv.con` can be updated by your system. This can cause DNS leaks, so for best security, use `protonvpn reconnect` after changing network.

**Enabling DNS Leak Protection**

To enable DNS Leak Protection use the `protonvpn configure` command, then press `4` to choose DNS Management. Then press `1` to choose that you want to enable DNS Leak Protection.

From now on your DNS queries are secured.

#### Custom DNS

If you always want to use a custom DNS Server when you connect to ProtonVPN, ProtonVPN-CLI allows you to do this as well. You can add up to 3 custom DNS Servers.

**Enabling Custom DNS**

To enable DNS Leak Protection use the `protonvpn configure` command, then press `4` to choose DNS Management. Then press `2` to choose that you want to configure custom DNS Servers. Now enter the IPs of up to 3 DNS Servers you want to use and confirm with Enter.

#### Disabling DNS Management

If you don't want ProtonVPN-CLI to do any changes to your DNS, you can do this as well. This will cause ProtonVPN-CLI to not touch `/etc/resolv.conf` and your device will always use the DNS servers configured by you or through your network.

**Disabling any DNS management**

To enable DNS Leak Protection use the `protonvpn configure` command, then press `4` to choose DNS Management. Then press `3` to disable any DNS management.

### IPv6 Leak Protection

ProtonVPN-CLI features an IPv6 Leak Protection feature. It makes sure that your IPv6 address doesn't get leaked when connecting to a ProtonVPN server.

This feature is enabled by default and for security reasons can't be disabled.

It works by detecting the IPv6 address, backing it up and removing it from the default interface. When disconnecting it adds the IPv6 address back to the default interface and deleting the backup.

### Kill Switch

ProtonVPN-CLI has a built-in Kill Switch that protects your data in a case where your VPN connection would go down unexptectedly.

It works by replacing your existing iptables rules with custom rules that only allow data to go over the OpenVPN interface when the VPN connection is established. When disconnecting ProtonVPN-CLI will revert iptables to it's previous state.

**Enabling the Kill Switch**

To enable the Kill Switch, open the configuration menu with `protonvpn configure`, then select `5` for the Kill Switch and confirm the activation with `y`. On the next connection the Kill Switch will be enabled.

*Note: The Kill Switch only activates on unexptected connection drops. It will not persist through reboots and not activate when calling `protonvpn disconnect`. To simulate the Kill Switch, kill the OpenVPN process while connected with `sudo pkill openvpn`.*

### Split Tunneling

ProtonVPN-CLI features IP-based split tunneling. This means that you can exclude specific IPs or networks from being routed over the VPN tunnel.

*Note: Split Tunneling does not work when the Kill Switch is enabled.*

**Enable Split Tunneling**

To enable Split Tunneling, open the configuration menu with `protonvpn configure`, then select Split Tunneling with `6`. Then confirm with `y`.

Now add the IPs you want (one IP at a time) or networks in [CIDR notation](https://www.ipaddressguide.com/cidr).

If you want to have a big list of IPs or networks that you want to exclude, it is recommended to add one IP via above mentioned method, this will create the file `~/.pvpn-cli/split_tunnel.txt`. You can then paste the IPs or networks in CIDR notation in this file, one IP/network per line.

Then call `protonvpn refresh` to update the OpenVPN template with your excluded IP addresses.

## Enhancements

This is a list of optional enhancements that make using ProtonVPN-CLI easier.

### Disable sudo password query

You can disable the prompt for the sudo password when using ProtonVPN-CLI.

1. Enter `sudo which protonvpn` to find where the executable is installed

    ![which-protonvpn](https://i.imgur.com/JjYpviI.png)

2. Enter `sudo visudo` to edit the sudoers file.

    Go to the bottom of the file and add the following line

    `user ALL = (root)  NOPASSWD: /usr/local/bin/protonvpn`

    *Note: Make sure to replace the name `user` with your own username and the path with the output of the previous command*

3. Save the file

Now you can use ProtonVPN-CLI without entering your password. This is best used with an [alias](#configure-alias-for-quicker-access).

### Configure alias for quicker access

An alias let's you access the `protonvpn` command easier and without typing `sudo` all the time. To configure an alias, open your shell's rc file with your favorite editor, for bash, which is the default shell on most linux distributions, this would be `~/.bashrc`. Now add the following lines at the end of the file

`alias protonvpn='sudo protonvpn'`

`alias pvpn='sudo protonvpn'`

This let's you use ProtonVPN-CLI by just typing `protonvpn` without sudo or even just typing `pvpn`. For the latter, make sure you have uninstalled the old [bash-based ProtonVPN-CLI](https://github.com/ProtonVPN/protonvpn-cli) to avoid complications.

### Auto-connect on boot

#### via Systemd Service

Systemd is the current init system of most major Linux distributions. This guide shows you how to use systemd to automatically connect to a ProtonVPN Server when you boot up your system.

1. Find the location of the executable with `sudo which protonvpn`

    ![which-protonvpn](https://i.imgur.com/JjYpviI.png)

2. Create the unit file in `/etc/systemd/system`

    `sudo nano /etc/systemd/system/protonvpn-autoconnect.service`

3. Add the following contents to this file

    ```
    [Unit]
    Description=ProtonVPN-CLI auto-connect
    Wants=network-online.target

    [Service]
    Type=forking
    ExecStart=/usr/local/bin/protonvpn connect -f
    Environment=SUDO_USER=user

    [Install]
    WantedBy=multi-user.target
    ```

    Make sure to replace the username in the `Environment=` line with your own username that has ProtonVPN-CLI configured.

    Also replace the path to the `protonvpn` executable in the `ExecStart` line with the output of Step 1.

    If you want another connect command than fastest as used in this example, just replace `-f` with what you personally prefer.

4. Reload the systemd configuration

    `sudo systemctl daemon-reload`.

5. Enable the service so it starts on boot

    `sudo systemctl enable protonvpn-autoconnect`

Now ProtonVPN-CLI should connect automatically when you boot up your system.

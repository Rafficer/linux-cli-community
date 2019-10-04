"""pvpn-cli 0.1.0
A community maintened CLI for ProtonVPN.

Usage:
    pvpn-cli init
    pvpn-cli (c | connect) [<servername>] [-p <protocol>]
    pvpn-cli (c | connect) [-f | --fastest] [-p <protocol>]
    pvpn-cli (c | connect) [--cc <code>] [-p <protocol>]
    pvpn-cli (c | connect) [--sc] [-p <protocol>]
    pvpn-cli (c | connect) [--p2p] [-p <protocol>]
    pvpn-cli (c | connect) [--tor] [-p <protocol>]
    pvpn-cli (c | connect) [-r | --random] [-p <protocol>]
    pvpn-cli (r | reconnect)
    pvpn-cli (d | disconnect)
    pvpn-cli (s | status)
    pvpn-cli configure
    pvpn-cli refresh
    pvpn-cli uninstall
    pvpn-cli (-h | --help)
    pvpn-cli (-v | --version)

Options:
    -f, --fastest       Select the fastest ProtonVPN server.
    -r, --random        Select a random ProtonVPN server.
    --cc CODE           Determine the country for fastest connect.
    --sc                Connect to the fastest Secure-Core server.
    --p2p               Connect to the fastest torrent server.
    --tor               Connect to the fastest Tor server.
    -p PROTOCOL         Determine the protocol (UDP or TCP).
    -h, --help          Show this help message.
    -v, --version       Display version.

Commands:
    init                Initialize a ProtonVPN profile.
    c, connect          Connect to a ProtonVPN server.
    r, reconnect        Reconnect to the last server.
    d, disconnect       Disconnect the current session.
    s, status           Show connection status.
    configure           Change pvpn-cli configuration.
    refresh             Refresh OpenVPN configuration and server data.
    uninstall           Uninstall the CLI.

Arguments:
    <servername>        Servername (CH#4, CH-US-1, HK5-Tor).

Examples:
    pvpn-cli connect
                        Display a menu and select server interactively.
    pvpn-cli c BE-5
                        Connect to BE#5 with the default protocol.

    pvpn-cli connect NO#3 -p tcp
                        Connect to NO#3 with TCP.

    pvpn-cli c --fastest
                        Connect to the fastest VPN Server.

    pvpn-cli connect --cc AU
                        Connect to the fastest Australian server
                        with the default protocol.

    pvpn-cli c --p2p -p tcp
                        Connect to the fastest torrent server with TCP.

    pvpn-cli c --sc
                        Connect to the fastest Secure-Core server with
                        the default protocol.

    pvpn-cli reconnect
                        Reconnect the currently active session or connect
                        to the last connected server.

    pvpn-cli disconnect
                        Disconnect the current session.

    pvpn-cli s
                        Print information about the current session.
"""
# Standard Libraries
import sys
import os
import textwrap
import configparser
import getpass
import shutil
import time
# External Libraries
from docopt import docopt
# pvpn-cli Functions
from . import connection
from .logger import logger
from .utils import (
    check_root, change_file_owner, pull_server_data, make_ovpn_template,
    check_init, set_config_value, get_config_value
)
# Constants
from .constants import CONFIG_DIR, CONFIG_FILE, PASSFILE, USER, VERSION


def main():
    """Main function"""
    try:
        cli()
    except KeyboardInterrupt:
        print("\nQuitting...")
        sys.exit(1)


def cli():
    """Run user's input command."""
    args = docopt(__doc__, version=VERSION)

    # Initial log values
    change_file_owner(os.path.join(CONFIG_DIR, "pvpn-cli.log"))
    logger.debug("###########################")
    logger.debug("### NEW PROCESS STARTED ###")
    logger.debug("###########################")
    logger.debug(sys.argv)
    logger.debug("Arguments\n{0}".format(args))
    logger.debug("USER: {0}".format(USER))
    logger.debug("CONFIG_DIR: {0}".format(CONFIG_DIR))

    # Parse arguments
    if args.get("init"):
        init_cli()
    elif args.get("c") or args.get("connect"):
        check_root()
        check_init()

        protocol = args.get("-p")
        if protocol is not None and protocol.lower().strip() in ["tcp", "udp"]:
            protocol = protocol.lower().strip()

        if args.get("--random"):
            connection.random_c(protocol)
        elif args.get("--fastest"):
            connection.fastest(protocol)
        elif args.get("<servername>"):
            connection.direct(args.get("<servername>"), protocol)
        elif args.get("--cc") is not None:
            connection.country_f(args.get("--cc"), protocol)
        # Features: 1: Secure-Core, 2: Tor, 4: P2P
        elif args.get("--p2p"):
            connection.feature_f(4, protocol)
        elif args.get("--sc"):
            connection.feature_f(1, protocol)
        elif args.get("--tor"):
            connection.feature_f(2, protocol)
        else:
            connection.dialog()
    elif args.get("r") or args.get("reconnect"):
        check_root()
        check_init()
        connection.reconnect()
    elif args.get("d") or args.get("disconnect"):
        check_root()
        check_init()
        connection.disconnect()
    elif args.get("s") or args.get("status"):
        connection.status()
    elif args.get("configure"):
        check_root()
        check_init(check_props=False)
        configure_cli()
    elif args.get("refresh"):
        pull_server_data(force=True)
        make_ovpn_template()
    elif args.get("uninstall"):
        check_root()
        uninstall()


def init_cli():
    """Initialize the CLI."""

    def init_config_file():
        """"Initialize configuration file."""
        config = configparser.ConfigParser()
        config["USER"] = {
            "username": "None",
            "tier": "None",
            "default_protocol": "None",
            "initialized": "0",
            "dns_leak_protection": "1",
            "custom_dns": "None",
            "check_update_interval": "7",
        }
        config["metadata"] = {
            "last_api_pull": "0",
            "last_update_check": str(int(time.time())),
        }

        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        change_file_owner(CONFIG_FILE)
        logger.debug("pvpn-cli.cfg initialized")

    check_root()

    if not os.path.isdir(CONFIG_DIR):
        os.mkdir(CONFIG_DIR)
        logger.debug("Config Directory created")
    change_file_owner(CONFIG_DIR)

    # Warn user about reinitialization
    try:
        if int(get_config_value("USER", "initialized")):
            print("An initialized profile has been found.")
            overwrite = input(
                "Are you sure you want to overwrite that profile? [y/N]: "
            )
            if overwrite.strip().lower() != "y":
                print("Quitting...")
                sys.exit(1)
    except KeyError:
        pass

    term_width = shutil.get_terminal_size()[0]
    print("[ -- PVPN-CLI INIT -- ]\n".center(term_width))

    init_msg = (
        "ProtonVPN uses two different sets of credentials, one for the "
        "website and official apps where the username is most likely your "
        "e-mail, and one for connecting to the VPN servers.\n\n"
        "You can find the OpenVPN credentials at "
        "https://account.protonvpn.com/settings.\n\n"
        "--- Please make sure to use the OpenVPN credentials ---\n"
    ).splitlines()

    for line in init_msg:
        print(textwrap.fill(line, width=term_width))

    # Set ProtonVPN Username and Password
    ovpn_username, ovpn_password = set_username_password(write=False)

    # Set the ProtonVPN Plan
    user_tier = set_protonvpn_tier(write=False)

    # Set default Protocol
    user_protocol = set_default_protocol(write=False)

    # Enable or disable DNS Leak Protection
    dns_leak_protection, custom_dns = set_dns_protection(write=False)

    # Enable or disable VPN Killswitch
    print(
        "The Killswitch will block all network traffic\n"
        "if the VPN connection drops unexpectedly."
    )
    killswitch = set_killswitch(write=False)

    protonvpn_plans = {1: "Free", 2: "Basic", 3: "Plus", 4: "Visionary"}

    print()
    print(
        "You entered the following information:\n",
        "Username: {0}\n".format(ovpn_username),
        "Password: {0}\n".format("*" * len(ovpn_password)),
        "Tier: {0}\n".format(protonvpn_plans[user_tier]),
        "Default protocol: {0}\n".format(user_protocol.upper()),
        "DNS Leak Protection: {0}\n"
        .format('On' if dns_leak_protection else 'Off'),
        "Killswitch: {0}".format('On' if killswitch else 'Off'),
    )
    if custom_dns:
        print("Custom DNS: {0}\n".format(custom_dns))
    else:
        print()

    user_confirmation = input(
        "Is this information correct? [Y/n]: "
    ).strip().lower()

    if user_confirmation == "y" or user_confirmation == "":
        print("Writing configuration to disk...")
        init_config_file()

        pull_server_data()
        make_ovpn_template()

        # Change user tier to correct value
        if user_tier == 4:
            user_tier = 3
        user_tier -= 1

        set_config_value("USER", "username", ovpn_username)
        set_config_value("USER", "tier", user_tier)
        set_config_value("USER", "default_protocol", user_protocol)
        set_config_value("USER", "dns_leak_protection", dns_leak_protection)
        set_config_value("USER", "custom_dns", custom_dns)
        set_config_value("USER", "killswitch", killswitch)

        with open(PASSFILE, "w") as f:
            f.write("{0}\n{1}".format(ovpn_username, ovpn_password))
            logger.debug("Passfile created")
            os.chmod(PASSFILE, 0o600)

        set_config_value("USER", "initialized", 1)

        print()
        print("Done! Your account has been successfully initialized.")
        logger.debug("Initialization completed.")
    else:
        print()
        print("Please restart the initialization process.")
        sys.exit(1)


def configure_cli():
    """Change single configuration values"""

    while True:
        print(
            "What do you want to change?\n"
            "\n"
            "1) Username and Password\n"
            "2) ProtonVPN Plan\n"
            "3) Default Protocol\n"
            "4) DNS Management\n"
            "5) Killswitch\n"
        )

        user_choice = input(
            "Please enter your choice or leave empty to quit: "
        )

        user_choice = user_choice.lower().strip()
        if user_choice == "1":
            set_username_password(write=True)
            break
        elif user_choice == "2":
            set_protonvpn_tier(write=True)
            break
        elif user_choice == "3":
            set_default_protocol(write=True)
            break
        elif user_choice == "4":
            set_dns_protection(write=True)
            break
        elif user_choice == "5":
            set_killswitch(write=True)
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print(
                "[!] Invalid choice. Please enter the number of your choice.\n"
            )
            time.sleep(0.5)


def uninstall():
    """Uninstall the CLI"""

    # Function may be removed as other package managers will handle this
    # Further discussion needed

    connection.disconnect()
    if os.path.isdir(CONFIG_DIR):
        shutil.rmtree(CONFIG_DIR)
    if os.path.isdir("/usr/local/pvpn-cli"):
        shutil.rmtree("/usr/local/pvpn-cli")
    if os.path.islink("/usr/local/bin/pvpn-cli"):
        os.unlink("/usr/local/bin/pvpn-cli")
    print("PVPN-CLI and Configuration uninstalled.")


def set_username_password(write=False):
    """Set the ProtonVPN Username and Password."""

    print()
    ovpn_username = input("Enter your ProtonVPN OpenVPN username: ")

    # Ask for the password and confirmation until both are the same
    while True:
        ovpn_password1 = getpass.getpass(
            "Enter your ProtonVPN OpenVPN password: "
        )
        ovpn_password2 = getpass.getpass(
            "Confirm your ProtonVPN OpenVPN password: "
        )

        if not ovpn_password1 == ovpn_password2:
            print()
            print("[!] The passwords do not match. Please try again.")
        else:
            break

    if write:
        set_config_value("USER", "username", ovpn_username)

        with open(PASSFILE, "w") as f:
            f.write("{0}\n{1}".format(ovpn_username, ovpn_password1))
            logger.debug("Passfile updated")
            os.chmod(PASSFILE, 0o600)

        print("Username and Password has been updated!")

    return ovpn_username, ovpn_password1


def set_protonvpn_tier(write=False):
    """Set the users ProtonVPN Plan."""

    protonvpn_plans = {1: "Free", 2: "Basic", 3: "Plus", 4: "Visionary"}

    print()
    print("Please choose your ProtonVPN Plan")

    for plan in protonvpn_plans:
        print("{0}) {1}".format(plan, protonvpn_plans[plan]))

    while True:
        print()
        user_tier = input("Your plan: ")

        try:
            user_tier = int(user_tier)
            # Check if the choice exists in the dictionary
            protonvpn_plans[user_tier]
            break
        except (KeyError, ValueError):
            print()
            print("[!] Invalid choice. Please enter the number of your plan.")

    if write:
        # Set Visionary to plus as it has the same access
        if user_tier == 4:
            user_tier = 3

        # Lower tier by one to match API allocation
        user_tier -= 1

        set_config_value("USER", "tier", str(user_tier))

        print("ProtonVPN Plan has been updated!")

    return user_tier


def set_default_protocol(write=False):
    """Set the users default protocol"""

    print()
    print(
        "Choose the default OpenVPN protocol.\n"
        "OpenVPN can act on two different protocols: UDP and TCP.\n"
        "UDP is preferred for speed but might be blocked in some networks.\n"
        "TCP is not as fast but a lot harder to block.\n"
        "Input your preferred protocol. (Default: UDP)\n"
    )

    protonvpn_protocols = {1: "UDP", 2: "TCP"}

    for protocol in protonvpn_protocols:
        print("{0}) {1}".format(protocol, protonvpn_protocols[protocol]))

    while True:
        print()
        user_protocol_choice = input("Your choice: ")

        try:
            if user_protocol_choice == "":
                user_protocol_choice = 1
            user_protocol_choice = int(user_protocol_choice)
            # Check if the choice exists in the dictionary
            user_protocol = protonvpn_protocols[user_protocol_choice].lower()
            break
        except (KeyError, ValueError):
            print()
            print(
                "[!] Invalid choice. "
                "Please enter the number of your preferred protocol."
            )

    if write:
        set_config_value("USER", "default_protocl", user_protocol)
        print("Default protocol has been updated.")

    return user_protocol


def set_dns_protection(write=False):
    """Enable or disable DNS Leak Protection and custom DNS"""

    # DNS Leak protection and Custom DNS Server
    print()
    print(
        "DNS Leak Protection makes sure that you always use "
        "ProtonVPN's DNS servers.\n"
        "For security reasons this option is recommended."
    )
    print()
    user_choice = input("Enable DNS Leak Protection? [Y/n]: ")
    user_choice = user_choice.strip().lower()

    custom_dns = None

    if user_choice == "y" or user_choice == "":
        dns_leak_protection = 1
    else:
        dns_leak_protection = 0
        print()
        user_choice = input(
            "Would you like to use a custom DNS server? [y/N]: "
        )
        user_choice = user_choice.strip().lower()
        if user_choice == "y":
            custom_dns = input("Please enter your custom DNS server: ")
            custom_dns = custom_dns.strip()

    if write:
        set_config_value("USER", "dns_leak_protection", dns_leak_protection)
        set_config_value("USER", "custom_dns", custom_dns)
        print("DNS Management updated.")

    return dns_leak_protection, custom_dns


def set_killswitch(write=False):
    """Enable or disable the Killswitch."""

    print()
    user_choice = input("Enable VPN Killswitch? [y/N]: ")

    if user_choice.strip().lower() == "y":
        killswitch = 1
    else:
        killswitch = 0

    if write:
        set_config_value("USER", "killswitch", killswitch)
        print()
        print("Killswitch configuration updated.")

    return killswitch

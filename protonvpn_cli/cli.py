# Standard Libraries
import sys
import os
import textwrap
import configparser
import getpass
import shutil
import time
import argparse
# protonvpn-cli Functions
from . import connection
from .logger import logger
from .utils import (
    check_root, change_file_owner, pull_server_data,
    check_init, set_config_value, get_config_value,
    is_valid_ip, wait_for_network
)
# Constants
from .constants import (
    CONFIG_DIR, CONFIG_FILE, PASSFILE, USER, VERSION, SPLIT_TUNNEL_FILE, USAGE
)


def main():
    """Main function"""
    try:
        cli()
    except KeyboardInterrupt:
        print("\nQuitting...")
        sys.exit(1)


def cli():
    """Run user's input command."""

    # Initial log values
    change_file_owner(os.path.join(CONFIG_DIR, "pvpn-cli.log"))
    logger.debug("###########################")
    logger.debug("### NEW PROCESS STARTED ###")
    logger.debug("###########################")
    logger.debug(sys.argv)
    logger.debug("USER: {0}".format(USER))
    logger.debug("CONFIG_DIR: {0}".format(CONFIG_DIR))

    ProtonVPNCLI()


class ProtonVPNCLI():
    server_features_dict = dict(
        p2p=4,
        sc=1,
        tor=2
    )

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog="protonvpn",
            add_help=False
        )

        parser.add_argument("command", nargs="?")
        parser.add_argument("-v", "--version", required=False, action="store_true")
        parser.add_argument("-h", "--help", required=False, action="store_true")

        args = parser.parse_args(sys.argv[1:2])

        logger.debug("Main argument\n{0}".format(args))

        if args.version:
            print("\nProtonVPN CLI v.{}".format(VERSION))
            parser.exit(1)
        elif not args.command or not hasattr(self, args.command) or args.help:
            print(USAGE)
            parser.exit(1)

        getattr(self, args.command)()

    def init(self):
        """CLI command that intialiazes ProtonVPN profile"""
        parser = argparse.ArgumentParser(description="Initialize ProtonVPN profile", prog="protonvpn init")
        parser.add_argument(
            "-i", "--inline", nargs=3, required=False,
            help="Inline intialize profile. (username password protocol)", metavar=""
        )

        args = parser.parse_args(sys.argv[2:])
        logger.debug("Sub-arguments\n{0}".format(args))

        if args.inline:
            print("Please intialize without '-i/--inline' as it is not fully supported yet.")
            sys.exit(1)

        init_cli()

    def c(self):
        """Short CLI command for connecting to the VPN"""
        self.connect()

    def connect(self):
        """Full CLI command for connecting to the VPN"""
        check_root()
        check_init()

        # Wait until a connection to the ProtonVPN API can be made
        # As this is mainly for automatically connecting on boot, it only
        # activates when the environment variable PVPN_WAIT is 1
        # Otherwise it wouldn't connect when a VPN process without
        # internet access exists or the Kill Switch is active
        if int(os.environ.get("PVPN_WAIT", 0)) > 0:
            wait_for_network(int(os.environ["PVPN_WAIT"]))

        parser = argparse.ArgumentParser(description="Connect to ProtonVPN", prog="protonvpn c")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("servername", nargs="?", help="Servername (CH#4, CH-US-1, HK5-Tor).", metavar="")
        group.add_argument("-f", "--fastest", help="Connect to the fastest ProtonVPN server.", action="store_true")
        group.add_argument("-r", "--random", help="Connect to a random ProtonVPN server.", action="store_true")
        group.add_argument("--cc", help="Connect to the specified country code (SE, PT, BR, AR).", metavar="")
        group.add_argument("--sc", help="Connect to the fastest Secure-Core server.", action="store_true")
        group.add_argument("--p2p", help="Connect to the fastest torrent server.", action="store_true")
        group.add_argument("--tor", help="Connect to the fastest Tor server.", action="store_true")
        parser.add_argument(
            "-p", "--protocol", help="Connect via specified protocol.",
            choices=["udp", "tcp"], metavar="", type=str.lower
        )

        args = parser.parse_args(sys.argv[2:])
        logger.debug("Sub-arguments:\n{0}".format(args))

        protocol = args.protocol
        if protocol and protocol.lower().strip() in ["tcp", "udp"]:
            protocol = protocol.lower().strip()

        if args.random:
            connection.random_c(protocol)
        elif args.fastest:
            connection.fastest(protocol)
        elif args.servername:
            connection.direct(args.servername, protocol)
        elif args.cc:
            connection.country_f(args.cc, protocol)
        elif args.p2p:
            connection.feature_f(self.server_features_dict.get("p2p", None), protocol)
        elif args.sc:
            connection.feature_f(self.server_features_dict.get("sc", None), protocol)
        elif args.tor:
            connection.feature_f(self.server_features_dict.get("tor", None), protocol)
        else:
            connection.dialog()

    def r(self):
        """Short CLI command to reconnect to the last connected VPN Server"""
        self.reconnect()

    def reconnect(self):
        """Full CLI command to reconnect to the last connected VPN Server"""
        check_root()
        check_init()
        connection.reconnect()

    def d(self):
        """Short CLI command to disconnect the VPN if a connection is present"""
        self.disconnect()

    def disconnect(self):
        """Full CLI command to disconnect the VPN if a connection is present"""
        check_root()
        check_init()
        connection.disconnect()

    def s(self):
        """Short CLI command to display the current VPN status"""
        self.status()

    def status(self):
        """Full CLI command to display the current VPN status"""
        connection.status()

    def cf(self):
        """Short CLI command to change single configuration values"""
        self.configure()

    def configure(self):
        """Full CLI command to change single configuration values"""
        check_root()
        check_init()
        configure_cli()

    def rf(self):
        """Short CLI command to refresh server list"""
        self.refresh()

    def refresh(self):
        """Full CLI command to refresh server list"""
        check_init()
        pull_server_data(force=True)

    def ex(self):
        """Short CLI command to display usage examples"""
        self.examples()

    def examples(self):
        """Full CLI command to display usage examples"""
        print_examples()


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
            "check_update_interval": "3",
            "api_domain": "https://api.protonvpn.ch",
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
            # Disconnect, so every setting (Kill Switch, IPv6, ...)
            # will be reverted (See #62)
            connection.disconnect(passed=True)
    except KeyError:
        pass

    term_width = shutil.get_terminal_size()[0]
    print("[ -- PROTONVPN-CLI INIT -- ]\n".center(term_width))

    init_msg = (
        "ProtonVPN uses two different sets of credentials, one for the "
        "website and official apps where the username is most likely your "
        "e-mail, and one for connecting to the VPN servers.\n\n"
        "You can find the OpenVPN credentials at "
        "https://account.protonvpn.com/account.\n\n"
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

    protonvpn_plans = {1: "Free", 2: "Basic", 3: "Plus", 4: "Visionary"}

    print()
    print(
        "You entered the following information:\n"
        + "Username: {0}\n".format(ovpn_username)
        + "Password: {0}\n".format("*" * len(ovpn_password))
        + "Tier: {0}\n".format(protonvpn_plans[user_tier])
        + "Default protocol: {0}".format(user_protocol.upper())
    )
    print()

    user_confirmation = input(
        "Is this information correct? [Y/n]: "
    ).strip().lower()

    if user_confirmation == "y" or user_confirmation == "":
        print("Writing configuration to disk...")
        init_config_file()

        pull_server_data()

        # Change user tier to correct value
        if user_tier == 4:
            user_tier = 3
        user_tier -= 1

        set_config_value("USER", "username", ovpn_username)
        set_config_value("USER", "tier", user_tier)
        set_config_value("USER", "default_protocol", user_protocol)
        set_config_value("USER", "dns_leak_protection", 1)
        set_config_value("USER", "custom_dns", None)
        set_config_value("USER", "killswitch", 0)

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


def print_examples():
    """Print some examples on how to use this program"""

    examples = (
        "protonvpn connect\n"
        "               Display a menu and select server interactively.\n\n"
        "protonvpn c BE-5\n"
        "               Connect to BE#5 with the default protocol.\n\n"
        "protonvpn connect NO#3 -p tcp\n"
        "               Connect to NO#3 with TCP.\n\n"
        "protonvpn c --fastest\n"
        "               Connect to the fastest VPN Server.\n\n"
        "protonvpn connect --cc AU\n"
        "               Connect to the fastest Australian server\n"
        "               with the default protocol.\n\n"
        "protonvpn c --p2p -p tcp\n"
        "               Connect to the fastest torrent server with TCP.\n\n"
        "protonvpn c --sc\n"
        "               Connect to the fastest Secure-Core server with\n"
        "               the default protocol.\n\n"
        "protonvpn reconnect\n"
        "               Reconnect the currently active session or connect\n"
        "               to the last connected server.\n\n"
        "protonvpn disconnect\n"
        "               Disconnect the current session.\n\n"
        "protonvpn s\n"
        "               Print information about the current session."
    )

    print(examples)


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
            "5) Kill Switch\n"
            "6) Split Tunneling\n"
            "7) Purge Configuration\n"
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
            set_dns_protection()
            break
        elif user_choice == "5":
            set_killswitch()
            break
        elif user_choice == "6":
            set_split_tunnel()
            break
        # Make sure this is always the last option
        elif user_choice == "7":
            purge_configuration()
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print(
                "[!] Invalid choice. Please enter the number of your choice.\n"
            )
            time.sleep(0.5)


def purge_configuration():
    """Purges CLI configuration"""

    user_choice = input(
        "Are you sure you want to purge the configuration? [y/N]: "
    ).lower().strip()

    if not user_choice == "y":
        return

    print("Okay :(")
    time.sleep(0.5)

    connection.disconnect(passed=True)
    if os.path.isdir(CONFIG_DIR):
        shutil.rmtree(CONFIG_DIR)
    print("Configuration purged.")


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
        set_config_value("USER", "default_protocol", user_protocol)
        print("Default protocol has been updated.")

    return user_protocol


def set_dns_protection():
    """Enable or disable DNS Leak Protection and custom DNS"""

    while True:
        print()
        print(
            "DNS Leak Protection makes sure that you always use "
            "ProtonVPN's DNS servers.\n"
            "For security reasons this option is recommended.\n"
            "\n"
            "1) Enable DNS Leak Protection (recommended)\n"
            "2) Configure Custom DNS Servers\n"
            "3) Disable DNS Management"
        )
        print()
        user_choice = input(
            "Please enter your choice or leave empty to quit: "
        )
        user_choice = user_choice.lower().strip()
        if user_choice == "1":
            dns_leak_protection = 1
            custom_dns = None
            break
        elif user_choice == "2":
            dns_leak_protection = 0
            custom_dns = input(
                "Please enter your custom DNS servers (space separated): "
            )
            custom_dns = custom_dns.strip().split()

            # Check DNS Servers for validity
            if len(custom_dns) > 3:
                print("[!] Don't enter more than 3 DNS Servers")
                return

            for dns in custom_dns:
                if not is_valid_ip(dns):
                    print("[!] {0} is invalid. Please try again.".format(dns))
                    return
            custom_dns = " ".join(dns for dns in custom_dns)
            break
        elif user_choice == "3":
            dns_leak_protection = 0
            custom_dns = None
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print(
                "[!] Invalid choice. Please enter the number of your choice.\n"
            )
            time.sleep(0.5)

    set_config_value("USER", "dns_leak_protection", dns_leak_protection)
    set_config_value("USER", "custom_dns", custom_dns)
    print("DNS Management updated.")


def set_killswitch():
    """Enable or disable the Kill Switch."""

    while True:
        print()
        print(
            "The Kill Switch will block all network traffic\n"
            "if the VPN connection drops unexpectedly.\n"
            "\n"
            "Please note that the Kill Switch assumes only one network interface being active.\n" # noqa
            "\n"
            "1) Enable Kill Switch (Block access to/from LAN)\n"
            "2) Enable Kill Switch (Allow access to/from LAN)\n"
            "3) Disable Kill Switch"
        )
        print()
        user_choice = input(
            "Please enter your choice or leave empty to quit: "
        )
        user_choice = user_choice.lower().strip()
        if user_choice == "1":
            killswitch = 1
            break
        elif user_choice == "2":
            killswitch = 2
            break
        elif user_choice == "3":
            killswitch = 0
            break
        elif user_choice == "":
            print("Quitting configuration.")
            sys.exit(0)
        else:
            print(
                "[!] Invalid choice. Please enter the number of your choice.\n"
            )
            time.sleep(0.5)

    if killswitch and int(get_config_value("USER", "split_tunnel")):
        set_config_value("USER", "split_tunnel", 0)
        print()
        print(
            "[!] Kill Switch can't be used with Split Tunneling.\n"
            + "[!] Split Tunneling has been disabled."
        )
        time.sleep(1)

    set_config_value("USER", "killswitch", killswitch)
    print()
    print("Kill Switch configuration updated.")


def set_split_tunnel():
    """Enable or disable split tunneling"""

    print()
    user_choice = input("Enable split tunneling? [y/N]: ")

    if user_choice.strip().lower() == "y":
        if int(get_config_value("USER", "killswitch")):
            set_config_value("USER", "killswitch", 0)
            print()
            print(
                "[!] Split Tunneling can't be used with Kill Switch.\n"
                + "[!] Kill Switch has been disabled.\n"
            )
            time.sleep(1)

        set_config_value("USER", "split_tunnel", 1)

        while True:
            ip = input(
                "Please enter an IP or CIDR to exclude from VPN.\n"
                "Or leave empty to stop: "
            ).strip()

            if ip == "":
                break

            if not is_valid_ip(ip):
                print("[!] Invalid IP")
                print()
                continue

            with open(SPLIT_TUNNEL_FILE, "a") as f:
                f.write("\n{0}".format(ip))

        if os.path.isfile(SPLIT_TUNNEL_FILE):
            change_file_owner(SPLIT_TUNNEL_FILE)
        else:
            # If no no config file exists,
            # split tunneling should be disabled again
            logger.debug("No split tunneling file existing.")
            set_config_value("USER", "split_tunnel", 0)

    else:
        set_config_value("USER", "split_tunnel", 0)

        if os.path.isfile(SPLIT_TUNNEL_FILE):
            clear_config = input("Remove split tunnel configuration? [y/N]: ")

            if clear_config.strip().lower() == "y":
                os.remove(SPLIT_TUNNEL_FILE)

    print()
    print("Split tunneling configuration updated.")

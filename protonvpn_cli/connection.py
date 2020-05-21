# Standard Libraries
import os
import sys
import subprocess
import time
import shutil
import random
import re
import configparser
import datetime
import zlib
# External Libraries
from dialog import Dialog
# protonvpn-cli Functions
from .logger import logger
from .utils import (
    check_init, pull_server_data, is_connected,
    get_servers, get_server_value, get_config_value,
    set_config_value, get_ip_info, get_country_name,
    get_fastest_server, check_update, get_default_nic,
    get_transferred_data, create_openvpn_config,
    is_ipv6_disabled
)
# Constants
from .constants import (
    CONFIG_DIR, OVPN_FILE, PASSFILE, CONFIG_FILE
)


def dialog():
    """Connect to a server with a dialog menu."""
    def show_dialog(headline, choices, stop=False):
        """Show the dialog and process response."""
        d = Dialog(dialog="dialog")

        logger.debug("Showing Dialog: {0}".format(headline))

        code, tag = d.menu(headline, title="ProtonVPN-CLI", choices=choices)
        if code == "ok":
            return tag
        else:
            os.system("clear")
            print("Canceled.")
            sys.exit(1)

    logger.debug("Starting dialog connect")

    # Check if dialog is installed
    dialog_check = subprocess.run(['which', 'dialog'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
    if not dialog_check.returncode == 0:
        print("'dialog' not found. "
              "Please install dialog via your package manager.")
        logger.debug("dialog not found")
        sys.exit(1)

    pull_server_data()

    features = {0: "Normal", 1: "Secure-Core", 2: "Tor", 4: "P2P"}
    server_tiers = {0: "F", 1: "B", 2: "P"}

    servers = get_servers()

    countries = {}
    for server in servers:
        country = get_country_name(server["ExitCountry"])
        if country not in countries.keys():
            countries[country] = []
        countries[country].append(server["Name"])

    # Fist dialog
    choices = []

    for country in sorted(countries.keys()):
        country_features = []
        for server in countries[country]:
            feat = int(get_server_value(server, "Features", servers))
            if not features[feat] in country_features:
                country_features.append(features[feat])
        choices.append((country, " | ".join(sorted(country_features))))

    country = show_dialog("Choose a country:", choices)
    logger.debug("Country Choice: {0}".format(country))

    # Second dialog
    # lambda sorts servers by Load instead of name
    choices = []
    country_servers = sorted(countries[country],
                             key=lambda s: get_server_value(
                                 s, "Load", servers))

    for servername in country_servers:

        load = str(
            get_server_value(servername, "Load", servers)
        ).rjust(3, " ")

        feature = features[
            get_server_value(servername, 'Features', servers)
        ]

        tier = server_tiers[
            get_server_value(servername, "Tier", servers)
        ]

        choices.append((servername, "Load: {0}% | {1} | {2}".format(
            load, tier, feature
        )))

    server_result = show_dialog("Choose the server to connect:", choices)

    logger.debug("Server Choice: {0}".format(server_result))

    protocol_result = show_dialog(
        "Choose a protocol:", [
            ("UDP", "Better Speed"), ("TCP", "Better Reliability")
        ]
    )

    logger.debug("Protocol Choice: {0}".format(protocol_result))

    os.system("clear")
    openvpn_connect(server_result, protocol_result)


def random_c(protocol=None):
    """Connect to a random ProtonVPN Server."""

    logger.debug("Starting random connect")

    if not protocol:
        protocol = get_config_value("USER", "default_protocol")

    servers = get_servers()

    servername = random.choice(servers)["Name"]

    openvpn_connect(servername, protocol)


def fastest(protocol=None):
    """Connect to the fastest server available."""

    logger.debug("Starting fastest connect")

    if not protocol:
        protocol = get_config_value("USER", "default_protocol")

    disconnect(passed=True)
    pull_server_data(force=True)

    servers = get_servers()

    # ProtonVPN Features: 1: SECURE-CORE, 2: TOR, 4: P2P
    excluded_features = [1, 2]

    # Filter out excluded features
    server_pool = []
    for server in servers:
        if server["Features"] not in excluded_features:
            server_pool.append(server)

    fastest_server = get_fastest_server(server_pool)
    openvpn_connect(fastest_server, protocol)


def country_f(country_code, protocol=None):
    """Connect to the fastest server in a specific country."""
    logger.debug("Starting fastest country connect")

    if not protocol:
        protocol = get_config_value("USER", "default_protocol")

    country_code = country_code.strip().upper()

    disconnect(passed=True)
    pull_server_data(force=True)

    servers = get_servers()

    # ProtonVPN Features: 1: SECURE-CORE, 2: TOR, 4: P2P
    excluded_features = [1, 2]

    # Filter out excluded features and countries
    server_pool = []
    for server in servers:
        if server["Features"] not in excluded_features and server["ExitCountry"] == country_code:
            server_pool.append(server)

    if len(server_pool) == 0:
        print(
            "[!] No Server in country {0} found\n".format(country_code)
            + "[!] Please choose a valid country"
        )
        logger.debug("No server in country {0}".format(country_code))
        sys.exit(1)

    fastest_server = get_fastest_server(server_pool)
    openvpn_connect(fastest_server, protocol)


def feature_f(feature, protocol=None):
    """Connect to the fastest server in a specific country."""
    logger.debug(
        "Starting fastest feature connect with feature {0}".format(feature)
    )

    if not protocol:
        protocol = get_config_value("USER", "default_protocol")

    disconnect(passed=True)
    pull_server_data(force=True)

    servers = get_servers()

    server_pool = [s for s in servers if s["Features"] == feature]

    if len(server_pool) == 0:
        logger.debug("No servers found with users selection. Exiting.")
        print("[!] No servers found with your selection.")
        sys.exit(1)

    fastest_server = get_fastest_server(server_pool)
    openvpn_connect(fastest_server, protocol)


def direct(user_input, protocol=None):
    """Connect to a single given server directly"""

    logger.debug("Starting direct connect with {0}".format(user_input))
    pull_server_data()

    if not protocol:
        protocol = get_config_value("USER", "default_protocol")

    # For short format (UK-03/HK#5-Tor | Normal Servers/Tor Servers)
    re_short = re.compile(r"^((\w\w)(-|#)?(\d{1,3})-?(TOR)?)$")
    # For long format (IS-DE-01 | Secure-Core/Free/US Servers)
    re_long = re.compile(
        r"^(((\w\w)(-|#)?([A-Z]{2}|FREE))(-|#)?(\d{1,3})-?(TOR)?)$"
    )

    user_input = user_input.upper()

    if re_short.search(user_input):
        user_server = re_short.search(user_input)

        country_code = user_server.group(2)
        number = user_server.group(4).lstrip("0")
        tor = user_server.group(5)
        servername = "{0}#{1}".format(country_code, number) +\
                     "{0}".format('-' + tor if tor is not None else '')
    elif re_long.search(user_input):
        user_server = re_long.search(user_input)
        country_code = user_server.group(3)
        country_code2 = user_server.group(5)
        number = user_server.group(7).lstrip("0")
        tor = user_server.group(8)
        servername = "{0}-{1}#{2}".format(country_code,
                                          country_code2, number) + \
                     "{0}".format('-' + tor if tor is not None else '')
    else:
        print(
            "[!] '{0}' is not a valid servername\n".format(user_input)
            + "[!] Please enter a valid servername"
        )
        logger.debug("'{0}' is not a valid servername'".format(user_input))
        sys.exit(1)

    servers = get_servers()

    if servername not in [server["Name"] for server in servers]:
        print(
            "[!] {0} doesn't exist, ".format(servername)
            + "is under maintenance, or inaccessible with your plan.\n"
            "[!] Please enter a different, valid servername."
        )
        logger.debug("{0} doesn't exist".format(servername))
        sys.exit(1)

    openvpn_connect(servername, protocol)


def reconnect():
    """Reconnect to the last VPN Server."""

    logger.debug("Starting reconnect")

    try:
        servername = get_config_value("metadata", "connected_server")
        protocol = get_config_value("metadata", "connected_proto")
    except KeyError:
        logger.debug("No previous connection found")
        print(
            "[!] Couldn't find a previous connection\n"
            "[!] Please connect normally first"
        )
        sys.exit(1)

    openvpn_connect(servername, protocol)


def disconnect(passed=False):
    """Disconnect VPN if a connection is present."""

    logger.debug("Initiating disconnect")

    if is_connected():
        if passed:
            print("There is already a VPN connection running.")
            print("Terminating previous connection...")
        subprocess.run(["pkill", "openvpn"])

        time.sleep(0.5)
        timer_start = time.time()

        while True:
            if is_connected():
                if time.time() - timer_start <= 5:
                    subprocess.run(["pkill", "openvpn"])
                    time.sleep(0.2)
                else:
                    subprocess.run(
                        ["pkill", "-9", "openvpn"])
                    logger.debug("SIGKILL sent")
                    break
            else:
                break

        if is_connected():
            print("[!] Could not terminate OpenVPN process.")
            sys.exit(1)
        else:
            manage_dns("restore")
            manage_ipv6("restore")
            manage_killswitch("restore")
            logger.debug("Disconnected")
            if not passed:
                print("Disconnected.")
    else:
        if not passed:
            print("No connection found.")
        manage_dns("restore")
        manage_ipv6("restore")
        manage_killswitch("restore")
        logger.debug("No connection found")


def status():
    """
    Display the current VPN status

    Showing connection status (connected/disconnected),
    current IP, server name, country, server load
    """
    check_init()
    logger.debug("Getting VPN Status")

    # Quit if not connected
    if not is_connected():
        logger.debug("Disconnected")
        print("Status:     Disconnected")
        if os.path.isfile(os.path.join(CONFIG_DIR, "iptables.backup")):
            print("[!] Kill Switch is currently active.")
            logger.debug("Kill Switch active while VPN disconnected")
        else:
            ip, isp = get_ip_info()
            print("IP:         {0}".format(ip))
            print("ISP:        {0}".format(isp))
        return

    pull_server_data()

    try:
        connected_server = get_config_value("metadata", "connected_server")
        connected_protocol = get_config_value("metadata", "connected_proto")
        dns_server = get_config_value("metadata", "dns_server")
    except KeyError:
        print("It looks like there never was a connection.\n"
              "Please connect with 'protonvpn connect' first.")
        sys.exit(1)

    # Check if the VPN Server is reachable
    ping = subprocess.run(["ping", "-c", "1", dns_server],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if ping.returncode != 0:
        logger.debug("Could not reach VPN server")
        print("[!] Could not reach the VPN Server")
        print("[!] You may want to reconnect with 'protonvpn reconnect'")
        return

    servers = get_servers()

    ip, isp = get_ip_info()

    # Collect Information
    all_features = {0: "Normal", 1: "Secure-Core", 2: "Tor", 4: "P2P"}

    logger.debug("Collecting status information")
    country_code = get_server_value(connected_server, "ExitCountry", servers)
    country = get_country_name(country_code)
    city = get_server_value(connected_server, "City", servers)
    load = get_server_value(connected_server, "Load", servers)
    feature = get_server_value(connected_server, "Features", servers)
    last_connection = get_config_value("metadata", "connected_time")
    connection_time = time.time() - int(last_connection)

    if os.path.isfile(os.path.join(CONFIG_DIR, "iptables.backup")):
        killswitch_on = True
    else:
        killswitch_on = False
    killswitch_status = "Enabled" if killswitch_on else "Disabled"
    # Turn time into human readable format and trim microseconds
    connection_time = str(datetime.timedelta(
        seconds=connection_time)).split(".")[0]

    tx_amount, rx_amount = get_transferred_data()

    # Print Status Output
    logger.debug("Printing status")
    print(
        "Status:       Connected\n"
        + "Time:         {0}\n".format(connection_time)
        + "IP:           {0}\n".format(ip)
        + "Server:       {0}\n".format(connected_server)
        + "Features:     {0}\n".format(all_features[feature])
        + "Protocol:     {0}\n".format(connected_protocol.upper())
        + "Kill Switch:  {0}\n".format(killswitch_status)
        + "Country:      {0}\n".format(country)
        + "City:         {0}\n".format(city)
        + "Load:         {0}%\n".format(load)
        + "Received:     {0}\n".format(rx_amount)
        + "Sent:         {0}".format(tx_amount)
    )


def openvpn_connect(servername, protocol):
    """Connect to VPN Server."""

    logger.debug("Initiating OpenVPN connection")
    logger.debug(
        "Connecting to {0} via {1}".format(servername, protocol.upper())
    )

    port = {"udp": 1194, "tcp": 443}

    servers = get_servers()
    subservers = get_server_value(servername, "Servers", servers)
    ip_list = [subserver["EntryIP"] for subserver in subservers]

    # Ports gets casted to a list instead of just a single port to make it iterable
    create_openvpn_config(serverlist=ip_list, protocol=protocol, ports=[port[protocol.lower()]])

    disconnect(passed=True)

    old_ip, _ = get_ip_info()

    print("Connecting to {0} via {1}...".format(servername, protocol.upper()))

    with open(os.path.join(CONFIG_DIR, "ovpn.log"), "w+") as f:
        subprocess.Popen(
            [
                "openvpn",
                "--config", OVPN_FILE,
                "--auth-user-pass", PASSFILE,
                "--dev", "proton0",
                "--dev-type", "tun"
            ],
            stdout=f, stderr=f
        )

    logger.debug("OpenVPN process started")
    time_start = time.time()

    with open(os.path.join(CONFIG_DIR, "ovpn.log"), "r") as f:
        while True:
            content = f.read()
            f.seek(0)
            # If connection successful
            if "Initialization Sequence Completed" in content:
                # Enable DNS Leak Protection
                dns_dhcp_regex = re.compile(
                    r"(dhcp-option DNS )"
                    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                )

                dns_dhcp = dns_dhcp_regex.search(content)
                if dns_dhcp:
                    dns_server = dns_dhcp.group(2)
                    set_config_value("metadata", "dns_server", dns_server)
                    manage_dns("leak_protection", dns_server)
                else:
                    print(
                        "[!] Could not enable DNS Leak Protection!\n"
                        "[!] Make sure you are protected!"
                    )
                manage_ipv6("disable")
                manage_killswitch("enable", proto=protocol.lower(),
                                  port=port[protocol.lower()])
                new_ip, _ = get_ip_info()
                if old_ip == new_ip:
                    logger.debug("Failed to connect. IP didn't change")
                    print("[!] Connection failed. Reverting all changes...")
                    disconnect(passed=True)
                print("Connected!")
                logger.debug("Connection successful")
                break
            # If Authentication failed
            elif "AUTH_FAILED" in content:
                print(
                    "[!] Authentication failed. \n"
                    "[!] Please make sure that your "
                    "Username and Password is correct."
                )
                logger.debug("Authentication failure")
                sys.exit(1)
            # Stop after 45s
            elif time.time() - time_start >= 45:
                print("Connection failed.")
                logger.debug("Connection failed after 45 Seconds")
                sys.exit(1)
            time.sleep(0.1)

    # Write connection info into configuration file
    logger.debug("Writing connection info to file")
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    config["metadata"]["connected_server"] = servername
    config["metadata"]["connected_proto"] = protocol
    config["metadata"]["connected_time"] = str(int(time.time()))

    with open(CONFIG_FILE, "w+") as f:
        config.write(f)

    check_update()


def manage_dns(mode, dns_server=False):
    """
    Manage resolv.conf to circumvent DNS Leaks.

    Has 2 modes (string): leak_protection / restore
    leak_protection: Replace the current resolv.conf entries with ProtonVPN DNS
    restore: Revert changes and restore original configuration
    """

    backupfile = os.path.join(CONFIG_DIR, "resolv.conf.backup")
    resolvconf_path = os.path.realpath("/etc/resolv.conf")

    if mode == "leak_protection":
        logger.debug("Leak Protection initiated")
        # Restore original resolv.conf if it exists
        if os.path.isfile(backupfile):
            logger.debug("resolv.conf.backup exists")
            manage_dns("restore")
        # Check for custom DNS Server
        if not int(get_config_value("USER", "dns_leak_protection")):
            if get_config_value("USER", "custom_dns") == "None":
                logger.debug("DNS Leak Protection is disabled")
                return
            else:
                dns_server = get_config_value("USER", "custom_dns")
                logger.debug("Using custom DNS")
        else:
            logger.debug("DNS Leak Protection is enabled")
        # Make sure DNS Server has been provided
        if not dns_server:
            raise Exception("No DNS Server has been provided.")

        shutil.copy2(resolvconf_path, backupfile)
        logger.debug("{0} (resolv.conf) backed up".format(resolvconf_path))

        # Remove previous nameservers
        dns_regex = re.compile(r"^nameserver .*$")

        with open(backupfile, 'r') as backup_handle:
            with open(resolvconf_path, 'w') as resolvconf_handle:
                for line in backup_handle:
                    if not dns_regex.search(line):
                        resolvconf_handle.write(line)

        logger.debug("Removed existing DNS Servers")

        # Add ProtonVPN managed DNS Server to resolv.conf
        dns_server = dns_server.split()
        with open(resolvconf_path, "a") as f:
            f.write("# ProtonVPN DNS Servers. Managed by ProtonVPN-CLI.\n")
            for dns in dns_server[:3]:
                f.write("nameserver {0}\n".format(dns))
            logger.debug("Added ProtonVPN or custom DNS")

        # Write the hash of the edited file in the configuration
        #
        # This is so it doesn't restore an old DNS configuration
        # if the configuration changes during a VPN session
        # (e.g. by switching networks)

        with open(resolvconf_path, "rb") as f:
            filehash = zlib.crc32(f.read())
        set_config_value("metadata", "resolvconf_hash", filehash)

    elif mode == "restore":
        logger.debug("Restoring DNS")
        if os.path.isfile(backupfile):

            # Check if the file changed since connection
            oldhash = get_config_value("metadata", "resolvconf_hash")
            with open(resolvconf_path, "rb") as f:
                filehash = zlib.crc32(f.read())

            if filehash == int(oldhash):
                shutil.copy2(backupfile, resolvconf_path)
                logger.debug("resolv.conf restored from backup")
            else:
                logger.debug("resolv.conf changed. Not restoring.")

            os.remove(backupfile)
            logger.debug("resolv.conf.backup removed")
        else:
            logger.debug("No Backupfile found")
    else:
        raise Exception("Invalid argument provided. "
                        "Mode must be 'restore' or 'leak_protection'")


def manage_ipv6(mode):
    """
    Disable and Enable IPv6 to circumvent IPv6 leaks.

    Has 2 modes (string): disable / restore.
    disable: Disables IPv6 for the default interface.
    restore: Revert changes and restore original configuration.
    """

    ipv6_backupfile = os.path.join(CONFIG_DIR, "ipv6.backup")
    ip6tables_backupfile = os.path.join(CONFIG_DIR, "ip6tables.backup")

    if mode == "disable":

        logger.debug("Disabling IPv6")
        # Needs to be removed eventually. I'll leave it in for now
        # so it still properly restores the IPv6 address the old way
        if os.path.isfile(ipv6_backupfile):
            manage_ipv6("legacy_restore")

        if os.path.isfile(ip6tables_backupfile):
            logger.debug("IPv6 backup exists")
            manage_ipv6("restore")

        if is_ipv6_disabled():
            logger.debug("IPv6 is disabled or unavailable, skipping leak protection")
            return

        # Backing up ip6ables rules
        logger.debug("Backing up ip6tables rules")
        ip6tables_rules = subprocess.run(["ip6tables-save"],
                                         stdout=subprocess.PIPE)

        if "COMMIT" in ip6tables_rules.stdout.decode():
            with open(ip6tables_backupfile, "wb") as f:
                f.write(ip6tables_rules.stdout)
        else:
            with open(ip6tables_backupfile, "w") as f:
                f.write("*filter\n")
                f.write(":INPUT ACCEPT\n")
                f.write(":FORWARD ACCEPT\n")
                f.write(":OUTPUT ACCEPT\n")
                f.write("COMMIT\n")

        # Get the default nic from ip route show output
        default_nic = get_default_nic()

        ip6tables_commands = [
            "ip6tables -A INPUT -i {0} -j DROP".format(default_nic),
            "ip6tables -A OUTPUT -o {0} -j DROP".format(default_nic),
        ]
        for command in ip6tables_commands:
            command = command.split()
            subprocess.run(command)
        logger.debug("IPv6 disabled successfully")

    elif mode == "restore":
        logger.debug("Restoring ip6tables")
        # Same as above, remove eventually
        if os.path.isfile(ipv6_backupfile):
            logger.debug("legacy ipv6 backup found")
            manage_ipv6("legacy_restore")
        if os.path.isfile(ip6tables_backupfile):
            subprocess.run(
                "ip6tables-restore < {0}".format(
                    ip6tables_backupfile
                ), shell=True, stdout=subprocess.PIPE
            )
            logger.debug("ip6tables restored")
            os.remove(ip6tables_backupfile)
            logger.debug("ip6tables.backup removed")
        else:
            logger.debug("No Backupfile found")
        return

    elif mode == "legacy_restore":
        logger.debug("Restoring IPv6")
        if not os.path.isfile(ipv6_backupfile):
            logger.debug("No Backupfile found")
            return

        with open(ipv6_backupfile, "r") as f:
            lines = f.readlines()
            default_nic = lines[0].strip()
            ipv6_addr = lines[1].strip()

        ipv6_info = subprocess.run(
            "ip addr show dev {0} | grep '\<inet6.*global\>'".format(default_nic), # noqa
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        has_ipv6 = True if ipv6_info.returncode == 0 else False

        if has_ipv6:
            logger.debug("IPv6 address present")
            os.remove(ipv6_backupfile)
            return

        ipv6_enable = subprocess.run(
            "sysctl -w net.ipv6.conf.{0}.disable_ipv6=0".format(default_nic),
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        if not ipv6_enable.returncode == 0:
            print(
                "[!] There was an error with restoring the IPv6 configuration"
            )
            logger.debug("IPv6 restoration error: sysctl")
            logger.debug("stdout: {0}".format(ipv6_enable.stdout))
            logger.debug("stderr: {0}".format(ipv6_enable.stderr))
            return

        ipv6_restore_address = subprocess.run(
            "ip addr add {0} dev {1}".format(ipv6_addr, default_nic),
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        if not ipv6_restore_address.returncode == 0:
            print(
                "[!] There was an error with restoring the IPv6 configuration"
            )
            logger.debug("IPv6 restoration error: ip")
            logger.debug("stdout: {0}".format(ipv6_restore_address.stdout))
            logger.debug("stderr: {0}".format(ipv6_restore_address.stderr))
            return

        logger.debug("Removing IPv6 backup file")
        os.remove(ipv6_backupfile)
        logger.debug("IPv6 restored")

    else:
        raise Exception("Invalid argument provided. "
                        "Mode must be 'disable' or 'restore'")


def manage_killswitch(mode, proto=None, port=None):
    """
    Disable and enable the VPN Kill Switch.

    The Kill Switch creates IPTables rules that only allow connections to go
    through the OpenVPN device. If the OpenVPN process stops for some unknown
    reason this will completely block access to the internet.
    """

    backupfile = os.path.join(CONFIG_DIR, "iptables.backup")

    if mode == "restore":
        logger.debug("Restoring iptables")
        if os.path.isfile(backupfile):
            logger.debug("Restoring IPTables rules")
            subprocess.run("iptables-restore < {0}".format(backupfile),
                           shell=True, stdout=subprocess.PIPE)
            logger.debug("iptables restored")
            os.remove(backupfile)
            logger.debug("iptables.backup removed")
        else:
            logger.debug("No Backupfile found")
        return

    # Stop if Kill Switch is disabled
    if not int(get_config_value("USER", "killswitch")):
        return

    if mode == "enable":
        if os.path.isfile(backupfile):
            logger.debug("Kill Switch backup exists")
            manage_killswitch("restore")

        with open(os.path.join(CONFIG_DIR, "ovpn.log"), "r") as f:
            content = f.read()
            device = re.search(r"(TUN\/TAP device) (.+) opened", content)
            if not device:
                print("[!] Kill Switch activation failed."
                      "Device couldn't be determined.")
                logger.debug(
                    "Kill Switch activation failed. No device in logfile"
                )
            device = device.group(2)

        # Backing up IPTables rules
        logger.debug("Backing up iptables rules")
        iptables_rules = subprocess.run(["iptables-save"],
                                        stdout=subprocess.PIPE)

        if "COMMIT" in iptables_rules.stdout.decode():
            with open(backupfile, "wb") as f:
                f.write(iptables_rules.stdout)
        else:
            with open(backupfile, "w") as f:
                f.write("*filter\n")
                f.write(":INPUT ACCEPT\n")
                f.write(":FORWARD ACCEPT\n")
                f.write(":OUTPUT ACCEPT\n")
                f.write("COMMIT\n")

        # Creating Kill Switch rules
        iptables_commands = [
            "iptables -F",
            "iptables -P INPUT DROP",
            "iptables -P OUTPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o {0} -j ACCEPT".format(device),
            "iptables -A INPUT -i {0} -j ACCEPT".format(device),
            "iptables -A OUTPUT -o {0} -m state --state ESTABLISHED,RELATED -j ACCEPT".format(device), # noqa
            "iptables -A INPUT -i {0} -m state --state ESTABLISHED,RELATED -j ACCEPT".format(device), # noqa
            "iptables -A OUTPUT -p {0} -m {1} --dport {2} -j ACCEPT".format(proto.lower(), proto.lower(), port), # noqa
            "iptables -A INPUT -p {0} -m {1} --sport {2} -j ACCEPT".format(proto.lower(), proto.lower(), port), # noqa
        ]

        if int(get_config_value("USER", "killswitch")) == 2:
            # Getting local network information
            default_nic = get_default_nic()
            local_network = subprocess.run(
                "ip addr show {0} | grep inet".format(default_nic),
                stdout=subprocess.PIPE, shell=True
            )
            local_network = local_network.stdout.decode().strip().split()[1]

            exclude_lan_commands = [
                "iptables -A OUTPUT -o {0} -d {1} -j ACCEPT".format(default_nic, local_network), # noqa
                "iptables -A INPUT -i {0} -s {1} -j ACCEPT".format(default_nic, local_network), # noqa
            ]

            for lan_command in exclude_lan_commands:
                iptables_commands.append(lan_command)

        for command in iptables_commands:
            command = command.split()
            subprocess.run(command)
        logger.debug("Kill Switch enabled")

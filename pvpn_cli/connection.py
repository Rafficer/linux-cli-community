# Standard Libraries
import os
import sys
import subprocess
import time
import shutil
import random
import re
import fileinput
import configparser
import datetime
import zlib
# External Libraries
from dialog import Dialog
from .logger import logger
# pvpn-cli Functions
from .utils import (
    check_init, pull_server_data, is_connected,
    get_servers, get_server_value, get_config_value,
    set_config_value, get_ip_info, get_country_name,
    get_fastest_server
)
# Constants
from .constants import (
    CONFIG_DIR, TEMPLATE_FILE, OVPN_FILE, PASSFILE, CONFIG_FILE
)


def dialog():
    """Connect to a server with a dialog menu."""
    def show_dialog(headline, choices, stop=False):
        """Show the dialog and process response."""
        d = Dialog(dialog="dialog")

        logger.debug("Showing Dialog: {0}".format(headline))

        code, tag = d.menu(headline, title="PVPN-CLI", choices=choices)
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
        choices.append((servername, "Load: {0}% | {1}".format(load, feature)))

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
        if server["Features"] not in excluded_features \
         and server["ExitCountry"] == country_code:
            server_pool.append(server)

    if len(server_pool) == 0:
        print(
            "[!] No Server in country {0} found\n".format(country_code),
            "[!] Please choose a valid country"
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
        print(servername)
    elif re_long.search(user_input):
        user_server = re_long.search(user_input)
        country_code = user_server.group(3)
        country_code2 = user_server.group(5)
        number = user_server.group(7).lstrip("0")
        tor = user_server.group(8)
        servername = "{0}-{1}#{2}".format(country_code,
                                          country_code2, number) + \
                     "{0}".format('-' + tor if tor is not None else '')
        servername = (servername)
    else:
        print(
            "[!] '{0}' is not a valid servername\n".format(user_input),
            "[!] Please enter a valid servername"
        )
        logger.debug("'{0}' is not a valid servername'".format(user_input))
        sys.exit(1)

    servers = get_servers()

    if servername not in [server["Name"] for server in servers]:
        print(
            "[!] {servername} doesn't exist or inaccessible with your plan.\n"
            .format(servername),
            "[!] Please enter a valid servername."
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
    pull_server_data()
    logger.debug("Getting VPN Status")

    # Quit if not connected
    if not is_connected():
        logger.debug("Disconnected")
        ip, isp = get_ip_info()
        print("Status:     Disconnected")
        print("IP:         {0}".format(ip))
        print("ISP:        {0}".format(isp))

        if os.path.isfile(os.path.join(CONFIG_DIR, "iptables.backup")):
            print("[!] Killswitch is active. Run pvpn_cli disconnect.")
            logger.debug("Killswitch active while VPN disconnected")
        return

    try:
        connected_server = get_config_value("metadata", "connected_server")
        connected_protocol = get_config_value("metadata", "connected_proto")
        dns_server = get_config_value("metadata", "dns_server")
    except KeyError:
        print("It looks like there never was a connection.\n"
              "Please connect with 'pvpn-cli c' first.")
        sys.exit(1)

    # Check if the VPN Server is reachable
    ping = subprocess.run(["ping", "-c", "1", dns_server],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if ping.returncode != 0:
        logger.debug("Could not reach VPN server")
        print("[!] Could not reach the VPN Server")
        print("[!] You may want to reconnect with 'pvpn-cli reconnect'")
        return

    servers = get_servers()

    subs = [s["Servers"] for s in servers if s["Name"] == connected_server][0]
    server_ips = [subserver["ExitIP"] for subserver in subs]

    ip, isp = get_ip_info()

    if ip not in server_ips:
        logger.debug("IP not found in connected_server IPs")
        print("[!] Your IP was not found in last Servers IPs\n"
              "[!] Maybe you're not connected to a ProtonVPN Server")
        sys.exit(1)

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

    # Print Status Output
    logger.debug("Printing status")
    print(
        "Status:       Connected\n",
        "Time:         {0}\n".format(connection_time),
        "IP:           {0}\n".format(ip),
        "Server:       {0}\n".format(connected_server),
        "Features:     {0}\n".format(all_features[feature]),
        "Protocol:     {0}\n".format(connected_protocol.upper()),
        "Killswitch:   {0}\n".format(killswitch_status),
        "Country:      {0}\n".format(country),
        "City:         {0}\n".format(city),
        "Load:         {0}%".format(load),
    )


def openvpn_connect(servername, protocol):
    """Connect to VPN Server."""

    logger.debug("Initiating OpenVPN connection")
    logger.debug(
        "Connecting to {0} via {1}".format(servername, protocol.upper())
    )

    port = {"udp": 1194, "tcp": 443}

    shutil.copyfile(TEMPLATE_FILE, OVPN_FILE)

    servers = get_servers()
    subservers = get_server_value(servername, "Servers", servers)
    ip_list = [subserver["EntryIP"] for subserver in subservers]

    with open(OVPN_FILE, "a") as f:
        f.write("\n\n")
        f.write("proto {0}\n".format(protocol.lower()))
        for ip in ip_list:
            f.write("remote {0} {1}\n".format(ip, port[protocol.lower()]))
        logger.debug("IPs: {0}".format(ip_list))
        logger.debug("connect.ovpn written")

    if is_connected():
        disconnect(passed=True)

    old_ip, _ = get_ip_info()

    print("Connecting to {0} via {1}...".format(servername, protocol.upper()))

    with open(os.path.join(CONFIG_DIR, "ovpn.log"), "w+") as f:
        subprocess.Popen(
            [
                "openvpn",
                "--config", OVPN_FILE,
                "--auth-user-pass", PASSFILE
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
                print("Connection timed out after 45 Seconds")
                logger.debug("Connection timed out after 45 Seconds")
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


def manage_dns(mode, dns_server=False):
    """
    Manage resolv.conf to circumvent DNS Leaks.

    Has 2 modes (string): leak_protection / restore
    leak_protection: Replace the current resolv.conf entries with ProtonVPN DNS
    restore: Revert changes and restore original configuration
    """

    backupfile = os.path.join(CONFIG_DIR, "resolv.conf.backup")

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

        shutil.copy2("/etc/resolv.conf", backupfile)
        logger.debug("resolv.conf backed up")

        # Remove previous nameservers
        dns_regex = re.compile(r"^nameserver .*$")

        for line in fileinput.input("/etc/resolv.conf", inplace=True):
            if not dns_regex.search(line) and not dns_regex.search(line):
                print(line, end="")
        logger.debug("Removed existing DNS Servers")

        # Add ProtonVPN DNS Server to resolv.conf
        with open("/etc/resolv.conf", "a") as f:
            f.write("# ProtonVPN DNS Servers. Managed by pvpn-cli.\n")
            f.write("nameserver {0}\n".format(dns_server))
            logger.debug("Added ProtonVPN or custom DNS")

        # Write the hash of the edited file in the configuration
        #
        # This is so it doesn't restore an old DNS configuration
        # if the configuration changes during a VPN session
        # (e.g. by switching networks)

        with open("/etc/resolv.conf", "rb") as f:
            filehash = zlib.crc32(f.read())
        set_config_value("metadata", "resolvconf_hash", filehash)

    elif mode == "restore":
        logger.debug("Restoring DNS")
        if os.path.isfile(backupfile):

            # Check if the file changed since connection
            oldhash = get_config_value("metadata", "resolvconf_hash")
            with open("/etc/resolv.conf", "rb") as f:
                filehash = zlib.crc32(f.read())

            if filehash == int(oldhash):
                shutil.copy2(backupfile, "/etc/resolv.conf")
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

    if mode == "disable":

        logger.debug("Disabling IPv6")
        if os.path.isfile(ipv6_backupfile):
            manage_ipv6("restore")

        default_route = subprocess.run(
            "ip route show | grep default",
            stdout=subprocess.PIPE, shell=True
        )

        # Get the default nic from ip route show output
        default_nic = default_route.stdout.decode().strip().split()[4]

        ipv6_info = subprocess.run(
            "ip addr show dev {0} | grep '\<inet6.*global\>'".format(default_nic), # noqa
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
        )

        has_ipv6 = True if ipv6_info.returncode == 0 else False

        # Stop configuration if not IPv6 address is present
        if not has_ipv6:
            logger.debug("No IPv6 present")
            return

        # Get the actual IPv6 address
        ipv6_addr = ipv6_info.stdout.decode().strip().split()[1]

        logger.debug("Writing backup file")
        with open(ipv6_backupfile, "w") as f:
            f.write("{0}\n".format(default_nic))
            f.write(ipv6_addr)

        ipv6_disable = subprocess.run(
            "sysctl -w net.ipv6.conf.{0}.disable_ipv6=1".format(default_nic),
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        if not ipv6_disable.returncode == 0:
            print("[!] There was an error with disabling IPv6")
            logger.debug("Error with disabling IPv6")
            logger.debug("stdout: {0}".format(ipv6_disable.stdout))
            logger.debug("stderr: {0}".format(ipv6_disable.stderr))
        else:
            logger.debug("Successfully disabled IPv6")

    elif mode == "restore":
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
    Disable and enable the VPN Killswitch.

    The Killswitch creates IPTables rules that only allow connections to go
    through the OpenVPN device. If the OpenVPN process stops for some unkown
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

    # Stop if killswitch is disabled
    if not int(get_config_value("USER", "killswitch")):
        return

    if mode == "enable":
        if os.path.isfile(backupfile):
            logger.debug("Killswitch backup exists")
            manage_killswitch("restore")

        with open(os.path.join(CONFIG_DIR, "ovpn.log"), "r") as f:
            content = f.read()
            device = re.search(r"(TUN\/TAP device) (.+) opened", content)
            if not device:
                print("[!] Killswitch activation failed."
                      "Device couldn't be determined.")
                logger.debug(
                    "Killswitch activation failed. No device in logfile"
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

        # Creating Killswitch rules
        iptables_commands = [
            "iptables -F",
            "iptables -P INPUT DROP",
            "iptables -P OUTPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -A OUTPUT -o {0} -j ACCEPT".format(device),
            "iptables -A INPUT -i {0} -j ACCEPT".format(device),
            "iptables -A OUTPUT -o {0} -m state --state ESTABLISHED,RELATED -j ACCEPT".format(device), # noqa
            "iptables -A INPUT -i {0} -m state --state ESTABLISHED,RELATED -j ACCEPT".format(device), # noqa
            "iptables -A OUTPUT -p {0} -m {1} --dport {2} -j ACCEPT".format(proto.lower(), proto.lower(), port), # noqa
            "iptables -A INPUT -p {0} -m {1} --sport {2} -j ACCEPT".format(proto.lower(), proto.lower(), port), # noqa
        ]

        for command in iptables_commands:
            command = command.split()
            subprocess.run(command)
        logger.debug("Killswitch enabled")

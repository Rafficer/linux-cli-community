# Standard Libraries
import os
import sys
import configparser
import time
import json
import subprocess
import re
import fileinput
import getpass
import random
# External Libraries
import requests
from .logger import logger
# Constants
from .constants import (
    USER, CONFIG_FILE, SERVER_INFO_FILE, TEMPLATE_FILE
)


def call_api(url, json_format=True):
    """Call to the ProtonMail API at https://api.protonmail.ch."""
    headers = {
        "x-pm-appversion": "Other",
        "x-pm-apiversion": "3",
        "Accept": "application/vnd.protonmail.v1+json"
    }

    logger.debug("Initiating API Call: {0}".format(url))

    try:
        response = requests.get(url, headers=headers)
    except (requests.exceptions.ConnectionError,
            requests.exceptions.ConnectTimeout):
        print(
            "[!] There was an error connecting to the ProtonMail API.\n"
            "[!] Please make sure your connection is working properly!"
        )
        logger.debug("Error connecting to ProtonMail API")
        sys.exit(1)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        print(
            "[!] There was an error with accessing the ProtonMail API.\n"
            "[!] Please make sure your connection is working properly!\n"
            "[!] HTTP Error Code: {0}".format(response.status_code)
        )
        logger.debug("Bad Return Code: {0}".format(response.status_code))
        sys.exit(1)

    if json_format:
        logger.debug("Successful json response")
        return response.json()
    else:
        logger.debug("Successful non-json response")
        return response


def pull_server_data(force=False):
    """Pull current server data from the ProtonMail API."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not force:
        # Check if last server pull happened within the last 15 min (900 sec)
        if int(time.time()) - int(config["metadata"]["last_api_pull"]) <= 900:
            logger.debug("Last server pull within 15mins")
            return

    data = call_api("https://api.protonmail.ch/vpn/logicals")

    with open(SERVER_INFO_FILE, "w") as f:
        json.dump(data, f)
        logger.debug("SERVER_INFO_FILE written")

    change_file_owner(SERVER_INFO_FILE)
    config["metadata"]["last_api_pull"] = str(int(time.time()))

    with open(CONFIG_FILE, "w+") as f:
        config.write(f)
        logger.debug("last_api_call updated")


def get_servers():
    """Return a list of all servers for the users Tier."""

    with open(SERVER_INFO_FILE, "r") as f:
        logger.debug("Reading servers from file")
        server_data = json.load(f)

    servers = server_data["LogicalServers"]

    user_tier = int(get_config_value("USER", "tier"))

    # Sort server IDs by Tier
    return [server for server in servers if server["Tier"] <= user_tier and server["Status"] == 1] # noqa


def get_server_value(servername, key, servers):
    """Return the value of a key for a given server."""
    value = [server[key] for server in servers if server['Name'] == servername]
    return value[0]


def get_config_value(group, key):
    """Return specific value from CONFIG_FILE as string"""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    return config[group][key]


def set_config_value(group, key, value):
    """Write a specific value to CONFIG_FILE"""

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    config[group][key] = str(value)

    logger.debug(
        "Writing {0} to [{1}] in config file".format(key, group)
    )

    with open(CONFIG_FILE, "w+") as f:
        config.write(f)


def get_ip_info():
    """Return the current public IP Address"""
    logger.debug("Getting IP Information")
    ip_info = call_api("https://api.protonmail.ch/vpn/location")

    ip = ip_info["IP"]
    isp = ip_info["ISP"]

    return ip, isp


def get_country_name(code):
    """Return the full name of a country from code"""

    # Very abstract to make it work with pyinstaller and python
    cc_file = os.path.join(os.path.split(
        os.path.abspath(__file__))[0], "country_codes.json"
    )

    with open(cc_file, "r") as f:
        cc_to_name = json.load(f)["cc_to_name"]

    try:
        return cc_to_name[code]
    except KeyError:
        return code


def get_fastest_server(server_pool):
    """Return the fastest server from a list of servers"""

    # Sort servers by "speed" and select top n according to pool_size
    fastest_pool = sorted(
        server_pool, key=lambda server: server["Score"]
    )
    if len(fastest_pool) >= 50:
        pool_size = 4
    else:
        pool_size = 1
    logger.debug(
        "Returning fastest server with pool size {0}".format(pool_size)
    )
    fastest_server = random.choice(fastest_pool[:pool_size])["Name"]
    return fastest_server


def is_connected():
    """Check if a VPN connection already exists."""
    ovpn_processes = subprocess.run(["pgrep", "openvpn"],
                                    stdout=subprocess.PIPE)
    ovpn_processes = ovpn_processes.stdout.decode("utf-8").split()

    logger.debug(
        "Checking connection Status. OpenVPN processes: {0}"
        .format(len(ovpn_processes))
        )
    return True if ovpn_processes != [] else False


def make_ovpn_template():
    """Create OpenVPN template file."""
    pull_server_data()

    with open(SERVER_INFO_FILE, "r") as f:
        server_data = json.load(f)

    # Get the ID of the first server from the API
    server_id = server_data["LogicalServers"][0]["ID"]

    config_file_response = call_api(
        "https://api.protonmail.ch/vpn/config?Platform=linux&LogicalID={0}&Protocol=tcp".format(server_id),  # noqa
        json_format=False
    )

    with open(TEMPLATE_FILE, "wb") as f:
        for chunk in config_file_response.iter_content(100000):
            f.write(chunk)
            logger.debug("OpenVPN config file downloaded")

    # Remove all remote, proto, up, down and script-security lines
    # from template file
    remove_regex = re.compile(r"^(remote|proto|up|down|script-security) .*$")

    for line in fileinput.input(TEMPLATE_FILE, inplace=True):
        if not remove_regex.search(line):
            print(line, end="")

    logger.debug("remote and proto lines removed")

    change_file_owner(TEMPLATE_FILE)


def change_file_owner(path):
    """Change the owner of specific files to the sudo user."""
    uid = int(subprocess.run(["id", "-u", USER],
                             stdout=subprocess.PIPE).stdout)
    gid = int(subprocess.run(["id", "-u", USER],
                             stdout=subprocess.PIPE).stdout)

    current_owner = subprocess.run(["id", "-nu", str(os.stat(path).st_uid)],
                                   stdout=subprocess.PIPE).stdout
    current_owner = current_owner.decode().rstrip("\n")

    # Only change file owner if it wasn't owned by current running user.
    if current_owner != USER:
        os.chown(path, uid, gid)
        logger.debug("Changed owner of {0} to {1}".format(path, USER))


def check_root():
    """Check if the program was executed as root and prompt the user."""
    if getpass.getuser() != "root":
        print(
            "[!] The program was not executed as root.\n"
            "[!] Plase run as root"
        )
        logger.debug("Program was executed as root")
        sys.exit(1)
    else:
        # Check for dependencies
        dependencies = ["openvpn", "ip", "sysctl", "pgrep", "pkill"]
        for program in dependencies:
            check = subprocess.run(["which", program],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            if not check.returncode == 0:
                logger.debug("{0} not found".format(program))
                print("'{0}' not found. \n".format(program),
                      "Please install {0}.".format(program))


def check_init(check_props=True):
    """Check if a profile has been initialized, quit otherwise."""

    try:
        if not int(get_config_value("USER", "initialized")):
            print(
                "[!] There has been no profile initialized yet. "
                "Please run 'pvpn-cli init'."
            )
            logger.debug("Initialized Profile not found")
            sys.exit(1)
        elif check_props:
            # Check if required properties are set.
            # This is to ensure smooth updates so the user can be warned
            # when a property is missing and can be ordered
            # to run `pvpn-cli configure` or something else.

            required_props = ["username", "tier", "default_protocol",
                              "dns_leak_protection", "custom_dns"]

            for prop in required_props:
                try:
                    get_config_value("USER", prop)
                except KeyError:
                    print(
                        "[!] {0} is missing from configuration.\n".format(prop), # noqa
                        "[!] Please run 'pvpn-cli configure' to set it."
                    )
                    logger.debug(
                        "{0} is missing from configuration".format(prop)
                    )
                    sys.exit(1)
    except KeyError:
        print(
            "[!] There has been no profile initialized yet. "
            "Please run 'pvpn-cli init'."
        )
        logger.debug("Initialized Profile not found")
        sys.exit(1)

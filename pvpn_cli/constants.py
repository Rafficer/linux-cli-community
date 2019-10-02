import os
import getpass

try:
    USER = os.environ["SUDO_USER"]
except KeyError:
    USER = getpass.getuser()

CONFIG_DIR = os.path.join(os.path.expanduser("~{0}".format(USER)), ".pvpn-cli")
CONFIG_FILE = os.path.join(CONFIG_DIR, "pvpn-cli.cfg")
TEMPLATE_FILE = os.path.join(CONFIG_DIR, "template.ovpn")
SERVER_INFO_FILE = os.path.join(CONFIG_DIR, "serverinfo.json")
OVPN_FILE = os.path.join(CONFIG_DIR, "connect.ovpn")
PASSFILE = os.path.join(CONFIG_DIR, "pvpnpass")
VERSION = "0.1.0"

import os
import getpass
import pwd

# This implementation is mostly for GUI support. See #168
try:
    USER = pwd.getpwuid(int(os.environ["PKEXEC_UID"])).pw_name
except KeyError:
    try:
        USER = os.environ["SUDO_USER"]
    except KeyError:
        USER = getpass.getuser()

CONFIG_DIR = os.path.join(os.path.expanduser("~{0}".format(USER)), ".pvpn-cli")
CONFIG_FILE = os.path.join(CONFIG_DIR, "pvpn-cli.cfg")
SERVER_INFO_FILE = os.path.join(CONFIG_DIR, "serverinfo.json")
SERVER_FEATURES = {
    1: "Secure-Core",
    2: "Tor",
    4: "P2P",
    8: "Streaming",
}
SPLIT_TUNNEL_FILE = os.path.join(CONFIG_DIR, "split_tunnel.txt")
OVPN_FILE = os.path.join(CONFIG_DIR, "connect.ovpn")
PASSFILE = os.path.join(CONFIG_DIR, "pvpnpass")
CLIENT_SUFFIX = "plc"  # ProtonVPN Linux Community
VERSION = "2.2.12"

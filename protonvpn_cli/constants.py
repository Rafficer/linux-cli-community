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
SPLIT_TUNNEL_FILE = os.path.join(CONFIG_DIR, "split_tunnel.txt")
OVPN_FILE = os.path.join(CONFIG_DIR, "connect.ovpn")
PASSFILE = os.path.join(CONFIG_DIR, "pvpnpass")
VERSION = "2.2.4"

USAGE = """
ProtonVPN CLI

Usage:
    protonvpn init
    protonvpn (c | connect) [<servername>] [-p <protocol>]
    protonvpn (c | connect) [-f | --fastest] [-p <protocol>]
    protonvpn (c | connect) [--cc <code>] [-p <protocol>]
    protonvpn (c | connect) [--sc] [-p <protocol>]
    protonvpn (c | connect) [--p2p] [-p <protocol>]
    protonvpn (c | connect) [--tor] [-p <protocol>]
    protonvpn (c | connect) [-r | --random] [-p <protocol>]
    protonvpn (r | reconnect)
    protonvpn (d | disconnect)
    protonvpn (s | status)
    protonvpn (cf | configure)
    protonvpn (rf | refresh)
    protonvpn (ex | examples)
    protonvpn (-h | --help)
    protonvpn (-v | --version)

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
    cf, configure       Change ProtonVPN-CLI configuration.
    rf, refresh         Refresh OpenVPN configuration and server data.
    ex, examples        Print some example commands.

Arguments:
    <servername>        Servername (CH#4, CH-US-1, HK5-Tor).
"""

import os
import getpass

try:
    USER = os.environ["SUDO_USER"]
except KeyError:
    USER = getpass.getuser()

# Ensure backwards compatibility
home_path = os.path.expanduser("~{0}".format(USER))
home_config = os.path.join(home_path, ".pvpn-cli")
if os.path.exists(home_config):
    CONFIG_DIR = home_config
    DATA_DIR = home_config
    CACHE_DIR = home_config

else:
    # Get the config directory
    xdg_config_str = os.getenv("XDG_CONFIG_HOME")
    if not xdg_config_str:
        xdg_config = os.path.join(home_path, ".config")
    else:
        xdg_config = os.path.realpath(xdg_config_str)
    CONFIG_DIR = os.path.join(xdg_config, "pvpn-cli")

    # Get the data directory
    xdg_data_str = os.getenv("XDG_DATA_HOME")
    if not xdg_data_str:
        xdg_data = os.path.join(home_path, ".local/share")
    else:
        xdg_data = os.path.realpath(xdg_data_str)
    DATA_DIR = os.path.join(xdg_data, "pvpn-cli")

    # Get the cache directory
    xdg_cache_str = os.getenv("XDG_CACHE_HOME")
    if not xdg_cache_str:
        xdg_cache = os.path.join(home_path, ".cache")
    else:
        xdg_cache = os.path.realpath(xdg_cache_str)
    CACHE_DIR = os.path.join(xdg_cache, "pvpn-cli")


CONFIG_FILE = os.path.join(CONFIG_DIR, "pvpn-cli.cfg")
TEMPLATE_FILE = os.path.join(CACHE_DIR, "template.ovpn")
SERVER_INFO_FILE = os.path.join(CACHE_DIR, "serverinfo.json")
SPLIT_TUNNEL_FILE = os.path.join(DATA_DIR, "split_tunnel.txt")
OVPN_FILE = os.path.join(DATA_DIR, "connect.ovpn")
PASSFILE = os.path.join(DATA_DIR, "pvpnpass")
VERSION = "2.2.0"

import re

# local
from utils.helpers import run_suppressed_cmd


###########################
##### wlan interfaces #####
###########################
def get_wlan_interfaces() -> list:
    """
    Gather available wireless interfaces by running the 'iw dev' command.
    Returns a list of interface names, or None if none are found.
    """
    output = run_suppressed_cmd("iw dev")
    interfaces = []
    for line in output.splitlines():
        line = line.strip()
        # Look for lines that start with "Interface"
        if line.startswith("Interface"):
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[1]
                if re.match(r'^[a-zA-Z0-9_-]+$', iface):
                    interfaces.append(iface)
    return interfaces if interfaces else None

def get_gateway_for_interface(iface: str) -> str:
    """
    Retrieve the default gateway for the given interface using 'ip route show default'.
    """
    output = run_suppressed_cmd("ip route show default")
    for line in output.splitlines():
        if iface in line:
            parts = line.split()
            try:
                via_index = parts.index("via")
                return parts[via_index + 1]
            except (ValueError, IndexError):
                return ""
    return ""

def get_ip_for_interface(iface: str) -> str:
    """
    Retrieve the IPv4 address for the given interface using 'ip addr show <iface>'.
    """
    output = run_suppressed_cmd(f"ip addr show {iface}")
    for line in output.splitlines():
        line = line.strip()
        # Look for a line that starts with "inet " but excludes inet6.
        if line.startswith("inet ") and "inet6" not in line:
            parts = line.split()
            try:
                # The IP address is usually in the format "192.168.8.174/24"
                return parts[1].split('/')[0]
            except IndexError:
                return ""
    return ""

def get_mac_for_interface(iface: str) -> str:
    """
    Retrieve the MAC address for the given interface.
    """
    output = run_suppressed_cmd(f"cat /sys/class/net/{iface}/address")
    return output.strip()

def get_protocol_for_interface(iface: str) -> str:
    """
    Determine the protocol type for the given interface.
    For example, if the interface name contains 'wlan' or 'wlx', assume 'wlan'.
    """
    if "wlan" in iface or "wlx" in iface:
        return "wlan"
    return "unknown"
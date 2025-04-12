import logging
import os
import re
import subprocess
import time

# local
from utils.helpers import run_suppressed_cmd


######################
##### interfaces #####
######################
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

def get_eth_interfaces() -> list:
    """
    Gather available Ethernet interfaces by listing /sys/class/net,
    excluding wireless (wlan, wlx, etc.) and loopback.
    Returns a list of interface names, or None if none are found.
    """
    try:
        all_ifaces = os.listdir('/sys/class/net')
    except Exception:
        return None

    eth_ifaces = []
    for iface in all_ifaces:
        # Exclude loopback
        if iface == 'lo':
            continue
        # Exclude known wireless prefixes
        if re.match(r'^(wlan|wlx|wifi)', iface):
            continue
        # Ensure valid name
        if re.match(r'^[a-zA-Z0-9_-]+$', iface):
            eth_ifaces.append(iface)

    return eth_ifaces if eth_ifaces else None

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

def get_netmask_for_interface(iface: str) -> str:
    """
    Retrieve the netmask (in dotted decimal format) for the given interface.
    Parses the output of 'ip addr show <iface>' and converts the CIDR suffix.
    """
    from utils.helpers import run_suppressed_cmd  # use your helper for command execution
    output = run_suppressed_cmd(f"ip addr show {iface}")
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet ") and "inet6" not in line:
            parts = line.split()
            try:
                # parts[1] is like "192.168.1.100/24"
                ip_cidr = parts[1]
                ip, cidr_str = ip_cidr.split('/')
                cidr = int(cidr_str)
                # Convert CIDR to dotted decimal netmask
                mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
                netmask = "{}.{}.{}.{}".format(
                    (mask >> 24) & 0xff,
                    (mask >> 16) & 0xff,
                    (mask >> 8) & 0xff,
                    mask & 0xff
                )
                return netmask
            except (IndexError, ValueError):
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
    Check /sys/class/net/<iface>/wireless existence to detect wireless,
    otherwise treat as Ethernet.
    """
    wireless_path = f"/sys/class/net/{iface}/wireless"
    if os.path.isdir(wireless_path):
        return "wlan"
    # If there's a device type file, you can inspect it; but default to eth
    return "eth"

def set_interface_to_monitor(iface: str, stage_delay: float = 1.0) -> bool:
    """
    Attempts to set the given interface to monitor mode in stages.
    This function:
      1. Brings the interface down.
      2. Sets the interface type to monitor.
      3. Brings the interface up.
      4. Checks that the final state has the interface UP and in monitor mode.

    :param iface: The interface name.
    :param stage_delay: Delay between stages to allow changes to propagate.
    :return: True if the interface is up and in monitor mode, False otherwise.
    """
    # Stage 1: Bring the interface down.
    logging.debug("Bringing interface %s down...", iface)
    try:
        run_suppressed_cmd(f"ip link set {iface} down")
    except Exception as e:
        logging.error("Failed to bring %s down: %s", iface, e)
        return False
    time.sleep(stage_delay)

    # Stage 2: Set the interface to monitor mode.
    logging.debug("Setting interface %s to monitor mode...", iface)
    try:
        run_suppressed_cmd(f"iw dev {iface} set type monitor")
    except Exception as e:
        logging.error("Failed to set %s to monitor mode: %s", iface, e)
        return False
    time.sleep(stage_delay)

    # Stage 3: Bring the interface up.
    logging.debug("Bringing interface %s up...", iface)
    try:
        run_suppressed_cmd(f"ip link set {iface} up")
    except Exception as e:
        logging.error("Failed to bring %s up: %s", iface, e)
        return False
    time.sleep(stage_delay)

    # Final Check: Ensure the interface is UP and in monitor mode.
    mode = get_iw_mode(iface)
    up = is_interface_up(iface)
    logging.debug("Final check for %s: mode=%s, up=%s", iface, mode, up)
    return (mode.lower() == "monitor") and up

def get_iw_mode(iface: str) -> str:
    """
    Determine the interface mode for the given interface (e.g., monitor, managed).
    Parses the output of the "iw dev <iface>" command and returns the mode.
    """
    try:
        output = run_suppressed_cmd(f"iw dev {iface} info")
    except subprocess.CalledProcessError as e:
        logging.getLogger(__name__).error("Failed to get interface details: %s", e)
        return "error"

    # Parse the output to find the "type" line
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("type"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]  # e.g., "monitor" or "managed"
    return "unknown"

def ip_link_down(iface: str) -> bool:
    """
    set interface down
    :param iface: interface to set down
    :return:
    """
    try:
        run_suppressed_cmd(f"ip link set {iface} down")
    except subprocess.CalledProcessError as e:
        logging.getLogger(__name__).error(e)
        return False

def ip_link_up(iface: str) -> bool:
    """
    set interface up
    :param iface:
    :return:
    """
    try:
        run_suppressed_cmd(f"ip link set {iface} up")
    except subprocess.CalledProcessError as e:
        logging.getLogger(__name__).error(e)
        return False

def iw_monitor(iface: str) -> bool:
    """
    set interface monitor
    :param iface: interface to set monitor mode
    :return: 
    """
    try:
        run_suppressed_cmd(f"iw dev {iface} set type monitor")
    except subprocess.CalledProcessError as e:
        logging.getLogger(__name__).error(e)
        return False

def iw_managed(iface: str) -> bool:
    """
    Set interface managed
    :param iface:
    :return:
    """
    try:
        run_suppressed_cmd(f"iw dev {iface} set type managed")
    except subprocess.CalledProcessError as e:
        logging.getLogger(__name__).error(e)
        return False

def is_interface_up(iface: str) -> bool:
    """
    Checks if the interface is up.
    """
    try:
        output = run_suppressed_cmd(f"ip link show {iface}")
    except Exception as e:
        logging.error("Error checking interface %s status: %s", iface, e)
        return False
    # Look for a keyword indicating "UP" in the output.
    return "UP" in output



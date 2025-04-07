import os
import logging
from mac_vendor_lookup import MacLookup, BaseMacLookup
from config.paths import OUI_CACHE_PATH

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Override the default cache path
BaseMacLookup.cache_path = OUI_CACHE_PATH
logger.debug("Using custom cache path: %s", OUI_CACHE_PATH)

# Create a persistent MacLookup instance.
mac = MacLookup()


def check_and_update_vendors():
    """
    Check if the vendor cache exists and is non-empty.
    If not, update the vendor list (this can take a few seconds).
    """
    if not os.path.exists(OUI_CACHE_PATH) or os.stat(OUI_CACHE_PATH).st_size == 0:
        logger.debug("Cache file not found or empty. Updating vendor list...")
        mac.update_vendors()
        logger.debug("Vendor list updated and stored at: %s", OUI_CACHE_PATH)
    else:
        logger.debug("Vendor cache exists at: %s", OUI_CACHE_PATH)


def find_mac(mac_address):
    """
    Look up the vendor for a given MAC address using the persistent MacLookup instance.
    """
    logger.debug("Looking up vendor for MAC: %s", mac_address)
    try:
        vendor = mac.lookup(mac_address)
        logger.debug("Lookup result for %s: %s", mac_address, vendor)
        return vendor if vendor else "-"
    except Exception as e:
        logger.error("Error during MAC lookup for %s: %s", mac_address, e)
        return "-"
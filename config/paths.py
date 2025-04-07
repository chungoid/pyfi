import os

# Determine the base directory for your config files (adjust as needed)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Set a custom cache path for the MAC vendor list within the config directory
OUI_CACHE_PATH = os.path.join(BASE_DIR, "mac_vendors.txt")

# Define the directory where WPA-sec results will be stored.
WPASEC_RESULTS_DIR = os.path.join(BASE_DIR, "wpa_sec_results")
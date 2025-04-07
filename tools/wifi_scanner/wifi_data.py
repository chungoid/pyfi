# wifi_data.py

from collections import defaultdict
import time
from queue import Queue

# Dictionary to store access points
networks = defaultdict(lambda: {
    'SSID': '',
    'Beacons': 0,
    'Data': 0,
    'Data Rate': 0,
    'Last Data Count': 0,
    'Last Update Time': time.time(),
    'Vendor': '-',
    'Hidden': False,
    'Randomized': False,
    'Signal': 'N/A'
})

# Dictionaries for client devices and associations
devices_with_ap = defaultdict(dict)
devices_without_ap = defaultdict(lambda: {
    'Signal': 'N/A',
    'Probe SSID': set(),
    'Vendor': '-',
    'Randomized': False
})
other_devices = defaultdict(dict)
associations = defaultdict(set)

# Queues for packets and MAC lookup tasks
packet_queue = Queue()
mac_lookup_queue = Queue()

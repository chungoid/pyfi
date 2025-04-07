# tools/wifi_scanner.py
import asyncio
import os
import time
import threading
import logging
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon
from mac_vendor_lookup import AsyncMacLookup
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Header, Footer, Input
from textual.containers import VerticalScroll
from rich.table import Table


# local
from tools.tool import Tool, ToolScreen
from tools.wifi_scanner.wifi_data import (
    networks, devices_with_ap, devices_without_ap, other_devices, associations, packet_queue, mac_lookup_queue
)
class WifiScanner(Tool):
    def __init__(self, name: str = "wifi_scanner"):
        super().__init__(name)
        self.selected_wlan_interface = {
            'name': "",
            'protocol': "",
            'mac': "",
            'gateway': "",
            'ip': ""
        }
        self.stop_event = threading.Event()
        self.last_print_time = time.time()
        self.logger = logging.getLogger("Tool.wifiscanner")
        self.logger.debug("WifiScanner initialized with no selected interface.")
        # Default to 2.4 GHz channels: 1-14.
        self.scanning_channels = list(range(1, 15))
        # Initialize async MAC lookup (see previous refactors).
        try:
            self.mac_lookup = AsyncMacLookup()
        except Exception as e:
            self.logger.error("Error initializing MAC lookup: %s", e)
            self.mac_lookup = None
        # Unique wpa-sec api key for downloading founds
        self.wpa_sec_key = ""  # New property to store the WPA-sec API key.

    def get_screen(self):
        self.logger.debug("Returning WifiScannerScreen for tool.")
        return WifiScannerScreen(self)

    def compose_status(self) -> str:
        # Optionally, you could keep this method for use with the "show info" command
        if self.selected_wlan_interface['name']:
            return (
                f"[bold]WiFi Scanner Info[/bold]\n"
                f"Interface: {self.selected_wlan_interface['name']}\n"
                f"Protocol: {self.selected_wlan_interface['protocol']}\n"
                f"MAC: {self.selected_wlan_interface['mac']}\n"
                f"Gateway: {self.selected_wlan_interface['gateway']}\n"
                f"IP: {self.selected_wlan_interface['ip']}\n"
                f"Active: {self.active}"
            )
        else:
            return ("[bold]WiFi Scanner[/bold]\n[italic]Interface not selected.[/italic]\n"
                    "Tip: Use 'list interfaces' then 'set interface <number>' to choose one.")

    def handle_custom_command(self, command: str) -> str:
        lower_cmd = command.lower().strip()
        self.logger.debug("Handling custom command: '%s'", command)

        if lower_cmd == "help":
            return self.get_help()

        elif lower_cmd == "list interfaces":
            if self.available_wlan_interfaces:
                lines = ["Available interfaces:"]
                for idx, iface in enumerate(self.available_wlan_interfaces, start=1):
                    lines.append(f"{idx}. {iface}")
                return "\n".join(lines) + "\nTip: Use 'set interface <number>' to choose an interface."
            else:
                return "No WLAN interfaces available."

        elif lower_cmd.startswith("set interface "):
            selection = command[len("set interface "):].strip()
            if selection.isdigit():
                idx = int(selection) - 1
                if 0 <= idx < len(self.available_wlan_interfaces):
                    iface = self.available_wlan_interfaces[idx]
                    self.populate_selected_wlan_interface(iface)
                    return f"Interface selected: {iface}"
                else:
                    return f"Invalid interface number: {selection}"
            else:
                self.populate_selected_wlan_interface(selection)
                return f"Interface selected: {selection}"

        elif lower_cmd.startswith("set freq"):
            freq = command[len("set freq "):].strip()
            if freq == "2":
                self.scanning_channels = list(range(1, 15))
            elif freq == "5":
                # Define a typical set of 5 GHz channels.
                self.scanning_channels = [36, 40, 44, 48, 52, 56, 60, 64,
                                          100, 104, 108, 112, 116, 120, 124, 128,
                                          132, 136, 140, 144, 149, 153, 157, 161, 165]
            elif freq in {"2,5", "5,2"}:
                self.scanning_channels = list(range(1, 15)) + [36, 40, 44, 48, 52, 56, 60, 64,
                                                               100, 104, 108, 112, 116, 120, 124, 128,
                                                               132, 136, 140, 144, 149, 153, 157, 161, 165]
            else:
                return "Invalid frequency option. Use 'set freq 2', 'set freq 5' or 'set freq 2,5'."
            return f"Scanning frequency set to: {freq}"

        elif lower_cmd == "show info":
            return self.compose_status()

        elif lower_cmd == "list networks":
            lines = ["Available Networks:"]
            net_list = list(networks.items())
            for idx, (bssid, info) in enumerate(net_list, start=1):
                ssid = info.get("SSID", "<hidden>")
                lines.append(f"{idx}. {ssid} ({bssid}) - Signal: {info.get('Signal', 'N/A')}")
            return "\n".join(lines)

        elif lower_cmd.startswith("connect "):
            network_id = command[len("connect "):].strip()
            return f"Attempting to connect to network {network_id}..."

        elif lower_cmd.startswith("set key"):
            # Command syntax: set key <your_key>
            key = command[len("set key"):].strip()
            if not key:
                return "Please provide a WPA-sec API key. Usage: set key <your_key>"
            self.wpa_sec_key = key
            return "WPA-sec API key set."

        elif lower_cmd == "download wpasec":
            # Ensure that a WPA-sec API key has been set.
            if not self.wpa_sec_key:
                return "WPA-sec API key not set. Use 'set key <your_key>' first."
            # Call the download function
            from config.helpers import download_from_wpasec
            from config.paths import WPASEC_RESULTS_DIR
            path = download_from_wpasec(self, self.wpa_sec_key, WPASEC_RESULTS_DIR)
            if path:
                return f"Downloaded WPA-sec results to {path}"
            else:
                return "Failed to download WPA-sec results."

        elif lower_cmd.startswith("connect "):
            try:
                network_number = int(command[len("connect "):].strip())
            except ValueError:
                return "Please provide a valid network number."
            return self.connect_network(network_number)

        else:
            return f"Unknown command for WiFi Scanner: {command}"

    def get_custom_help(self) -> str:
        return (
            "\n[bold]Interface Commands:[/]\n"
            "  list interfaces       - List available WLAN interfaces with numbers\n"
            "  set interface <number> - Select a WLAN interface by its number (or name)\n\n"
            "[bold]Network Commands:[/]\n"
            "  list networks         - List available networks with numbers\n"
            "  set network <number>  - Select a network to interact with\n"
            "  connect <number>      - Attempt to connect to a network\n\n"
            "[bold]Frequency Commands:[/]\n"
            "  set freq 2            - Scan only 2.4 GHz channels\n"
            "  set freq 5            - Scan only 5 GHz channels\n"
            "  set freq 2,5          - Scan both 2.4 GHz and 5 GHz channels\n\n"
            "[bold]WPA-sec Commands:[/]\n"
            "  set key <your_key>    - Set the WPA-sec API key for downloading results\n"
            "  download wpasec       - Download WPA-sec results using the set API key\n\n"
        )

    # --- Scanning Logic Methods ---
    def change_channel(self, interface: str, sleep_duration: float = 2.0) -> None:
        self.logger.debug("Starting channel changer on interface: %s", interface)
        while not self.stop_event.is_set():
            # Iterate over the configured scanning channels.
            for ch in self.scanning_channels:
                os.system(f"iw dev {interface} set channel {ch}")
                self.logger.debug("Channel set to: %s", ch)
                if self.stop_event.is_set():
                    break
                time.sleep(sleep_duration)

    def process_packets(self) -> None:
        self.logger.debug("Starting packet processing loop.")
        while not self.stop_event.is_set():
            packet = packet_queue.get()
            try:
                if packet.haslayer(Dot11):
                    if packet.type == 0 and packet.subtype == 8:
                        self.logger.debug("Processing beacon frame.")
                        self.process_beacon_frame(packet)
                    elif packet.type == 0 and packet.subtype == 4:
                        self.logger.debug("Processing probe request.")
                        self.process_probe_request(packet)
                    elif packet.type == 2:
                        self.logger.debug("Processing data frame.")
                        self.process_data_frame(packet)
                current_time = time.time()
                if current_time - self.last_print_time >= 1:
                    self.update_data_rates()
                    self.last_print_time = current_time
                    self.logger.debug("Data rates updated.")
            except Exception as e:
                self.logger.error("Error processing packet: %s", e)
            finally:
                packet_queue.task_done()

    def process_beacon_frame(self, packet) -> None:
        ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else ''
        bssid = packet.addr2
        dbm_signal = getattr(packet, 'dBm_AntSignal', 'N/A')
        encryption = self._get_encryption_type(packet)
        networks[bssid]['Beacons'] += 1

        if packet.haslayer(Dot11Beacon):
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get("channel", "Unknown")
        else:
            channel = "Unknown"
        frequency = self.calculate_frequency(channel)
        networks[bssid]['Channel'] = channel
        networks[bssid]['Frequency'] = frequency
        is_randomized = self.check_randomized_mac(bssid)

        if ssid == '':
            ssid_element = packet.getlayer(Dot11Elt, ID=0)
            if ssid_element and hasattr(ssid_element, 'len'):
                ssid = f"<length: {ssid_element.len}>"
            else:
                ssid = "<length: 0>"
            networks[bssid]['Hidden'] = True

        networks[bssid]['SSID'] = ssid
        networks[bssid]['Signal'] = dbm_signal
        networks[bssid]['Encryption'] = encryption
        networks[bssid]['Randomized'] = is_randomized

        if networks[bssid]['Vendor'] in ['-', 'Unknown']:
            mac_lookup_queue.put(bssid)

        self.remove_bssid_from_other_tables(bssid)
        self.logger.debug("Beacon frame processed for BSSID: %s", bssid)

    def process_data_frame(self, packet) -> None:
        bssid = packet.addr1
        client_mac = packet.addr2
        dbm_signal = getattr(packet, 'dBm_AntSignal', 'N/A')
        is_randomized = self.check_randomized_mac(client_mac)
        if bssid in networks:
            associations[bssid].add(client_mac)
            networks[bssid]['Data'] += 1
            if bssid and bssid != 'N/A' and client_mac not in networks and client_mac not in devices_with_ap:
                devices_with_ap[client_mac] = {
                    'Signal': dbm_signal,
                    'Associated AP': bssid,
                    'Vendor': '-',
                    'Randomized': is_randomized
                }
                mac_lookup_queue.put(client_mac)
            self.remove_mac_from_other_tables(client_mac)
        else:
            if client_mac not in networks and client_mac not in devices_with_ap:
                if client_mac not in other_devices:
                    other_devices[client_mac] = {
                        'Signal': dbm_signal,
                        'Vendor': '-',
                        'Randomized': is_randomized
                    }
                    mac_lookup_queue.put(client_mac)
        self.logger.debug("Data frame processed for client MAC: %s", client_mac)

    def process_probe_request(self, packet) -> None:
        mac = packet.addr2
        dbm_signal = getattr(packet, 'dBm_AntSignal', 'N/A')
        probe_ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else 'N/A'
        is_randomized = self.check_randomized_mac(mac)
        if mac not in networks and mac not in devices_with_ap:
            if mac not in devices_without_ap and mac not in other_devices:
                if probe_ssid == 'N/A':
                    other_devices[mac] = {
                        'Signal': dbm_signal,
                        'Vendor': '-',
                        'Randomized': is_randomized
                    }
                else:
                    devices_without_ap[mac] = {
                        'Signal': dbm_signal,
                        'Probe SSID': {probe_ssid},
                        'Vendor': '-',
                        'Randomized': is_randomized
                    }
                mac_lookup_queue.put(mac)
            else:
                if mac in devices_without_ap:
                    devices_without_ap[mac]['Signal'] = dbm_signal
                    if probe_ssid != 'N/A':
                        devices_without_ap[mac]['Probe SSID'].add(probe_ssid)
                elif mac in other_devices and probe_ssid == 'N/A':
                    other_devices[mac].update({'Signal': dbm_signal})
        self.logger.debug("Probe request processed for MAC: %s", mac)

    def get_mac_vendor(self, mac_address):
        """Use a new event loop in this worker thread to run the async lookup."""
        if not self.mac_lookup:
            self.logger.error("MAC lookup instance is not initialized.")
            return "-"
        try:
            normalized_mac = mac_address.replace(":", "").upper()
            self.logger.debug("Normalized MAC for lookup: %s", normalized_mac)
            # Create a new event loop in this thread.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # Call the async lookup coroutine.
            vendor = loop.run_until_complete(self.mac_lookup.lookup(mac_address))
            loop.close()
            self.logger.debug("Lookup result for %s (normalized: %s): %s", mac_address, normalized_mac, vendor)
            return vendor if vendor else '-'
        except Exception as e:
            self.logger.error("Error during MAC lookup for %s: %s", mac_address, e)
            return "-"

    def mac_lookup_worker(self):
        """Thread worker to process MAC lookup requests concurrently with additional debugging."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            while True:
                mac = mac_lookup_queue.get()
                self.logger.debug("MAC lookup queue received MAC: %s", mac)
                # Skip if vendor info already updated in any table.
                if mac in networks and networks[mac]['Vendor'] not in ['-', 'Unknown']:
                    self.logger.debug("MAC %s already has vendor info in networks.", mac)
                    mac_lookup_queue.task_done()
                    continue
                elif mac in devices_with_ap and devices_with_ap[mac]['Vendor'] not in ['-', 'Unknown']:
                    self.logger.debug("MAC %s already has vendor info in devices_with_ap.", mac)
                    mac_lookup_queue.task_done()
                    continue
                elif mac in devices_without_ap and devices_without_ap[mac]['Vendor'] not in ['-', 'Unknown']:
                    self.logger.debug("MAC %s already has vendor info in devices_without_ap.", mac)
                    mac_lookup_queue.task_done()
                    continue
                elif mac in other_devices and other_devices[mac]['Vendor'] not in ['-', 'Unknown']:
                    self.logger.debug("MAC %s already has vendor info in other_devices.", mac)
                    mac_lookup_queue.task_done()
                    continue

                self.logger.debug("Submitting MAC lookup task for %s", mac)
                future = executor.submit(self.get_mac_vendor, mac)
                futures[future] = mac

                for future in as_completed(futures):
                    mac_lookup = futures[future]
                    try:
                        vendor = future.result()
                        self.logger.debug("MAC lookup completed for %s: %s", mac_lookup, vendor)
                        self.update_vendor_in_tables(mac_lookup, vendor)
                    except Exception as e:
                        self.logger.error("Error processing MAC %s: %s", mac_lookup, e)
                    finally:
                        mac_lookup_queue.task_done()
                    del futures[future]

    def remove_bssid_from_other_tables(self, bssid) -> None:
        for table in [devices_with_ap, devices_without_ap, other_devices]:
            if bssid in table:
                del table[bssid]
                self.logger.debug("Removed BSSID %s from other tables.", bssid)

    def remove_mac_from_other_tables(self, client_mac) -> None:
        for table in [devices_without_ap, other_devices]:
            if client_mac in table:
                del table[client_mac]
                self.logger.debug("Removed MAC %s from other tables.", client_mac)

    def update_data_rates(self) -> None:
        current_time = time.time()
        for bssid, info in networks.items():
            time_diff = current_time - info['Last Update Time']
            if time_diff > 0:
                data_diff = info['Data'] - info['Last Data Count']
                info['Data Rate'] = data_diff / time_diff
                info['Last Data Count'] = info['Data']
                info['Last Update Time'] = current_time

    def calculate_frequency(self, channel) -> str:
        try:
            channel = int(channel)
        except ValueError:
            return "Unknown"
        if 1 <= channel <= 14:
            return '2.4 GHz'
        elif 36 <= channel <= 165:
            return '5 GHz'
        return "Unknown"

    def check_randomized_mac(self, mac) -> bool:
        try:
            return mac[1].upper() in ['A', 'E', '2', '6']
        except Exception:
            return False

    def _get_encryption_type(self, packet) -> str:
        encryption = "Open"
        is_wpa, is_wpa2, is_wpa3 = False, False, False
        if packet.haslayer(Dot11Elt):
            p = packet[Dot11Elt]
            while isinstance(p, Dot11Elt):
                if p.ID == 48:
                    is_wpa2 = True
                elif p.ID == 221:
                    if p.info.startswith(b'\x00\x50\xf2\x01'):
                        is_wpa = True
                    elif p.info.startswith(b'\x00\x0f\xac\x04'):
                        is_wpa3 = True
                p = p.payload
            if is_wpa3:
                encryption = "WPA3"
            elif is_wpa2:
                encryption = "WPA2"
            elif is_wpa:
                encryption = "WPA"
            elif 'privacy' in packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+'):
                encryption = "WEP"
        return encryption

    def start_sniffing(self, interface: str) -> None:
        self.logger.debug("Starting sniffing on interface: %s", interface)
        try:
            sniff(iface=interface, prn=self.packet_handler, stop_filter=lambda pkt: self.stop_event.is_set(), store=0)
        except Exception as e:
            self.logger.error("Sniffing error: %s", e)

    def packet_handler(self, packet) -> None:
        try:
            packet_queue.put(packet)
        except Exception as e:
            self.logger.error("Error putting packet in queue: %s", e)

    # --- Overriding Base Methods ---
    def start(self) -> None:
        if not self.selected_wlan_interface['name']:
            self.logger.error("No selected WLAN interface set. Please set an interface first.")
            return
        self.logger.info("Starting WiFi scanning on interface: %s", self.selected_wlan_interface['name'])
        self.active = True
        self.stop_event.clear()
        threading.Thread(target=self.change_channel, args=(self.selected_wlan_interface['name'], 2),
                         daemon=True).start()
        threading.Thread(target=self.process_packets, daemon=True).start()
        threading.Thread(target=self.start_sniffing, args=(self.selected_wlan_interface['name'],), daemon=True).start()
        # Start the MAC lookup worker thread to process the vendor lookups.
        threading.Thread(target=self.mac_lookup_worker, daemon=True).start()
        self.logger.info("WiFi scanning threads started.")

    def stop(self) -> None:
        self.logger.info("Stopping WiFi scanning.")
        self.stop_event.set()
        self.active = False

    def compose(self) -> ComposeResult:
        from textual.widgets import Static
        if self.selected_wlan_interface['name']:
            status = (
                f"[bold]WiFi Scanner[/bold]\n"
                f"Interface: {self.selected_wlan_interface['name']}\n"
                f"Protocol: {self.selected_wlan_interface['protocol']}\n"
                f"MAC: {self.selected_wlan_interface['mac']}\n"
                f"Gateway: {self.selected_wlan_interface['gateway']}\n"
                f"IP: {self.selected_wlan_interface['ip']}\n"
                f"Active: {self.active}"
            )
        else:
            status = ("[bold]WiFi Scanner[/bold]\n[italic]Interface not selected.[/italic]\n"
                      "Tip: Use 'list interfaces' then 'select <number>' to choose one.")
        self.logger.debug("Composing UI with status:\n%s", status)
        yield Static(status)

    def get_network_table(self):
        table = Table(title="WiFi Networks")
        table.add_column("No.", style="white", width=4)
        table.add_column("BSSID", style="cyan", no_wrap=True)
        table.add_column("SSID", style="green")
        table.add_column("Signal", style="white")
        table.add_column("Channel", style="magenta")
        table.add_column("Freq", style="yellow")
        table.add_column("Enc", style="red")
        table.add_column("Beacons", style="white")
        table.add_column("Vendor", style="blue")
        table.add_column("Password", style="white")  # NEW password column
        net_list = list(networks.items())
        for idx, (bssid, info) in enumerate(net_list, start=1):
            row = [
                str(idx),
                bssid,
                info.get('SSID', ''),
                str(info.get('Signal', 'N/A')),
                str(info.get('Channel', 'Unknown')),
                str(info.get('Frequency', 'Unknown')),
                info.get('Encryption', 'Open'),
                str(info.get('Beacons', 0)),
                info.get('Vendor', '-'),
                info.get('Password', '-')  # Display password if exists, otherwise '-'
            ]
            table.add_row(*row)
        return table

    def update_vendor_in_tables(self, mac, vendor):
        """Update vendor information in all relevant tables."""
        for table in [networks, devices_with_ap, devices_without_ap, other_devices]:
            if mac in table:
                table[mac]['Vendor'] = vendor

    def get_associated_table(self):
        table = Table(title="Associated Clients")
        table.add_column("MAC", style="cyan", no_wrap=True)
        table.add_column("Signal", style="white")
        table.add_column("Associated AP", style="green")
        table.add_column("SSID", style="green")
        table.add_column("Vendor", style="blue")
        for mac, info in devices_with_ap.items():
            bssid = info.get('Associated AP', 'N/A')
            # Look up the SSID in networks dictionary if available
            ssid = networks[bssid].get('SSID', 'N/A') if bssid in networks else "N/A"
            row = [
                mac,
                str(info.get('Signal', 'N/A')),
                bssid,
                ssid,
                info.get('Vendor', '-')
            ]
            table.add_row(*row)
        return table

    def get_probe_table(self):
        table = Table(title="Probing Clients")
        table.add_column("MAC", style="cyan", no_wrap=True)
        table.add_column("Signal", style="white")
        table.add_column("Probe SSIDs", style="yellow")
        table.add_column("Vendor", style="blue")
        for mac, info in devices_without_ap.items():
            probe_ssids = ", ".join(info.get('Probe SSID', [])) if isinstance(info.get('Probe SSID', []), set) else str(
                info.get('Probe SSID', ''))
            row = [
                mac,
                str(info.get('Signal', 'N/A')),
                probe_ssids,
                info.get('Vendor', '-')
            ]
            table.add_row(*row)
        return table

    def get_other_table(self):
        table = Table(title="Other Devices")
        table.add_column("MAC", style="cyan", no_wrap=True)
        table.add_column("Signal", style="white")
        table.add_column("Vendor", style="blue")
        for mac, info in other_devices.items():
            row = [
                mac,
                str(info.get('Signal', 'N/A')),
                info.get('Vendor', '-')
            ]
            table.add_row(*row)
        return table

    def update_network_passwords(self, founds_path: str, networks: dict) -> None:
        try:
            with open(founds_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue  # Skip empty lines
                    parts = line.split(":")
                    if len(parts) < 4:
                        continue  # Skip invalid lines
                    found_bssid = parts[0].strip()
                    found_ssid = parts[2].strip()
                    password = parts[3].strip()
                    if found_bssid in networks:
                        networks[found_bssid]["Password"] = password
                    else:
                        for bssid, info in networks.items():
                            if info.get("SSID", "").strip() == found_ssid:
                                info["Password"] = password
        except Exception as e:
            self.logger.exception("Error updating network passwords: %s", e)

    def connect_network(self, network_number: int) -> str:
        """
        Connects to the selected network using nmcli by looking up the SSID and Password
        from the networks table and then using run_suppressed_cmd to execute the command.

        :param network_number: The network index (as displayed in the table).
        :return: A message indicating success or failure.
        """
        net_list = list(networks.items())
        if network_number < 1 or network_number > len(net_list):
            return f"Network number {network_number} out of range."

        bssid, info = net_list[network_number - 1]
        ssid = info.get("SSID", "").strip()
        password = info.get("Password", "").strip()

        if not ssid:
            return "No SSID available for the selected network."

        # Build the nmcli command string
        command = f"nmcli dev wifi connect '{ssid}'"
        if password and password != "-":
            command += f" password '{password}'"

        # Use run_suppressed_cmd from utils.helpers to execute the command quietly.
        from utils.helpers import run_suppressed_cmd
        output = run_suppressed_cmd(command)

        # You can further parse the output or simply return it.
        if output:
            return f"Connected to {ssid}. Output: {output}"
        else:
            return f"Attempted connection to {ssid}, but no output was returned."


class WifiScannerScreen(ToolScreen):
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="scroll"):
            yield Static("", id="status", markup=True)
            yield Static("", id="scan_table", markup=True)
            yield Static("", id="associated_table", markup=True)
            yield Static("", id="probe_table", markup=True)
            yield Static("", id="other_table", markup=True)
            yield Static("", id="command_output", markup=True)
        yield Input(placeholder="Enter command...", id="tool_command")
        yield Footer()

    def on_mount(self) -> None:
        # Update scan tables every second.
        self.set_interval(1, self.update_ui)

    def update_ui(self) -> None:
        self.query_one("#scan_table", Static).update(self.tool.get_network_table())
        self.query_one("#associated_table", Static).update(self.tool.get_associated_table())
        self.query_one("#probe_table", Static).update(self.tool.get_probe_table())
        self.query_one("#other_table", Static).update(self.tool.get_other_table())

        # Auto-update network passwords using the scanner's method.
        from config.paths import WPASEC_RESULTS_DIR
        import os
        founds_path = os.path.join(WPASEC_RESULTS_DIR, "founds.txt")
        if os.path.exists(founds_path):
            self.tool.update_network_passwords(founds_path, networks)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        command = event.value.strip()
        self.tool.logger.debug("Received command on WifiScannerScreen: '%s'", command)
        if command.lower().startswith("set network"):
            try:
                network_num = int(command[len("set network "):].strip())
            except ValueError:
                self.query_one("#command_output", Static).update("> Please specify a valid network number.")
                self.query_one("#tool_command", Input).value = ""
                return
            net_list = list(networks.items())
            if 1 <= network_num <= len(net_list):
                selected_network = net_list[network_num - 1]
                await self.app.push_screen(NetworkInteractionScreen(self.tool, selected_network))
                response = f"Network {selected_network[1].get('SSID', '<hidden>')} selected."
            else:
                response = "Network number out of range."
            self.query_one("#command_output", Static).update("> " + response)
            self.query_one("#tool_command", Input).value = ""
        else:
            response = self.tool.handle_command(command)
            self.query_one("#command_output", Static).update("> " + response)
            self.query_one("#tool_command", Input).value = ""


# --- The network interaction subscreen ---
class NetworkInteractionScreen(Screen):
    def __init__(self, scanner_tool, selected_network):
        super().__init__()
        self.scanner_tool = scanner_tool
        self.selected_network = selected_network  # (bssid, info)

    def compose(self) -> ComposeResult:
        from textual.widgets import Static, Header, Footer, Input
        from textual.containers import Vertical
        yield Header()
        with Vertical():
            bssid, info = self.selected_network
            details = (
                f"[bold]Selected Network:[/bold]\n"
                f"SSID: {info.get('SSID', '<hidden>')}\n"
                f"BSSID: {bssid}\n"
                f"Signal: {info.get('Signal', 'N/A')}\n"
                f"Channel: {info.get('Channel', 'Unknown')}\n"
                f"Encryption: {info.get('Encryption', 'Open')}\n"
            )
            yield Static(details, id="network_details", markup=True)
            yield Static("", id="network_command_output", markup=True)
            self.command_input = Input(placeholder="Enter network command...", id="network_command")
            yield self.command_input
        yield Footer()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        command = event.value.strip()
        response = self.handle_network_command(command)
        self.query_one("#network_command_output", Static).update("> " + response)
        self.query_one("#network_command", Input).value = ""

    def handle_network_command(self, command: str) -> str:
        lower_cmd = command.lower().strip()
        if lower_cmd == "help":
            return (
                "Network Commands:\n"
                "  help     - Show this help message\n"
                "  connect  - Connect to this network\n"
                "  details  - Show detailed information\n"
                "  back     - Return to scanning screen"
            )
        elif lower_cmd == "details":
            bssid, info = self.selected_network
            return (
                f"SSID: {info.get('SSID', '<hidden>')}\n"
                f"BSSID: {bssid}\n"
                f"Signal: {info.get('Signal', 'N/A')}\n"
                f"Channel: {info.get('Channel', 'Unknown')}\n"
                f"Encryption: {info.get('Encryption', 'Open')}\n"
                f"Data Rate: {info.get('Data Rate', 0):.2f}\n"
                f"Beacons: {info.get('Beacons', 0)}\n"
                f"Data: {info.get('Data', 0)}"
            )
        elif lower_cmd == "connect":
            return f"Attempting to connect to {self.selected_network[1].get('SSID', '<hidden>')}..."
        elif lower_cmd == "back":
            self.app.pop_screen()
            return "Returning to scanning screen."
        else:
            return f"Unknown network command: {command}"
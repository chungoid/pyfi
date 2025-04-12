#!/usr/bin/env python3
# Simple Network Mapper Tool
# A drastically simplified version of network_mapper.py

import os
import re
import time
import datetime
import subprocess
import threading
import xml.etree.ElementTree as ET
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Tuple

from tools.tool import Tool
from tools.tool_helpers import (
    get_gateway_for_interface,
    get_ip_for_interface,
    get_netmask_for_interface,
    get_protocol_for_interface
)

class NetworkMapper(Tool):
    def __init__(self, *args, **kwargs):
        if 'name' not in kwargs:
            kwargs['name'] = 'Simple Network Mapper'
        super().__init__(*args, **kwargs)
        
        # Basic state
        self.client_data = {}
        self.selected_eth_interface = {}
        self.selected_wlan_interface = {}
        self.selected_targets = []
        self.selected_options = []
        self.running_processes = {}
        
        # Ensure results directory exists
        self.base_dir = Path(__file__).parent
        self.results_dir = self.base_dir / "results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.logger.info("SimpleNetworkMapper initialized")
    
    def get_screen(self):
        from tools.network_mapper.screens import NetworkMapperScreen
        return NetworkMapperScreen(self)
    
    # ==== Core Methods ====
    def populate_selected_interface(self, iface: str) -> None:
        """Set the selected interface info"""
        proto = get_protocol_for_interface(iface)
        gateway = get_gateway_for_interface(iface)
        ip = get_ip_for_interface(iface)
        netmask = get_netmask_for_interface(iface)

        if not ip or not netmask:
            self.logger.error(f"Failed to get IP/netmask for {iface}")
            return

        info = {'name': iface, 'gateway': gateway, 'ip': ip, 'netmask': netmask}
        if proto == "wlan":
            self.selected_wlan_interface = info
            self.logger.info(f"Wireless interface set: {info}")
        elif proto == "eth":
            self.selected_eth_interface = info
            self.logger.info(f"Ethernet interface set: {info}")
    
    def is_valid_target(self, target: str) -> bool:
        """Check if a target is valid (IP address, hostname, or CIDR notation)"""
        try:
            # Check if it's a valid IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Not a valid IP address, check if it's CIDR notation
            try:
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                # Not CIDR, check if it's a hostname (basic check)
                if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', target):
                    return True
                return False
    
    def set_targets(self, targets_arg: str) -> str:
        """Set the targets for scanning"""
        targets = []
        valid_targets = []
        
        # Handle CIDR notation
        try:
            network = ipaddress.ip_network(targets_arg.strip(), strict=False)
            if network.num_addresses > 256:
                return f"Network {targets_arg} has too many addresses. Maximum is 256."
            
            for ip in network.hosts():
                targets.append(str(ip))
        except ValueError:
            # Not CIDR notation, treat as comma-separated list
            targets = [t.strip() for t in targets_arg.split(',') if t.strip()]
        
        # Validate targets
        for target in targets:
            if self.is_valid_target(target):
                valid_targets.append(target)
        
        if not valid_targets:
            return "No valid targets provided"
            
        self.selected_targets = valid_targets
        return f"Set {len(valid_targets)} targets"
    
    def set_options(self, options_str: str) -> str:
        """Set scan options"""
        options = [opt.strip() for opt in options_str.split(',') if opt.strip()]
        valid_options = []
        
        # Filter valid options (1-15)
        for opt in options:
            if opt in [str(i) for i in range(1, 16)]:
                valid_options.append(opt)
                
        if not valid_options:
            return "No valid options provided"
            
        self.selected_options = valid_options
        return f"Set {len(valid_options)} scan options"
    
    def run_scan(self, target: str, option: str) -> None:
        """Run a single nmap scan in a separate thread"""
        self.logger.info(f"Starting scan for option {option} on target {target}")
        
        # Create unique ID for tracking
        scan_id = f"scan_{int(time.time())}_{option}_{target}"
        
        # Generate output filenames with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_target = target.replace('/', '_').replace(':', '_')
        output_xml = str(self.results_dir / f"scan_opt{option}_{sanitized_target}_{timestamp}.xml")
        
        # Track scan in process dictionary
        self.running_processes[scan_id] = {
            'start_time': time.time(),
            'target': target,
            'option': option,
            'output_file': output_xml,
            'completed': False
        }
        
        # Build nmap command based on option
        cmd = ["nmap", target, "-oX", output_xml]
        
        # Add scan-specific arguments
        option_args = {
            "1": ["--top-ports", "100"],                # Top Ports
            "2": ["-O"],                                # OS Detection
            "3": ["-p-"],                               # Full Port Scan
            "4": ["-sL"],                               # List Scan
            "5": ["-sV"],                               # Version Detection
            "6": ["-Pn", "-sZ"],                        # Stealth Scan
            "7": ["-sF"],                               # FIN Scan
            "8": ["-sS"],                               # SYN Scan
            "9": ["-sT"],                               # TCP Connect Scan
            "10": ["-sU"],                              # UDP Scan
            "11": ["-sP"],                              # Ping Scan
            "12": ["-PR"],                              # ARP Discovery
            "13": ["-sn"],                              # No Port Scan
            "14": ["--script", "dns-brute.nse"],        # DNS Brute Script
            "15": ["-sC"]                               # Default Script Scan
        }
        
        if option in option_args:
            cmd.extend(option_args[option])
        
        # Add timing template for faster scans
        cmd.append("-T4")
        
        # Add sudo for privileged scans
        if option in ["2", "6", "7", "8"]:  # OS detection, Stealth, FIN, SYN scans need privileges
            cmd = ["sudo"] + cmd
        
        # Log full command
        cmd_str = " ".join(cmd)
        self.logger.info(f"Executing command: {cmd_str}")
        
        try:
            # Run the command
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Update process tracking
            self.running_processes[scan_id]['pid'] = process.pid
            self.running_processes[scan_id]['command'] = cmd_str
            self.logger.info(f"Process started with PID {process.pid}")
            
            # Wait for completion
            stdout, stderr = process.communicate()
            
            # Update process status
            self.running_processes[scan_id]['completed'] = True
            self.running_processes[scan_id]['end_time'] = time.time()
            self.running_processes[scan_id]['returncode'] = process.returncode
            
            # Handle completion
            if process.returncode == 0:
                self.logger.info(f"Scan completed successfully: {scan_id}")
                
                # Check if output file exists
                if os.path.exists(output_xml):
                    # Parse the results
                    try:
                        self.logger.info(f"Parsing results from {output_xml}")
                        tree = ET.parse(output_xml)
                        xml = tree.getroot()
                        
                        # Process results based on scan type
                        results = self.parse_xml_results(xml, option)
                        
                        # Update client_data with results
                        if results:
                            self.client_data.update(results)
                            self.logger.info(f"Updated client_data with {len(results)} entries")
                    except Exception as e:
                        self.logger.error(f"Error parsing XML output: {e}")
                else:
                    self.logger.warning(f"Output file not created: {output_xml}")
            else:
                self.logger.error(f"Scan failed with return code {process.returncode}: {stderr}")
                self.running_processes[scan_id]['error'] = stderr
                
        except Exception as e:
            self.logger.error(f"Error in scan thread: {e}")
            if scan_id in self.running_processes:
                self.running_processes[scan_id]['completed'] = True
                self.running_processes[scan_id]['end_time'] = time.time()
                self.running_processes[scan_id]['returncode'] = -1
                self.running_processes[scan_id]['error'] = str(e)
    
    def start_scans(self) -> str:
        """Start scans for all selected options and targets"""
        if not self.selected_options:
            return "No scan options selected. Use 'set options <n1,n2,...>' first."
        if not self.selected_targets:
            return "No targets selected. Use 'set targets <n1,n2,...>' first."
        
        # Print current state for debugging
        self.logger.info(f"Starting scans with targets: {self.selected_targets}")
        self.logger.info(f"Options: {self.selected_options}")
        
        # Define option argument mappings
        option_args = {
            "1": ["--top-ports", "100"],                # Top Ports
            "2": ["-O"],                                # OS Detection
            "3": ["-p-"],                               # Full Port Scan
            "4": ["-sL"],                               # List Scan
            "5": ["-sV"],                               # Version Detection
            "6": ["-Pn", "-sZ"],                        # Stealth Scan
            "7": ["-sF"],                               # FIN Scan
            "8": ["-sS"],                               # SYN Scan
            "9": ["-sT"],                               # TCP Connect Scan
            "10": ["-sU"],                              # UDP Scan
            "11": ["-sP"],                              # Ping Scan
            "12": ["-PR"],                              # ARP Discovery
            "13": ["-sn"],                              # No Port Scan
            "14": ["--script", "dns-brute.nse"],        # DNS Brute Script
            "15": ["-sC"]                               # Default Script Scan
        }
        
        # Options that need sudo
        sudo_options = {"2", "6", "7", "8"}
        
        # New: Run one scan per target combining all options
        started_scans = []
        for target in self.selected_targets:
            # Combine all selected options into a single set of arguments
            combined_args = []
            needs_sudo = False
            
            # Check if we need sudo based on any selected option
            for opt in self.selected_options:
                if opt in sudo_options:
                    needs_sudo = True
                    
                # Add the args for this option
                if opt in option_args:
                    combined_args.extend(option_args[opt])
            
            # Skip redundant arguments
            if "-sS" in combined_args and "-sT" in combined_args:
                combined_args.remove("-sT")  # SYN scan is preferred over TCP connect
                
            # Generate unique output filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            sanitized_target = target.replace('/', '_').replace(':', '_')
            output_xml = str(self.results_dir / f"scan_combined_{sanitized_target}_{timestamp}.xml")
            
            # Build the complete command
            cmd = ["nmap", target, "-oX", output_xml, "-T4"] + combined_args
            
            # Add sudo if needed
            if needs_sudo:
                cmd = ["sudo"] + cmd
                
            # Log the full command
            cmd_str = " ".join(cmd)
            self.logger.info(f"Combined scan command: {cmd_str}")
            
            # Create unique ID for tracking
            scan_id = f"scan_{int(time.time())}_{target}"
            
            # Track scan in process dictionary
            self.running_processes[scan_id] = {
                'start_time': time.time(),
                'target': target,
                'options': ", ".join(self.selected_options),
                'output_file': output_xml,
                'completed': False,
                'command': cmd_str
            }
            
            # Start the scan in a background thread
            thread = threading.Thread(
                target=self._run_combined_scan,
                args=(cmd, scan_id),
                daemon=True
            )
            thread.start()
            
            started_scans.append(f"Combined scan ({', '.join(self.selected_options)}) on {target}")
            self.logger.info(f"Started combined scan thread for target {target}")
        
        if started_scans:
            return f"Started {len(started_scans)} combined scans. Use 'show processes' to check status."
        else:
            return "No scans were started."
            
    def _run_combined_scan(self, cmd, scan_id):
        """Run a combined nmap scan with multiple options in one command"""
        try:
            # Start the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Update process tracking
            self.running_processes[scan_id]['pid'] = process.pid
            self.logger.info(f"Process started with PID {process.pid}: {self.running_processes[scan_id]['command']}")
            
            # Wait for completion
            stdout, stderr = process.communicate()
            
            # Update process status
            self.running_processes[scan_id]['completed'] = True
            self.running_processes[scan_id]['end_time'] = time.time()
            self.running_processes[scan_id]['returncode'] = process.returncode
            
            # Handle completion
            if process.returncode == 0:
                self.logger.info(f"Scan completed successfully: {scan_id}")
                
                # Parse the results
                output_file = self.running_processes[scan_id]['output_file']
                if os.path.exists(output_file):
                    # Parse the XML output
                    try:
                        tree = ET.parse(output_file)
                        xml = tree.getroot()
                        
                        # Process results
                        results = self.parse_xml_results(xml, "combined")
                        
                        # Update client_data
                        if results:
                            self.client_data.update(results)
                            self.logger.info(f"Updated client_data with {len(results)} entries from combined scan")
                    except Exception as e:
                        self.logger.error(f"Error parsing output: {e}")
                else:
                    self.logger.warning(f"Output file not created: {output_file}")
            else:
                self.logger.error(f"Scan failed with return code {process.returncode}: {stderr}")
                self.running_processes[scan_id]['error'] = stderr
                
        except Exception as e:
            self.logger.exception(f"Error in combined scan: {e}")
            if scan_id in self.running_processes:
                self.running_processes[scan_id]['completed'] = True
                self.running_processes[scan_id]['end_time'] = time.time()
                self.running_processes[scan_id]['returncode'] = -1
                self.running_processes[scan_id]['error'] = str(e)
    
    def get_processes_status(self) -> str:
        """Get the status of all running and completed processes"""
        if not self.running_processes:
            return "No scan processes have been started."
        
        lines = ["Nmap Processes:"]
        running_count = 0
        completed_count = 0
        failed_count = 0
        
        for proc_id, proc_info in self.running_processes.items():
            target = proc_info.get('target', 'Unknown')
            option = proc_info.get('option', 'Unknown')
            pid = proc_info.get('pid', 'Unknown')
            completed = proc_info.get('completed', False)
            
            if completed:
                completed_count += 1
                end_time = proc_info.get('end_time', time.time())
                start_time = proc_info.get('start_time', end_time)
                duration = end_time - start_time
                returncode = proc_info.get('returncode', 'Unknown')
                
                if returncode == 0:
                    status = "Success"
                else:
                    status = f"Failed ({returncode})"
                    failed_count += 1
                
                lines.append(f"  {proc_id} - {status} - Duration: {duration:.1f}s - Option {option} on {target}")
                
                # Show error if failed
                if returncode != 0 and 'error' in proc_info:
                    lines.append(f"    Error: {proc_info['error']}")
            else:
                running_count += 1
                start_time = proc_info.get('start_time', time.time())
                elapsed = time.time() - start_time
                
                lines.append(f"  {proc_id} - RUNNING - Elapsed: {elapsed:.1f}s - Option {option} on {target}")
                
                # Check if process is still running
                try:
                    if pid != 'Unknown':
                        os.kill(pid, 0)  # Just check if process exists
                except ProcessLookupError:
                    lines.append(f"    WARNING: Process appears to have terminated abnormally")
                except OSError:
                    lines.append(f"    WARNING: Unable to determine process status")
        
        # Add summary line
        lines.append(f"\nSummary: {running_count} running, {completed_count} completed ({failed_count} failed)")
        
        # Show output files
        try:
            xml_files = list(self.results_dir.glob("*.xml"))
            if xml_files:
                lines.append(f"\nFound {len(xml_files)} output files in {self.results_dir}")
                
                # Show recent files
                xml_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                recent_files = xml_files[:3]
                if recent_files:
                    lines.append("Recent files:")
                    for file in recent_files:
                        size = file.stat().st_size
                        mod_time = datetime.datetime.fromtimestamp(file.stat().st_mtime)
                        lines.append(f"  {file.name} ({size} bytes, {mod_time.strftime('%Y-%m-%d %H:%M:%S')})")
        except Exception as e:
            lines.append(f"Error checking results dir: {e}")
        
        return "\n".join(lines)
    
    def parse_xml_results(self, xml, option: str) -> Dict[str, Any]:
        """Parse XML results from nmap scan"""
        results = {}
        
        # For discovery-type scans (11, 12, 13), just extract hosts that are up
        if option in ["11", "12", "13"]:
            for host in xml.findall('.//host'):
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                if addr_elem is not None:
                    ip = addr_elem.get('addr')
                    state_elem = host.find('.//status')
                    if state_elem is not None and state_elem.get('state').lower() == "up":
                        results[ip] = {
                            'state': {
                                'state': 'up',
                                'reason': state_elem.get('reason', 'unknown')
                            }
                        }
                        
                        # Add MAC if available
                        mac_elem = host.find('.//address[@addrtype="mac"]')
                        if mac_elem is not None:
                            mac = mac_elem.get('addr')
                            vendor = mac_elem.get('vendor', '')
                            results[ip]['macaddress'] = {'addr': mac, 'vendor': vendor}
        # For combined or normal scans, extract detailed information
        else:
            for host in xml.findall('.//host'):
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                if addr_elem is not None:
                    ip = addr_elem.get('addr')
                    
                    # Initialize host data
                    host_data = {}
                    
                    # Add state
                    state_elem = host.find('.//status')
                    if state_elem is not None:
                        host_data['state'] = {
                            'state': state_elem.get('state'),
                            'reason': state_elem.get('reason', '')
                        }
                    
                    # Skip hosts that aren't up
                    if host_data.get('state', {}).get('state', '').lower() != 'up':
                        continue
                    
                    # Add MAC if available
                    mac_elem = host.find('.//address[@addrtype="mac"]')
                    if mac_elem is not None:
                        host_data['macaddress'] = {
                            'addr': mac_elem.get('addr'),
                            'vendor': mac_elem.get('vendor', '')
                        }
                    
                    # Add OS info if available
                    osmatch_elems = host.findall('.//osmatch')
                    if osmatch_elems:
                        host_data['osmatch'] = []
                        for osmatch in osmatch_elems:
                            host_data['osmatch'].append({
                                'name': osmatch.get('name', ''),
                                'accuracy': osmatch.get('accuracy', '')
                            })
                    
                    # Add ports info if available
                    port_elems = host.findall('.//port')
                    if port_elems:
                        host_data['ports'] = []
                        for port in port_elems:
                            port_data = {
                                'protocol': port.get('protocol', ''),
                                'portid': port.get('portid', '')
                            }
                            
                            # Add state info
                            state = port.find('.//state')
                            if state is not None:
                                port_data['state'] = state.get('state', '')
                            
                            # Add service info
                            service = port.find('.//service')
                            if service is not None:
                                port_data['service'] = {
                                    'name': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', '')
                                }
                            
                            # For combined scans, also include script output if available
                            if option == "combined":
                                script_elems = port.findall('.//script')
                                if script_elems:
                                    port_data['scripts'] = {}
                                    for script in script_elems:
                                        script_id = script.get('id', '')
                                        script_output = script.get('output', '')
                                        port_data['scripts'][script_id] = script_output
                            
                            host_data['ports'].append(port_data)
                    
                    # Add hostnames if available
                    hostname_elems = host.findall('.//hostname')
                    if hostname_elems:
                        host_data['hostname'] = []
                        for hostname in hostname_elems:
                            host_data['hostname'].append({
                                'name': hostname.get('name', ''),
                                'type': hostname.get('type', '')
                            })
                    
                    # For combined scans, also include host scripts
                    if option == "combined":
                        host_script_elems = host.findall('.//hostscript/script')
                        if host_script_elems:
                            host_data['hostscripts'] = {}
                            for script in host_script_elems:
                                script_id = script.get('id', '')
                                script_output = script.get('output', '')
                                host_data['hostscripts'][script_id] = script_output
                    
                    # Add to results
                    results[ip] = host_data
        
        return results
    
    def get_results_table(self) -> str:
        """Format scan results as a text table"""
        if not self.client_data:
            return "No scan results available."
        
        # Count hosts that are up
        hosts_up = 0
        for _, info in self.client_data.items():
            if isinstance(info, dict):
                state = info.get('state', {}).get('state', '').lower()
                if state == 'up':
                    hosts_up += 1
        
        lines = [f"Scan Results ({hosts_up} hosts up):", ""]
        lines.append("IP               Status   OS                  Ports                Services")
        lines.append("-" * 78)
        
        for ip, info in self.client_data.items():
            # Skip non-dict entries
            if not isinstance(info, dict):
                continue
            
            # Get state
            state_dict = info.get('state', {})
            if not isinstance(state_dict, dict):
                continue
            
            state = state_dict.get('state', '')
            if state.lower() != 'up':
                continue
            
            # Get OS info
            os_list = info.get('osmatch', [])
            if os_list and isinstance(os_list, list):
                os_info = os_list[0].get('name', '-')[:20]
            else:
                os_info = '-'
            
            # Get ports info
            port_entries = info.get('ports', [])
            if port_entries and isinstance(port_entries, list):
                port_ids = [p.get('portid', '') for p in port_entries]
                ports = ", ".join(port_ids[:5])
                if len(port_ids) > 5:
                    ports += ", ..."
                
                services = []
                for p in port_entries[:5]:
                    svc = p.get('service', {}).get('name', '')
                    if svc:
                        services.append(svc)
                
                services_str = ", ".join(services)
                if len(port_entries) > 5:
                    services_str += ", ..."
            else:
                ports = '-'
                services_str = '-'
            
            # Format the line
            ip_padded = ip.ljust(16)
            state_padded = state.ljust(8)
            os_padded = os_info.ljust(20)
            ports_padded = ports[:20].ljust(20)
            
            lines.append(f"{ip_padded} {state_padded} {os_padded} {ports_padded} {services_str}")
        
        return "\n".join(lines)
    
    # ==== Command Handler Methods ====
    def handle_set_command(self, args: list) -> str:
        """Handle set commands (interface, targets, options)"""
        if not args:
            return "Missing set command. Use: set interface|targets|options <value>"
        
        subcmd = args[0].lower()
        
        if subcmd == "interface":
            if len(args) < 2:
                return "Missing interface. Use: set interface <name|#>"
            
            import tools.tool_helpers as helpers
            wlan = helpers.get_wlan_interfaces() or []
            eth = helpers.get_eth_interfaces() or []
            combined = wlan + eth
            
            if args[1].isdigit():
                idx = int(args[1]) - 1
                if 0 <= idx < len(combined):
                    iface = combined[idx]
                else:
                    return f"Invalid interface number: {args[1]}"
            else:
                iface = args[1]
                if iface not in combined:
                    return f"Interface not found: {iface}"
            
            self.populate_selected_interface(iface)
            
            # Return interface info
            if iface in wlan:
                return f"Wireless interface set: {self.selected_wlan_interface}"
            else:
                return f"Ethernet interface set: {self.selected_eth_interface}"
        
        elif subcmd == "targets":
            if len(args) < 2:
                return "Missing targets. Use: set targets <n1,n2,...> or <CIDR>"
            
            return self.set_targets(args[1])
        
        elif subcmd == "options":
            if len(args) < 2:
                return "Missing options. Use: set options <n1,n2,...>"
            
            return self.set_options(args[1])
        
        else:
            return f"Unknown set command: {subcmd}"
    
    def handle_show_command(self, args: list) -> str:
        """Handle show commands (scans, results, processes)"""
        if not args:
            return "Missing show command. Use: show scans|results|processes"
        
        subcmd = args[0].lower()
        
        if subcmd == "results":
            return self.get_results_table()
        
        elif subcmd == "processes":
            return self.get_processes_status()
        
        elif subcmd == "options":
            # Show available scan options
            lines = ["Scan Options:"]
            
            option_groups = {
                "Discovery Options": {
                    "11": "Ping Scan (-sP)",
                    "12": "ARP Discovery (-PR)",
                    "13": "No Port Scan (-sn)"
                },
                "Port Scanning": {
                    "1": "Top Ports Scan (--top-ports)",
                    "3": "Full Port Scan (-p-)",
                    "4": "List Scan (-sL)",
                    "8": "SYN Scan (-sS)",
                    "9": "TCP Connect Scan (-sT)",
                    "10": "UDP Scan (-sU)"
                },
                "Service & OS Detection": {
                    "2": "OS Detection (-O)",
                    "5": "Version Detection (-sV)",
                    "15": "Default Script Scan (-sC)"
                },
                "Advanced Scans": {
                    "6": "Stealth Scan (-Pn -sZ)",
                    "7": "FIN Scan (-sF)",
                    "14": "DNS Brute Script (--script dns-brute)"
                }
            }
            
            for group, options in option_groups.items():
                lines.append(f"\n{group}:")
                for num, desc in options.items():
                    lines.append(f"  {num}. {desc}")
            
            return "\n".join(lines)
        
        else:
            return f"Unknown show command: {subcmd}"
    
    def handle_list_command(self, args: list) -> str:
        """Handle list commands (interfaces, targets)"""
        if not args:
            return "Missing list command. Use: list interfaces|targets"
        
        subcmd = args[0].lower()
        
        if subcmd == "interfaces":
            import tools.tool_helpers as helpers
            wlan = helpers.get_wlan_interfaces() or []
            eth = helpers.get_eth_interfaces() or []
            
            lines = ["Available interfaces:"]
            
            if wlan:
                lines.append("\nWireless interfaces:")
                for i, iface in enumerate(wlan, 1):
                    lines.append(f"  {i}. {iface}")
            
            if eth:
                lines.append("\nEthernet interfaces:")
                for i, iface in enumerate(eth, 1):
                    lines.append(f"  {i}. {iface}")
            
            return "\n".join(lines)
        
        elif subcmd == "targets":
            if not self.client_data:
                return "No discovered targets yet. Run a scan first."
            
            lines = ["Discovered targets:"]
            for i, ip in enumerate(self.client_data.keys(), 1):
                lines.append(f"  {i}. {ip}")
            
            return "\n".join(lines)
        
        else:
            return f"Unknown list command: {subcmd}"
    
    def handle_discover_command(self, args: list) -> str:
        """Handle discovery commands (arp, ping, netdiscover)"""
        if not args:
            return "Missing discovery method. Use: discover arp|ping|host"
        
        method = args[0].lower()
        
        # Get the interface network
        subnet = None
        if self.selected_eth_interface.get('ip'):
            ip = self.selected_eth_interface.get('ip')
            netmask = self.selected_eth_interface.get('netmask')
            if ip and netmask:
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    subnet = str(network)
                except Exception as e:
                    self.logger.error(f"Error calculating subnet: {e}")
        elif self.selected_wlan_interface.get('ip'):
            ip = self.selected_wlan_interface.get('ip')
            netmask = self.selected_wlan_interface.get('netmask')
            if ip and netmask:
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    subnet = str(network)
                except Exception as e:
                    self.logger.error(f"Error calculating subnet: {e}")
        
        if not subnet:
            return "No interface selected. Use 'set interface <name|#>' first."
        
        # Start discovery scan
        method_args = {
            "arp": "-PR",
            "ping": "-sP",
            "host": "-sn"
        }
        
        if method not in method_args:
            return f"Unknown discovery method: {method}. Use: arp|ping|host"
        
        self.logger.info(f"Starting {method} discovery scan on {subnet}")
        
        # Create unique output filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = str(self.results_dir / f"discover_{method}_{timestamp}.xml")
        
        # Build command
        cmd = ["nmap", subnet, method_args[method], "-oX", output_file, "-T4"]
        
        # Run the scan as a background thread
        def run_discovery():
            self.logger.info(f"Executing discovery: {' '.join(cmd)}")
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    self.logger.info("Discovery scan completed successfully")
                    
                    # Parse results
                    if os.path.exists(output_file):
                        try:
                            tree = ET.parse(output_file)
                            xml = tree.getroot()
                            
                            # Process discovery hosts
                            results = self.parse_xml_results(xml, "13")  # Use format for host discovery
                            
                            # Update client data
                            if results:
                                self.client_data.update(results)
                                self.logger.info(f"Found {len(results)} hosts from discovery scan")
                        except Exception as e:
                            self.logger.error(f"Error parsing discovery results: {e}")
                else:
                    self.logger.error(f"Discovery scan failed with code {process.returncode}: {stderr}")
            except Exception as e:
                self.logger.error(f"Error in discovery scan: {e}")
        
        # Start thread
        thread = threading.Thread(target=run_discovery, daemon=True)
        thread.start()
        
        return f"Started {method} discovery scan on {subnet}. Results will be available when complete."
    
    def handle_clear_command(self, args: list) -> str:
        """Handle clear commands (results)"""
        if not args:
            return "Missing clear command. Use: clear results"
        
        subcmd = args[0].lower()
        
        if subcmd == "results":
            self.client_data.clear()
            return "Scan results cleared."
        else:
            return f"Unknown clear command: {subcmd}"
    
    async def handle_custom_command(self, command: str) -> str:
        """Process user commands"""
        parts = command.strip().split()
        if not parts:
            return ""
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == "help":
                return self.get_help()
            
            elif cmd == "set":
                return self.handle_set_command(args)
            
            elif cmd == "list":
                return self.handle_list_command(args)
            
            elif cmd == "show":
                return self.handle_show_command(args)
            
            elif cmd == "discover":
                return self.handle_discover_command(args)
            
            elif cmd == "start":
                return self.start_scans()
            
            elif cmd == "clear":
                return self.handle_clear_command(args)
            
            else:
                return f"Unknown command: {cmd}. Type 'help' for usage."
        
        except Exception as e:
            self.logger.exception(f"Error handling command: {e}")
            return f"Error: {e}"
    
    def get_help(self) -> str:
        return """Available Commands:

  set          - Set configurations
    interface <name|#>   - Choose network interface
    targets <ip,ip,...>  - Set target IP addresses
    options <n1,n2,...>  - Select scan types by number

  list         - List information  
    interfaces           - Show available network interfaces
    targets              - Show discovered targets

  show         - Display information
    options              - Show available scan options
    results              - Show scan results
    processes            - Show running/completed processes

  discover     - Run discovery scans
    arp|ping|host        - Discover hosts using specified method

  start        - Start scans using selected options and targets
  
  clear        - Clear information
    results              - Clear scan results
    
  help         - Show this help message
"""
    
    def compose_status(self) -> str:
        """Return current tool status"""
        lines = ["Simple Network Mapper"]
        
        # Show selected interface
        if self.selected_eth_interface.get('ip'):
            info = self.selected_eth_interface
            lines.append(f"Ethernet Interface: {info['name']} ({info['ip']})")
        elif self.selected_wlan_interface.get('ip'):
            info = self.selected_wlan_interface
            lines.append(f"Wireless Interface: {info['name']} ({info['ip']})")
        else:
            lines.append("No interface selected. Use 'set interface <name|#>'")
        
        # Show selected targets
        if self.selected_targets:
            target_str = ", ".join(self.selected_targets[:3])
            if len(self.selected_targets) > 3:
                target_str += f" and {len(self.selected_targets) - 3} more"
            lines.append(f"Targets: {target_str}")
        else:
            lines.append("No targets selected. Use 'set targets <ip,ip,...>'")
        
        # Show selected options
        if self.selected_options:
            option_str = ", ".join(self.selected_options)
            lines.append(f"Options: {option_str}")
        else:
            lines.append("No options selected. Use 'set options <n1,n2,...>'")
        
        # Show running processes
        running = sum(1 for p in self.running_processes.values() if not p.get('completed', True))
        if running:
            lines.append(f"Running processes: {running}")
        
        return "\n".join(lines) 
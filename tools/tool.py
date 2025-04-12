# tools/tool.py
import ipaddress
import yaml
from pathlib import Path
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Static, Header, Input, Footer
from textual.app import ComposeResult
import asyncio

# local
from tools.tool_helpers import *
from tools.tool_helpers import get_wlan_interfaces, get_protocol_for_interface, get_mac_for_interface, get_gateway_for_interface, get_ip_for_interface

logger = logging.getLogger(__name__.lower())


class Tool:
    def __init__(self, name: str):
        self.name = name.lower()
        self.active = False

        # Only set self.base_dir if it hasn't already been defined by a subclass.
        if not hasattr(self, 'base_dir'):
            self.base_dir = Path(__file__).parent

        logger = logging.getLogger(f"Tool.{self.name}")
        logger.debug("Tool.__init__: base_dir set to %s", self.base_dir)

        # Determine the skeleton file candidate (defaults.yaml in self.base_dir)
        skeleton_candidate = Path(self.base_dir) / "defaults.yaml"
        logger.debug("Looking for skeleton defaults file at %s", skeleton_candidate)
        if skeleton_candidate.exists():
            logger.debug("Found skeleton file at %s", skeleton_candidate)
            skeleton_path = skeleton_candidate
        else:
            logger.debug("No skeleton file found at %s", skeleton_candidate)
            skeleton_path = None

        # Prepare the user config directory
        self.config_dir = os.path.expanduser("~/.pyfi_config")
        os.makedirs(self.config_dir, exist_ok=True)
        self.config_path = os.path.join(self.config_dir, f"{self.name}.yaml")

        # Load or initialize the config, merging from skeleton if provided
        self.config = self._load_or_init_config(skeleton_path)

        self.available_wlan_interfaces = get_wlan_interfaces()
        logger.debug("Available WLAN interfaces: %s", self.available_wlan_interfaces)
        self.selected_wlan_interface = {
            'name': "",
            'protocol': "",
            'mac': "",
            'gateway': "",
            'ip': ""
        }
        self.available_eth_interfaces = get_eth_interfaces()
        logger.debug("Available ETH interfaces: %s", self.available_eth_interfaces)
        self.selected_eth_interface = {
            'name': "",
            'protocol': "",
            'mac': "",
            'gateway': "",
            'ip': ""
        }

        self.logger = logging.getLogger(f"Tool.{self.name}")
        self.logger.debug("Tool %s initialized.", self.name)

    def _load_or_init_config(self, skeleton_path: Path | None) -> dict:
        """
        Load ~/.pyfi/<tool>.yaml, or if missing, copy from skeleton_path (if given),
        or create a blank skeleton. If a config file already exists, merge in any keys
        from the skeleton file.
        """
        logger = logging.getLogger(f"Tool.{self.name}")
        logger.debug("Starting config load for %s", self.config_path)

        data = {}
        if os.path.exists(self.config_path):
            logger.debug("Config file exists at %s, loading it.", self.config_path)
            try:
                with open(self.config_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                logger.debug("Loaded config: %s", data)
            except Exception as e:
                logger.exception("Failed to read config file %s: %s", self.config_path, e)
        else:
            logger.debug("Config file %s does not exist.", self.config_path)

        # Log which skeleton path we're using
        if skeleton_path:
            logger.debug("Skeleton file provided: %s", skeleton_path)
        else:
            logger.debug("No skeleton file provided.")

        # If a skeleton is provided and exists, merge its values into the data.
        if skeleton_path and skeleton_path.exists():
            logger.debug("Loading skeleton defaults from %s", skeleton_path)
            try:
                with open(skeleton_path, 'r') as f:
                    skeleton_data = yaml.safe_load(f) or {}
                logger.debug("Loaded skeleton defaults: %s", skeleton_data)
            except Exception as e:
                logger.exception("Failed to load skeleton file %s: %s", skeleton_path, e)
                skeleton_data = {}

            # Merge skeleton_data into data without overwriting existing values.
            for key, value in skeleton_data.items():
                if key not in data:
                    data[key] = value
                    logger.debug("Key '%s' missing in config, setting it to %s", key, value)
                else:
                    # Merge dictionaries if applicable
                    if isinstance(value, dict) and isinstance(data.get(key), dict):
                        for sub_key, sub_value in value.items():
                            if sub_key not in data[key] or data[key][sub_key] in [None, ""]:
                                data[key][sub_key] = sub_value
                                logger.debug("Sub-key '%s' under '%s' missing/empty in config, setting it to %s",
                                             sub_key, key, sub_value)
            logger.debug("Merged config after skeleton merge: %s", data)
        else:
            logger.debug("Skeleton file not found or not provided; no defaults merged.")

        # Ensure required sections exist.
        data.setdefault('default_extras', {})
        data.setdefault('user_extras', {})

        # Write out the updated config file
        try:
            with open(self.config_path, 'w') as f:
                yaml.safe_dump(data, f)
            logger.debug("Config file updated at %s with data: %s", self.config_path, data)
        except Exception as e:
            logger.exception("Failed to write config file %s: %s", self.config_path, e)

        logger.debug("Final config data: %s", data)
        return data

    def save_config(self):
        """Persist changes back to ~/.pyfi/<tool>.yaml."""
        with open(self.config_path, 'w') as f:
            yaml.safe_dump(self.config, f)

    def start(self) -> None:
        self.active = True
        self.logger.info("Tool %s started.", self.name)

    def stop(self) -> None:
        """Stop the tool and all its background activities.
        This should be overridden by subclasses to provide
        proper cleanup of resources, background threads, etc."""
        self.active = False
        self.logger.info("Tool %s stopped.", self.name)
        
        # Use a try/except for each task to prevent errors from
        # stopping the entire cleanup process
        
        # Example: Clean up any running tasks or threads
        try:
            # Stop any asyncio tasks created by this tool
            for task in asyncio.all_tasks():
                if task.get_name().startswith(f"{self.name}_"):
                    self.logger.debug(f"Cancelling task: {task.get_name()}")
                    task.cancel()
        except Exception as e:
            self.logger.error(f"Error stopping tasks: {e}")
            
        # Example: Release hardware resources
        try:
            # Close any open files
            # Release any hardware that might have been opened
            pass
        except Exception as e:
            self.logger.error(f"Error releasing resources: {e}")
            
        # Subclasses should call super().stop() to ensure this runs

    def get_screen(self) -> Screen:
        self.logger.debug("Generating screen for tool %s.", self.name)
        return ToolScreen(self)

    def compose(self) -> ComposeResult:
        self.logger.debug("Composing default UI for tool %s.", self.name)
        yield Static(f"{self.name}: No UI defined.")

    def handle_command(self, command: str) -> str:
        """
        Handle a command in the context of the tool.
        
        Args:
            command: String command to interpret.
            
        Returns:
            Response string to display to the user.
        """
        lower_cmd = command.lower().strip()
        
        # Handle common commands for all tools
        if lower_cmd == "start":
            self.start()
            return "Tool started successfully."
        elif lower_cmd == "stop":
            self.stop()
            return "Tool stopped successfully."
        
        # Handle tool-specific commands
        if hasattr(self, 'handle_custom_command'):
            response = self.handle_custom_command(command)
            return response
        else:
            return self.get_help()

    def handle_custom_command(self, command: str) -> str:
        self.logger.debug("Custom command not recognized: %s", command)
        return f"Unknown command for {self.name}: {command}"

    def get_help(self) -> str:
        self.logger.debug("Generating help message for tool %s.", self.name)
        help_lines = []
        help_lines.append("\n[bold]Commands:[/]")
        help_lines.append("  start      - Start the tool")
        help_lines.append("  stop       - Stop the tool")
        help_lines.append("  help       - Show this help message")
        help_lines.append("  show info  - Display interface information on demand")
        # Append the custom help text
        custom_help = self.get_custom_help()
        if custom_help:
            help_lines.append(custom_help)
        return "\n".join(help_lines)

    def get_custom_help(self) -> dict:
        return {}

    def populate_selected_wlan_interface(self, iface: str) -> None:
        self.logger.debug("Populating interface with: %s", iface)
        self.selected_wlan_interface['name'] = iface
        self.selected_wlan_interface['protocol'] = get_protocol_for_interface(iface)
        self.selected_wlan_interface['mac'] = get_mac_for_interface(iface)
        self.selected_wlan_interface['gateway'] = get_gateway_for_interface(iface)
        self.selected_wlan_interface['ip'] = get_ip_for_interface(iface)
        self.logger.info("Interface populated: %s", self.selected_wlan_interface)

    def debug_init(self) -> None:
        self.logger.debug("Debug initialization for tool %s.", self.name)

    ####################################################
    ########## SHARED NETWORK RELATED METHODs ##########
    ####################################################

    def calculate_subnet(self) -> str | None:
        """
        Synchronously calculate the subnet (in CIDR notation) using the selected interface.
        It checks WLAN first; if not available, it falls back to Ethernet.
        """
        # Choose which interface to use for subnet calculation
        ip = None
        netmask = None
        if self.selected_wlan_interface.get("ip") and self.selected_wlan_interface.get("netmask"):
            ip = self.selected_wlan_interface["ip"]
            netmask = self.selected_wlan_interface["netmask"]
        elif self.selected_eth_interface.get("ip") and self.selected_eth_interface.get("netmask"):
            ip = self.selected_eth_interface["ip"]
            netmask = self.selected_eth_interface["netmask"]
        else:
            self.logger.error("No valid interface with IP and netmask set for subnet calculation.")
            return None

        self.logger.debug("Calculating subnet from IP: %s and Netmask: %s", ip, netmask)
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            subnet = f"{network.network_address}/{network.prefixlen}"
            self.logger.debug("Calculated subnet: %s", subnet)
            return subnet
        except Exception as e:
            self.logger.error("Error calculating subnet: %s", e)
            return None

    async def handle_navigation_command(self, screen, command: str) -> bool:
        """
        Standard method to handle navigation commands like 'back', 'exit', 'quit', 'main'.
        
        Args:
            screen: The current screen object
            command: The command string to process
            
        Returns:
            True if the command was a navigation command and was handled,
            False if the command was not a navigation command
        """
        lower_cmd = command.lower().strip()
        if lower_cmd in ["back", "exit", "quit", "main"]:
            self.logger.debug(f"Handling navigation command: '{command}'")
            
            # Log current screen state before navigation
            try:
                self.logger.debug(f"UI STATE BEFORE NAV: Screen type: {type(screen).__name__}")
                self.logger.debug(f"UI STATE BEFORE NAV: App screen stack size: {len(screen.app.screen_stack)}")
                
                # Check for command input fields
                try:
                    if hasattr(screen, "command_input"):
                        self.logger.debug(f"UI STATE BEFORE NAV: command_input exists, has_focus={screen.command_input.has_focus}")
                    else:
                        self.logger.debug("UI STATE BEFORE NAV: screen has no command_input attribute")
                        
                    # Try looking up by query
                    input_fields = screen.query("Input")
                    self.logger.debug(f"UI STATE BEFORE NAV: Found {len(input_fields)} input fields by query")
                    for idx, field in enumerate(input_fields):
                        self.logger.debug(f"UI STATE BEFORE NAV: Input {idx}: id={field.id}, has_focus={field.has_focus}")
                except Exception as e:
                    self.logger.debug(f"UI STATE BEFORE NAV: Error inspecting input fields: {e}")
            except Exception as e:
                self.logger.error(f"Error logging screen state before navigation: {e}")
            
            # Import here to avoid circular imports
            from pyfi import MainNavigator
            
            # Log that we're about to call the navigation handler
            self.logger.debug("About to call MainNavigator.handle_back_command")
            
            # Call the navigation handler
            result = await MainNavigator.handle_back_command(screen, self)
            
            # Log the result and final state
            self.logger.debug(f"Navigation completed with result: {result}")
            
            try:
                # Log current app state
                app = screen.app
                self.logger.debug(f"UI STATE AFTER NAV: App screen stack size: {len(app.screen_stack)}")
                self.logger.debug(f"UI STATE AFTER NAV: Current app.screen type: {type(app.screen).__name__}")
                
                # Try to examine input fields on the new screen
                try:
                    if len(app.screen_stack) > 0:
                        current_screen = app.screen
                        input_fields = current_screen.query("Input")
                        self.logger.debug(f"UI STATE AFTER NAV: Found {len(input_fields)} input fields on new screen")
                        for idx, field in enumerate(input_fields):
                            self.logger.debug(f"UI STATE AFTER NAV: Input {idx}: id={field.id}, has_focus={field.has_focus}")
                except Exception as e:
                    self.logger.debug(f"UI STATE AFTER NAV: Error examining new screen: {e}")
            except Exception as e:
                self.logger.error(f"Error logging screen state after navigation: {e}")
            
            return True
            
        return False

class ToolScreen(Screen):
    def __init__(self, tool: Tool):
        self.tool = tool
        super().__init__()
        self.tool.logger.debug("ToolScreen for %s created.", self.tool.name)

    def compose(self) -> ComposeResult:
        self.tool.logger.debug("Composing ToolScreen for %s.", self.tool.name)
        yield Header()
        with Vertical():
            # Add an output area for command responses.
            yield Static("", id="tool_output", markup=True)
            # Display the tool's own UI components.
            yield from self.tool.compose()
            # Add a command input widget.
            self.command_input = Input(placeholder="Enter command...", id="tool_command")
            yield self.command_input
        yield Footer()
        
    def on_mount(self) -> None:
        """Called when the screen is first mounted"""
        self.tool.logger.debug("ToolScreen mounted, setting initial focus")
        
        # Set initial focus on the command input
        try:
            self.command_input.focus()
        except Exception as e:
            self.tool.logger.error(f"Error setting initial focus: {e}")
        
        # Set periodic check to ensure input stays focused
        self.focus_timer = self.set_interval(3.0, self.ensure_input_focused)
        
    def on_unmount(self) -> None:
        """Called when the screen is removed from the DOM"""
        self.tool.logger.debug("ToolScreen unmounting, cleaning up timers")
        try:
            # Remove all timers to prevent callbacks after screen is gone
            self.clear_intervals()
            self.tool.logger.debug("Successfully cleared all intervals")
        except Exception as e:
            self.tool.logger.error(f"Error clearing intervals during unmount: {e}")

    def ensure_input_focused(self) -> None:
        """Periodically ensure command input has focus"""
        try:
            if hasattr(self, "command_input") and not self.command_input.has_focus:
                self.tool.logger.debug("Input field lost focus, refocusing")
                self.command_input.focus()
        except Exception as e:
            self.tool.logger.error(f"Error ensuring input focus: {e}")

    def on_key(self, event):
        """Handle key events to ensure input field is focused"""
        try:
            # Make sure any keypress causes focus to return to input field
            if hasattr(self, "command_input") and not self.command_input.has_focus:
                self.tool.logger.debug("Refocusing input field on key press")
                self.command_input.focus()
        except Exception as e:
            self.tool.logger.error(f"Error in key handler: {e}")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        # This handler is generic and will update "#tool_output" if present.
        command = event.value.strip()
        self.tool.logger.debug(f"Received command: '{command}' on ToolScreen")
        
        # Handle emergency exit command first - this is a direct exit mechanism
        if command.lower().strip() == "emergency_exit":
            self.tool.logger.critical("Emergency exit requested, forcing app termination")
            try:
                # Try to stop tool first
                self.tool.stop()
            except:
                pass
                
            try:
                # Force exit the app
                import os, sys
                os._exit(0)  # Hard exit
            except:
                sys.exit(0)  # Softer exit
            return
        
        # Handle navigation commands through the standardized method
        is_nav_command = await self.tool.handle_navigation_command(self, command)
        if is_nav_command:
            return
        
        # If we're here, it's not a navigation command, so handle normally
        try:
            # Process command through the tool
            response = self.tool.handle_command(command)
            
            # Check if the tool is also requesting navigation
            if response == "__BACK_TO_MAIN__":
                self.tool.logger.debug("Tool requested navigation to main menu")
                
                # Use the centralized navigation handler
                from pyfi import MainNavigator
                await MainNavigator.handle_back_command(self, self.tool)
                return
            
            # Normal response handling for non-navigation commands
            try:
                self.query_one("#tool_output", Static).update(response)
            except Exception as e:
                self.tool.logger.warning("Error updating output: %s", e)
            
            # Clear input field
            try:
                self.query_one("#tool_command", Input).value = ""
            except Exception as e:
                self.tool.logger.warning("Error clearing input: %s", e)
                
        except Exception as e:
            self.tool.logger.error("Error handling command: %s", e)
            try:
                self.query_one("#tool_output", Static).update(f"Error: {e}")
                self.query_one("#tool_command", Input).value = ""
            except:
                pass

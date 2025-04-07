# tools/tool.py

import logging
from pathlib import Path
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Static, Header, Input, Footer
from textual.app import ComposeResult

# local
from tools.tool_helpers import *
from tools.tool_helpers import get_wlan_interfaces, get_protocol_for_interface, get_mac_for_interface, get_gateway_for_interface, get_ip_for_interface

logger = logging.getLogger(__name__.lower())

class Tool:
    def __init__(self, name: str):
        self.name = name.lower()
        self.base_dir = Path(__file__).parent
        self.active = False
        self.configs = None
        self.database = None

        self.available_wlan_interfaces = get_wlan_interfaces()
        logger.debug("Available WLAN interfaces: %s", self.available_wlan_interfaces)
        self.selected_wlan_interface = {
            'name': "",
            'protocol': "",
            'mac': "",
            'gateway': "",
            'ip': ""
        }

        self.logger = logging.getLogger(f"Tool.{self.name}")
        self.logger.debug("Tool %s initialized.", self.name)

    def start(self) -> None:
        self.active = True
        self.logger.info("Tool %s started.", self.name)

    def stop(self) -> None:
        self.active = False
        self.logger.info("Tool %s stopped.", self.name)

    def get_screen(self) -> Screen:
        self.logger.debug("Generating screen for tool %s.", self.name)
        return ToolScreen(self)

    def compose(self) -> ComposeResult:
        self.logger.debug("Composing default UI for tool %s.", self.name)
        yield Static(f"{self.name}: No UI defined.")

    def handle_command(self, command: str) -> str:
        self.logger.debug("Handling command '%s' for tool %s.", command, self.name)
        lower_cmd = command.lower()
        if lower_cmd == "start":
            self.start()
            return "Tool started."
        elif lower_cmd == "stop":
            self.stop()
            return "Tool stopped."
        else:
            return self.handle_custom_command(command)

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

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        # This handler is generic and will update "#tool_output" if present.
        command = event.value.strip()
        self.tool.logger.debug("Received command on ToolScreen: '%s'", command)
        response = self.tool.handle_command(command)
        try:
            self.query_one("#tool_output", Static).update(response)
        except Exception as e:
            self.tool.logger.debug("No #tool_output widget found; skipping update: %s", e)
        self.query_one("#tool_command", Input).value = ""

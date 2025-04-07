#!/usr/bin/env python3
import logging
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Input, Static

# local

# local
from tools.wifi_scanner.wifi_scanner import WifiScanner
from config.logging import setup_logging
setup_logging()
from config.oui_lookup import check_and_update_vendors
check_and_update_vendors()

# Define a list of available tools as tuples of (tool name, tool class)
AVAILABLE_TOOLS = [
    ("WiFi Scanner", WifiScanner),
    # Add more tools here as needed.
]

HELP_TEXT = (
    "[bold underline]Available commands:[/]\n"
    "help             - Show this help message\n"
    "list             - List available tools\n"
    "run <number>     - Run a tool by its number (e.g., run 1)\n"
    "exit             - Exit current tool window or app"
)

class WiPy(Screen):
    def compose(self) -> ComposeResult:
        yield Static(HELP_TEXT, id="main_help", markup=True)
        self.input_field = Input(placeholder="Type command...", id="main_input")
        yield self.input_field

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        help_widget = self.query_one("#main_help", Static)
        help_widget.update(help_widget.renderable + f"\n> {command}")
        self.input_field.value = ""
        await self.process_command(command)

    async def process_command(self, command: str):
        lower_cmd = command.lower()
        if lower_cmd == "help":
            self.query_one("#main_help", Static).update(HELP_TEXT)
        elif lower_cmd == "list":
            # Build a numbered list of available tools.
            lines = ["Available tools:"]
            for idx, (name, _) in enumerate(AVAILABLE_TOOLS, start=1):
                lines.append(f"{idx}. {name}")
            self.query_one("#main_help", Static).update("\n".join(lines))
        elif lower_cmd.startswith("run "):
            arg = command[len("run "):].strip()
            if arg.isdigit():
                index = int(arg) - 1
                if 0 <= index < len(AVAILABLE_TOOLS):
                    tool_name, tool_cls = AVAILABLE_TOOLS[index]
                    self.app.selected_tool = tool_cls()
                    # Automatically open the tool's screen.
                    await self.app.push_screen(self.app.selected_tool.get_screen())
                else:
                    self.query_one("#main_help", Static).update(f"Invalid number: {arg}")
            else:
                self.query_one("#main_help", Static).update("Please provide a valid number after 'run'")
        elif lower_cmd == "exit":
            await self.app.pop_screen()
        else:
            self.query_one("#main_help", Static).update(f"Unknown command: {command}")

class Main(App):
    async def on_mount(self):
        self.selected_tool = None  # To store a selected tool instance
        await self.push_screen(WiPy())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    Main().run()


import asyncio
from textual.app import ComposeResult
from textual.widgets import Static, Header, Footer, Input
from textual.containers import VerticalScroll
from rich.table import Table

# local
from tools.tool import ToolScreen


class NetworkMapperScreen(ToolScreen):
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="scroll"):
            # Status (selected interfaces, active state)
            yield Static("", id="status", markup=True)
            # Clients/results table
            yield Static("", id="client_table", markup=True)
            # Command output - Add tool_output ID to fix the errors
            yield Static("", id="tool_output", markup=True)
            # Keep the original command_output for backward compatibility
            yield Static("", id="command_output", markup=True)
        yield Input(placeholder="Enter command (e.g. 'scan top 192.168.1.0/24')...", id="tool_command")
        yield Footer()

    def on_mount(self) -> None:
        # Refresh every second
        self.set_interval(1, self.update_ui)
        
        # Focus the command input field immediately
        self.query_one("#tool_command", Input).focus()
        
        # Set up a key handler for the screen
        self.focus_timer = self.set_interval(3.0, self.ensure_input_focused)
        self.tool.logger.debug("NetworkMapperScreen mounted and timers initialized")

    def on_unmount(self) -> None:
        """Called when the screen is removed from the DOM"""
        self.tool.logger.debug("NetworkMapperScreen unmounting, cleaning up timers")
        try:
            # Remove all timers to prevent callbacks after screen is gone
            self.clear_intervals()
            self.tool.logger.debug("Successfully cleared all intervals/timers")
        except Exception as e:
            self.tool.logger.error(f"Error clearing intervals during unmount: {e}")
            
        # Let parent handle any other cleanup
        super().on_unmount()

    def ensure_input_focused(self) -> None:
        """Periodically check that input field has focus"""
        try:
            input_field = self.query_one("#tool_command", Input)
            if not input_field.has_focus:
                self.tool.logger.debug("Input field lost focus, refocusing")
                input_field.focus()
        except Exception as e:
            self.tool.logger.error(f"Error ensuring input focus: {e}")

    def on_key(self, event):
        """Handle key events to ensure input field is focused"""
        try:
            # Make sure any keypress causes focus to return to input field
            input_field = self.query_one("#tool_command", Input)
            if not input_field.has_focus:
                self.tool.logger.debug("Refocusing input field on key press")
                input_field.focus()
        except Exception as e:
            self.tool.logger.error(f"Error in key handler: {e}")

    def update_ui(self) -> None:
        # Update status
        status = self.tool.compose_status()
        self.query_one("#status", Static).update(status)

        # Show scan status if there are running scans
        has_running_scans = bool(getattr(self.tool, "running_processes", {}))
        
        # Update client table differently depending on discovery mode.
        if getattr(self.tool, "discovery_mode", False):
            table = self.tool.get_discovery_table()
            self.query_one("#client_table", Static).update(table)
        elif has_running_scans:
            # Show running scans status when scans are active
            try:
                scan_status = self.tool.get_processes_status()
                self.query_one("#client_table", Static).update(scan_status)
            except Exception as e:
                self.tool.logger.error(f"Error showing scan status: {e}")
        else:
            try:
                table = self.tool.get_results_table()
                self.query_one("#client_table", Static).update(table)
            except Exception as e:
                self.tool.logger.error(f"Error showing results table: {e}")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        cmd = event.value.strip()
        self.tool.logger.debug(f"Received command on NetworkMapperScreen: '{cmd}'")

        # Directly handle navigation commands first
        lower_cmd = cmd.lower().strip()
        if lower_cmd in ["back", "exit", "quit", "main"]:
            self.tool.logger.debug(f"Directly handling navigation: '{cmd}'")
            
            # Log UI state before navigation
            try:
                app = self.app
                self.tool.logger.debug(f"PRE_NAV_STATE: Screen stack size: {len(app.screen_stack)}")
                for i, screen in enumerate(app.screen_stack):
                    self.tool.logger.debug(f"PRE_NAV_STATE: Screen {i} in stack: {type(screen).__name__}")
            
                # Log input field focus state before navigation
                try:
                    input_field = self.query_one("#tool_command", Input)
                    self.tool.logger.debug(f"PRE_NAV_STATE: input_field exists, has_focus={input_field.has_focus}")
                except Exception as e:
                    self.tool.logger.debug(f"PRE_NAV_STATE: Error inspecting input field: {e}")
            except Exception as e:
                self.tool.logger.error(f"Error logging pre-navigation state: {e}")
            
            # Use the centralized navigation handler
            from pyfi import MainNavigator
            self.tool.logger.debug("About to call MainNavigator.handle_back_command")
            result = await MainNavigator.handle_back_command(self, self.tool)
            self.tool.logger.debug(f"Navigation result: {result}")
            
            # Try to log post-navigation state
            try:
                app = self.app
                self.tool.logger.debug(f"POST_NAV_STATE: Screen stack size: {len(app.screen_stack)}")
                
                for i, screen in enumerate(app.screen_stack):
                    self.tool.logger.debug(f"POST_NAV_STATE: Screen {i} in stack: {type(screen).__name__}")
                    
                # Check if we're still the active screen
                is_top = (len(app.screen_stack) > 0 and app.screen_stack[-1] is self)
                self.tool.logger.debug(f"POST_NAV_STATE: This NetworkMapperScreen is still at top of stack: {is_top}")
                
                # Check the current screen's input fields
                try:
                    current_screen = app.screen
                    self.tool.logger.debug(f"POST_NAV_STATE: Current screen type: {type(current_screen).__name__}")
                    
                    input_fields = current_screen.query("Input")
                    self.tool.logger.debug(f"POST_NAV_STATE: Found {len(input_fields)} input fields on current screen")
                    
                    for idx, field in enumerate(input_fields):
                        self.tool.logger.debug(f"POST_NAV_STATE: Input field {idx}: id={field.id}, has_focus={field.has_focus}")
                except Exception as e:
                    self.tool.logger.debug(f"POST_NAV_STATE: Error querying input fields on current screen: {e}")
            except Exception as e:
                self.tool.logger.error(f"Error logging post-navigation state: {e}")
                
            return

        # For all other commands, process through the tool
        result = self.tool.handle_custom_command(cmd)
        
        # Handle different result types
        if asyncio.iscoroutine(result):
            # If it's a coroutine, await it
            self.tool.logger.debug("Got coroutine result, awaiting it")
            response = await result
        elif isinstance(result, asyncio.Task):
            # If it's a Task, await it
            self.tool.logger.debug("Got Task result, awaiting it")
            response = await result
        else:
            # Regular string response
            response = result

        # Convert response to string if it's not already
        if not isinstance(response, str):
            response = str(response)

        # Update both output widgets to ensure at least one works
        try:
            self.query_one("#tool_output", Static).update("> " + response)
        except Exception as e:
            self.tool.logger.debug(f"Error updating #tool_output: {e}")
            
        try:
            self.query_one("#command_output", Static).update("> " + response)
        except Exception as e:
            self.tool.logger.debug(f"Error updating #command_output: {e}")
            
        # Clear input field
        self.query_one("#tool_command", Input).value = ""


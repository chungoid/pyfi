#!/usr/bin/env python3
import logging
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Input, Static
import asyncio

from tools.network_mapper.network_mapper import NetworkMapper
# local
from tools.wifi_scanner.wifi_scanner import WifiScanner
from config.global_logging import setup_logging
from utils.gps import global_gps
from config.oui_lookup import check_and_update_vendors

def setup():
    # run at startup
    setup_functions = [
        setup_logging,
        check_and_update_vendors,
        # etc
    ]

    for func in setup_functions:
        try:
            func()
            logging.debug(f"{func.__name__} completed successfully.")
        except Exception as e:
            logging.exception(f"Error in {func.__name__}: {e}")

# Define a list of available tools as tuples of (tool name, tool class)
AVAILABLE_TOOLS = [
    ("WiFi Scanner", WifiScanner),
    ("Network Mapper", NetworkMapper),
    # Add more tools here as needed.
]

HELP_TEXT = (
    "[bold underline]Available commands:[/]\n"
    "run <number>     - Run a tool by its number (e.g., run 1)\n"
    "list             - List available tools\n"
    "help             - Show this help message\n"    
    "debug            - Show application debug information\n"
    "reset            - Force reset application state\n"
    "hardrestart      - Completely restart the application if stuck\n"
    "exit             - Exit current tool window or app"
)

class PyFi(Screen):
    BINDINGS = [
        ("ctrl+r", "emergency_reset", "Force emergency app reset"),
        ("f5", "refresh_screen", "Force refresh screen and terminal state"),
    ]
    
    @staticmethod
    def reset_terminal_state():
        """
        A minimal terminal state reset that avoids problematic control sequences.
        We let Textual handle most terminal state management now.
        """
        try:
            logging.debug("Using minimal terminal state reset")
            return True
        except Exception as e:
            logging.error(f"Error in minimal terminal reset: {e}")
            return False
    
    def compose(self) -> ComposeResult:
        yield Static(HELP_TEXT, id="main_help", markup=True)
        self.input_field = Input(placeholder="Type command...", id="main_input")
        yield self.input_field

    def on_mount(self) -> None:
        """Called when the screen is first mounted"""
        logging.debug("PyFi screen mounted")
        # Focus the input field on initial mount
        self.input_field.focus()
        
        # Set up a periodic check to ensure input stays focused
        self.set_interval(1.0, self.ensure_input_focused)

    def ensure_input_focused(self) -> None:
        """Periodically ensure command input has focus"""
        try:
            if hasattr(self, "input_field") and not self.input_field.has_focus:
                logging.debug("Main input field lost focus, refocusing")
                self.input_field.focus()
        except Exception as e:
            logging.error(f"Error ensuring main input focus: {e}")

    def on_show(self) -> None:
        """Called when the screen is shown (including when returning from a tool)"""
        logging.critical("===== PYFI ON_SHOW CALLED =====")
        
        # Debug the screen stack state
        try:
            logging.critical(f"Current app: {type(self.app).__name__}")
            logging.critical(f"Screen stack size: {len(self.app.screen_stack)}")
            for i, screen in enumerate(self.app.screen_stack):
                logging.critical(f"Stack[{i}]: {type(screen).__name__}")
            
            logging.critical(f"Is PyFi the current app.screen? {self.app.screen is self}")
        except Exception as e:
            logging.critical(f"Error checking screen stack: {e}")
        
        # Reset the help text to avoid accumulated commands from previous sessions
        try:
            self.query_one("#main_help", Static).update(HELP_TEXT)
            logging.critical("Help text reset successfully")
        except Exception as e:
            logging.critical(f"Error updating help text: {e}")
        
        # Make sure the input field is properly initialized and focused
        try:
            logging.critical("Attempting to locate and focus main input field")
            
            # Find the input field
            try:
                input_field = self.query_one("#main_input", Input)
                logging.critical(f"Found main input: id={input_field.id}")
                self.input_field = input_field  # Store reference
            except Exception as e:
                logging.critical(f"Failed to find #main_input: {e}")
                return
            
            # Check field state
            logging.critical(f"Input field state: focused={input_field.has_focus}, visible={input_field.visible}")
            
            # Clear any existing text
            input_field.value = ""
            
            # Focus attempts
            logging.critical("Initial focus attempt")
            input_field.focus()
            logging.critical(f"After initial focus: has_focus={input_field.has_focus}")
            
            # Add multiple attempts with refresh
            for i in range(3):
                try:
                    logging.critical(f"Focus attempt #{i+1}")
                    input_field.focus()
                    self.refresh()
                    logging.critical(f"Focus state after attempt #{i+1}: {input_field.has_focus}")
                except Exception as e:
                    logging.critical(f"Error in focus attempt #{i+1}: {e}")
            
            # Add delayed focus attempts
            self.call_later(self._delayed_focus_1)
            self.call_later(self._delayed_focus_2)
            
            # Set a more delayed focus call as a fallback
            async def delayed_focus_3():
                await asyncio.sleep(0.5)
                try:
                    logging.critical("Delayed focus attempt #3")
                    if hasattr(self, 'input_field') and self.input_field:
                        self.input_field.focus()
                        self.refresh()
                        logging.critical(f"Focus state after delayed focus #3: {self.input_field.has_focus}")
                    else:
                        logging.critical("Input field reference lost in delayed_focus")
                except Exception as e:
                    logging.critical(f"Error in delayed focus #3: {e}")
            
            asyncio.create_task(delayed_focus_3())
            
            # Set up a repeated check for focus
            self.focus_check_timer = self.set_interval(0.5, self._check_focus_state)
            
        except Exception as e:
            logging.critical(f"Error initializing main input field: {e}")

    def _delayed_focus_1(self):
        """First delayed focus attempt"""
        try:
            logging.critical("Delayed focus attempt #1")
            if hasattr(self, 'input_field') and self.input_field:
                self.input_field.focus()
                self.refresh()
                logging.critical(f"Focus state after delayed focus #1: {self.input_field.has_focus}")
        except Exception as e:
            logging.critical(f"Error in delayed focus #1: {e}")

    def _delayed_focus_2(self):
        """Second delayed focus attempt"""
        try:
            logging.critical("Delayed focus attempt #2")
            if hasattr(self, 'input_field') and self.input_field:
                self.input_field.focus()
                self.refresh()
                logging.critical(f"Focus state after delayed focus #2: {self.input_field.has_focus}")
                
                # Check if app.focused is set correctly
                if hasattr(self.app, 'focused'):
                    focused = self.app.focused
                    logging.critical(f"App focused element: {type(focused).__name__ if focused else 'None'}, id={focused.id if focused and hasattr(focused, 'id') else 'N/A'}")
        except Exception as e:
            logging.critical(f"Error in delayed focus #2: {e}")

    def _check_focus_state(self):
        """Periodically check focus state to diagnose problems"""
        try:
            if not hasattr(self, 'input_field') or not self.input_field:
                logging.critical("FOCUS_CHECK: input_field reference is missing")
                return
            
            has_focus = self.input_field.has_focus
            logging.critical(f"FOCUS_CHECK: input_field.has_focus = {has_focus}")
            
            # Add DOM visibility check to identify hidden/overlapping elements
            try:
                # Check if field is visible and properly attached to DOM
                is_visible = self.input_field.visible
                is_displayed = self.input_field.display
                
                # Check if input field is in the active DOM tree
                in_dom = self.input_field in self.query("*")
                
                logging.critical(f"FOCUS_CHECK: DOM state - visible={is_visible}, display={is_displayed}, in_dom={in_dom}")
                
                # Check if any other input field exists that could be capturing focus
                all_inputs = self.query("Input")
                if len(all_inputs) > 1:
                    logging.critical(f"FOCUS_CHECK: Found {len(all_inputs)} input fields in current screen")
                    for idx, inp in enumerate(all_inputs):
                        if inp is not self.input_field:
                            logging.critical(f"FOCUS_CHECK: Extra input {idx}: id={inp.id}, has_focus={inp.has_focus}, visible={inp.visible}")
            except Exception as e:
                logging.critical(f"FOCUS_CHECK: Error in DOM visibility check: {e}")
            
            # Check what the app thinks is focused
            if hasattr(self.app, 'focused'):
                focused = self.app.focused
                logging.critical(f"FOCUS_CHECK: app.focused = {type(focused).__name__ if focused else 'None'}, id={focused.id if focused and hasattr(focused, 'id') else 'N/A'}")
            
            # If focus is lost, try to regain it
            if not has_focus:
                logging.critical("FOCUS_CHECK: Focus lost, attempting to regain")
                self.input_field.focus()
                self.refresh()
                logging.critical(f"FOCUS_CHECK: After focus attempt, has_focus={self.input_field.has_focus}")
        except Exception as e:
            logging.critical(f"Error in _check_focus_state: {e}")

    def on_unmount(self) -> None:
        """Clean up timers when screen is removed"""
        logging.critical("PyFi screen being unmounted")
        try:
            # Remove all timers
            self.clear_intervals()
            logging.critical("Successfully cleared all intervals/timers in PyFi")
        except Exception as e:
            logging.critical(f"Error clearing intervals during PyFi unmount: {e}")

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
        elif lower_cmd in ["exit", "back", "quit"]:
            # Exit the entire application
            self.app.exit()
        elif lower_cmd == "hardrestart":
            # Force a complete application exit and restart via Python executable
            try:
                logging.critical("HARD RESTART REQUESTED - executing system restart")
                self.query_one("#main_help", Static).update("Restarting application completely...")
                
                # Import needed for restarting
                import sys, os
                
                # Get the current executable path and arguments
                python = sys.executable
                script = os.path.abspath(sys.argv[0])
                args = sys.argv[1:]
                
                # Exit with special code that will trigger restart
                logging.critical(f"Executing restart: {python} {script} {' '.join(args)}")
                
                # Set a brief delay to allow UI to update
                await asyncio.sleep(0.5)
                
                # Force complete exit and restart
                os.execl(python, python, script, *args)
            except Exception as e:
                logging.critical(f"Failed to restart application: {e}")
                self.query_one("#main_help", Static).update(f"Restart failed: {e}")
        elif lower_cmd == "reset":
            # Force reset the screen stack
            try:
                logging.debug("Executing reset command")
                # Reset by clearing the screen stack and pushing the main screen again
                self.app.screen_stack.clear()
                logging.debug("Screen stack cleared")
                await self.app.push_screen("main")
                logging.debug("Main screen pushed again")
                self.query_one("#main_help", Static).update("Application state reset successfully")
            except Exception as e:
                logging.error("Error in reset command: %s", str(e))
                self.query_one("#main_help", Static).update(f"Error in reset command: {str(e)}")
        elif lower_cmd == "debug":
            # Debug command to show app state
            try:
                info = [
                    "App debug information:",
                    f"App type: {type(self.app).__name__}",
                    f"Screen stack size: {len(self.app.screen_stack)}",
                    f"Current screen: {type(self.app.screen).__name__}",
                    "Screens in stack:"
                ]
                for i, screen in enumerate(self.app.screen_stack):
                    info.append(f"  {i}: {type(screen).__name__}")
                self.query_one("#main_help", Static).update("\n".join(info))
            except Exception as e:
                logging.error("Error in debug command: %s", str(e))
                self.query_one("#main_help", Static).update(f"Error in debug command: {str(e)}")
        else:
            self.query_one("#main_help", Static).update(f"Unknown command: {command}")

    @classmethod
    async def switch_to(cls, app):
        """
        Force a proper switch to this screen class, cleaning up the existing screen stack
        and setting up a fresh instance.
        """
        logging.debug("PyFi.switch_to called for emergency navigation")
        
        # Stop any active tool
        if hasattr(app, 'selected_tool') and app.selected_tool:
            try:
                logging.debug("Stopping tool before switch_to")
                app.selected_tool.stop()
                app.selected_tool = None
            except Exception as e:
                logging.error("Error stopping tool: %s", e)
        
        try:
            # Clear screen stack
            app.screen_stack = []
            
            # Create a fresh screen
            fresh_screen = cls()
            
            # Set as current screen and add to stack
            app.screen = fresh_screen
            app.screen_stack.append(fresh_screen)
            
            # Initialize the screen
            await fresh_screen.on_show()
            
            # Force refresh
            app.refresh(layout=True)
            logging.debug("Screen switch completed")
            
            return fresh_screen
        except Exception as e:
            logging.critical("Failed to switch to PyFi screen: %s", e)
            logging.exception("Switch error details")
            raise

    # Add safe_reset method to PyFi screen as well
    async def safe_reset(self) -> None:
        """Safely reset the entire application."""
        logging.critical("===== SAFE RESET STARTED =====")
        
        # Log detailed state of the app
        logging.critical(f"Current screen type: {type(self.screen).__name__}")
        logging.critical(f"Screen stack size: {len(self.screen_stack)}")
        for i, screen in enumerate(self.screen_stack):
            logging.critical(f"Screen {i} in stack: {type(screen).__name__}")
        
        # Check focus state before reset
        try:
            if hasattr(self, 'focused'):
                focused = self.focused
                logging.critical(f"App focused element before reset: {type(focused).__name__ if focused else 'None'}, id={focused.id if focused and hasattr(focused, 'id') else 'N/A'}")
        except Exception as e:
            logging.critical(f"Error checking focus before reset: {e}")
        
        # Stop any running tools
        try:
            # Check for a selected tool and stop it
            if hasattr(self, "selected_tool") and self.selected_tool:
                logging.critical(f"Stopping selected tool: {self.selected_tool.name}")
                if hasattr(self.selected_tool, "stop") and callable(self.selected_tool.stop):
                    self.selected_tool.stop()
                self.selected_tool = None
        except Exception as e:
            logging.critical(f"Error stopping tools during reset: {e}")
        
        # Clear any input handlers and timers from screens before popping them
        try:
            # Clear timers from all screens in the stack
            for i, screen in enumerate(self.screen_stack):
                logging.critical(f"Checking screen {i} for timers")
                try:
                    if hasattr(screen, 'clear_intervals') and callable(screen.clear_intervals):
                        screen.clear_intervals()
                        logging.critical(f"Cleared intervals for screen {i}")
                except Exception as e:
                    logging.critical(f"Error clearing intervals for screen {i}: {e}")
        except Exception as e:
            logging.critical(f"Error clearing screen timers: {e}")
        
        # Fix terminal state - critical for text input to work again
        # Apply multiple terminal reset techniques for redundancy
        PyFi.reset_terminal_state()
        
        # Use proper methods to navigate back to the main screen
        try:
            # Log critical information about state before navigation
            logging.critical("===== SAFE RESET: PRE-NAVIGATION STATE =====")
            logging.critical(f"Current screen type: {type(self.screen).__name__}")
            logging.critical(f"Screen stack size: {len(self.screen_stack)}")
            for i, s in enumerate(self.screen_stack):
                logging.critical(f"Stack[{i}]: {type(s).__name__}")
                
                # Clear intervals for this screen
                try:
                    if hasattr(s, 'clear_intervals') and callable(s.clear_intervals):
                        s.clear_intervals()
                        logging.critical(f"Cleared intervals for screen {i}")
                except Exception as e:
                    logging.critical(f"Error clearing intervals for screen {i}: {e}")
            
            # AGGRESSIVE RESET: Instead of popping screens, completely rebuild the stack
            logging.critical("Starting aggressive screen stack reset")
            old_stack = list(self.screen_stack)  # Keep reference for cleanup
            
            # Create a fresh screen
            fresh_screen = PyFi()
            logging.critical("Created fresh PyFi screen")
            
            # Replace entire screen stack
            self.screen_stack = []
            self.screen = fresh_screen
            self.screen_stack.append(fresh_screen)
            
            # Initialize the new screen
            await fresh_screen.on_mount()
            logging.critical("Fresh screen mounted")
            await fresh_screen.on_show()
            logging.critical("Fresh screen on_show called")
            
            # Forcibly try to set focus
            try:
                main_input = fresh_screen.query_one("#main_input", Input)
                main_input.focus()
                logging.critical(f"Focus attempt on fresh screen: has_focus={main_input.has_focus}")
                
                # Schedule multiple focus attempts
                self.call_later(main_input.focus)
                self.call_later(main_input.focus)
            except Exception as e:
                logging.critical(f"Error focusing input on fresh screen: {e}")
            
            # Force screen refresh
            self.refresh(layout=True)
            logging.critical("App refreshed with new screen")
            
            # Try to clean up old screens properly
            for i, old_screen in enumerate(old_stack):
                try:
                    if hasattr(old_screen, 'on_unmount') and callable(old_screen.on_unmount):
                        old_screen.on_unmount()
                        logging.critical(f"Called on_unmount for old screen {i}")
                except Exception as e:
                    logging.critical(f"Error in on_unmount for old screen {i}: {e}")
            
            logging.critical("===== SAFE RESET: COMPLETED AGGRESSIVE RESET =====")
        except Exception as e:
            logging.error(f"Error during aggressive reset: {e}")
            # Last resort - brute force approach
            try:
                logging.critical("Using emergency navigation approach")
                # Just push a new screen and hope it works
                fresh_pyfi = PyFi()
                await self.push_screen(fresh_pyfi)
                logging.debug("Emergency navigation completed")
                
                # One final attempt to focus the input
                try:
                    await asyncio.sleep(0.3)
                    fresh_pyfi.query_one("#main_input", Input).focus()
                    logging.debug("Final focus attempt made")
                except Exception as e:
                    logging.error(f"Error in final focus attempt: {e}")
            except Exception as final_e:
                logging.critical(f"Fatal error in emergency recovery: {final_e}")
        
        logging.info("App reset completed")

    async def action_emergency_reset(self) -> None:
        """Force emergency reset of the app through keyboard shortcut."""
        logging.critical("KEYBOARD EMERGENCY RESET TRIGGERED")
        try:
            # Update the help text to show the reset is happening
            help_widget = self.query_one("#main_help", Static)
            help_widget.update("EMERGENCY RESET IN PROGRESS...\nPlease wait...")
            self.refresh()
            
            # Try to find the app and reset it
            app = self.app
            if app:
                # First try safe_reset if available
                if hasattr(app, "safe_reset") and callable(app.safe_reset):
                    await app.safe_reset()
                    return
                
                # If not, create fresh screen and set it directly
                try:
                    # Clear screen stack
                    app.screen_stack = []
                    
                    # Create fresh screen
                    fresh = PyFi()
                    app.screen = fresh
                    app.screen_stack = [fresh]
                    
                    # Initialize
                    await fresh.on_mount()
                    await fresh.on_show()
                    
                    # Force refresh
                    app.refresh(layout=True)
                except Exception as e:
                    logging.critical(f"Failed to reset from keyboard: {e}")
        except Exception as e:
            logging.critical(f"Error in keyboard emergency reset: {e}")

    async def action_refresh_screen(self) -> None:
        """Force refresh the screen and terminal state."""
        logging.info("Manual screen refresh triggered with F5")
        try:
            # Reset terminal state
            import os
            os.system('stty sane')
            
            # Force UI refresh
            self.app.refresh(layout=True)
            
            # Clear and focus input
            if hasattr(self, "input_field"):
                self.input_field.value = ""
                self.input_field.focus()
            
            # Update help text
            help_widget = self.query_one("#main_help", Static)
            help_widget.update(HELP_TEXT + "\n\nScreen refreshed. Terminal state reset.")
            
            logging.info("Manual screen refresh completed")
        except Exception as e:
            logging.error(f"Error in manual screen refresh: {e}")

    def on_key(self, event):
        """Handle raw key events to help with input field focus."""
        try:
            # Ensure input field has focus when any key is pressed
            if hasattr(self, "input_field") and not self.input_field.has_focus:
                logging.debug("Main menu input field lost focus, refocusing on key press")
                self.input_field.focus()
                
                # Try second method of focus
                self.call_later(self.input_field.focus)
        except Exception as e:
            logging.error(f"Error in key handler: {e}")

class MainNavigator:
    """
    Utility class to handle navigation to the main menu from any screen.
    This provides a reliable way to get back to the main menu regardless of UI state.
    """
    
    @staticmethod
    async def go_to_main(screen, tool=None):
        """
        Navigate back to the main menu using the most reliable approach.
        """
        logging.debug("MainNavigator.go_to_main called")
        
        # Log pre-navigation state with DOM info
        app = screen.app
        logging.critical("===== NAVIGATION DIAGNOSTICS: PRE-NAVIGATION STATE =====")
        logging.critical(f"Current screen type: {type(screen).__name__}")
        logging.critical(f"Screen stack size: {len(app.screen_stack)}")
        for i, s in enumerate(app.screen_stack):
            logging.critical(f"Screen {i} in stack: {type(s).__name__}")
        
        # Check for focused elements before navigation
        try:
            # Get all input fields in the current DOM
            all_inputs = screen.query("Input")
            logging.critical(f"Found {len(all_inputs)} input fields in current screen")
            
            for idx, inp in enumerate(all_inputs):
                logging.critical(f"Input {idx}: id={inp.id}, has_focus={inp.has_focus}, visible={inp.visible}, display={inp.display}")
            
            # Check what element has focus in the app
            try:
                if hasattr(app, 'focused'):
                    focused = app.focused
                    logging.critical(f"App focused element: {type(focused).__name__ if focused else 'None'}, id={focused.id if focused and hasattr(focused, 'id') else 'N/A'}")
            except Exception as e:
                logging.critical(f"Error getting app.focused: {e}")
        except Exception as e:
            logging.critical(f"Error inspecting DOM before navigation: {e}")
        
        try:
            # Stop the tool if provided
            if tool:
                try:
                    if hasattr(tool, "stop") and callable(tool.stop):
                        logging.debug("Stopping tool")
                        tool.stop()
                except Exception as e:
                    logging.error(f"Error stopping tool: {e}")
            
            # Log app type for debugging
            logging.debug(f"App type is: {type(app).__name__}")
            
            # Check if the app itself is a Main instance with safe_reset method
            if hasattr(app, "safe_reset") and callable(app.safe_reset):
                logging.info("App has safe_reset method, using it directly")
                try:
                    await app.safe_reset()
                    logging.debug("App safe_reset completed successfully")
                    
                    # Log post-reset state with extensive DOM details
                    logging.critical("===== NAVIGATION DIAGNOSTICS: POST-RESET STATE =====")
                    
                    # Check current screen stack
                    logging.critical(f"Screen stack size after reset: {len(app.screen_stack)}")
                    for i, s in enumerate(app.screen_stack):
                        logging.critical(f"Screen {i} in stack after reset: {type(s).__name__}")
                    
                    # Check current screen
                    current_screen = app.screen
                    logging.critical(f"Current screen after reset: {type(current_screen).__name__}")
                    
                    # Check for input fields in current screen after reset
                    try:
                        post_inputs = current_screen.query("Input")
                        logging.critical(f"Found {len(post_inputs)} input fields after reset")
                        
                        for idx, inp in enumerate(post_inputs):
                            logging.critical(f"Post-reset input {idx}: id={inp.id}, has_focus={inp.has_focus}, visible={inp.visible}, display={inp.display}")
                        
                        # If main menu screen, try to explicitly focus the main input
                        if isinstance(current_screen, PyFi) and len(post_inputs) > 0:
                            main_input = None
                            try:
                                main_input = current_screen.query_one("#main_input", Input)
                                logging.critical(f"Found #main_input, has_focus={main_input.has_focus}, visible={main_input.visible}")
                                
                                # Try explicitly focusing the input
                                logging.critical("Explicitly focusing main input")
                                main_input.focus()
                                
                                # Check focus state
                                logging.critical(f"After explicit focus, has_focus={main_input.has_focus}")
                                
                                # Log focused element in app
                                if hasattr(app, 'focused'):
                                    focused = app.focused
                                    logging.critical(f"App focused element after explicit focus: {type(focused).__name__ if focused else 'None'}, id={focused.id if focused and hasattr(focused, 'id') else 'N/A'}")
                            except Exception as e:
                                logging.critical(f"Error focusing main input: {e}")
                    except Exception as e:
                        logging.critical(f"Error querying inputs after reset: {e}")
                    
                    # Check for any zombie screens that might be capturing input
                    try:
                        # If we're using Textual, try to check rendering tree
                        if hasattr(app, 'screen_stack'):
                            logging.critical("Checking for potential zombie screens in app.screen_stack:")
                            for i, s in enumerate(app.screen_stack):
                                logging.critical(f"  Stack[{i}]: {type(s).__name__}, mounted={getattr(s, 'is_mounted', 'unknown')}")
                                
                                # Check for focused elements within this screen
                                try:
                                    screen_inputs = s.query("Input") if hasattr(s, 'query') else []
                                    for j, inp in enumerate(screen_inputs):
                                        logging.critical(f"    Input[{j}] in {i}: id={inp.id}, has_focus={inp.has_focus}")
                                except Exception as e:
                                    logging.critical(f"    Error checking inputs in stack[{i}]: {e}")
                    except Exception as e:
                        logging.critical(f"Error checking for zombie screens: {e}")
                    
                    return True
                except Exception as e:
                    logging.error(f"Error in app.safe_reset: {e}")
                    # Continue to fallbacks
                
            # ------ FALLBACK APPROACHES BELOW ------
            
            # Try to pop screens until we get back to the main screen
            try:
                logging.info("Trying to pop screens until we reach the main menu")
                while len(app.screen_stack) > 1:
                    await app.pop_screen()
                    logging.debug("Popped a screen from stack")
                    
                logging.debug("Reached the bottom of screen stack")
                
                # Force a refresh
                app.refresh(layout=True)
                
                # Get the current screen and try to focus the input if it's PyFi
                current_screen = app.screen
                if isinstance(current_screen, PyFi):
                    try:
                        input_field = current_screen.query_one("#main_input", Input)
                        input_field.focus()
                        app.call_later(input_field.focus)
                        logging.debug("Focused input field on PyFi screen")
                        
                        # Log the focus state after setting it
                        logging.debug(f"UI STATE AFTER FOCUS: Input field has_focus={input_field.has_focus}")
                        return True
                    except Exception as e:
                        logging.error(f"Error focusing input: {e}")
                
                return True
            except Exception as e:
                logging.error(f"Error popping screens: {e}")
                # Continue to next fallback
            
            # Try alternative direct reset if needed
            if type(app).__name__ == "Main" and not app.screen_stack:
                logging.warning("Main app with empty screen stack, attempting direct recovery")
                try:
                    # Direct emergency recovery at the app level
                    fresh_screen = PyFi()
                    app.screen = fresh_screen
                    app.screen_stack = [fresh_screen]
                    await fresh_screen.on_mount()
                    await fresh_screen.on_show()
                    app.refresh(layout=True)
                    logging.info("Direct app recovery successful")
                    return True
                except Exception as e:
                    logging.error(f"Direct app recovery failed: {e}")
                    # Continue to next fallback
            
            # Try to find any screen with safe_reset method
            for s in app.screen_stack:
                if hasattr(s, "safe_reset") and callable(s.safe_reset):
                    logging.info(f"Found screen with safe_reset: {type(s).__name__}")
                    try:
                        await s.safe_reset()
                        logging.debug("Screen safe_reset completed successfully")
                        return True
                    except Exception as e:
                        logging.error(f"Error in screen.safe_reset: {e}")
                        # Continue to next screen or fallback
            
            # Fallback if no safe_reset method found or all failed
            logging.warning("No working safe_reset found, using fallback navigation")
            
            # Try to run switch_to if available on PyFi
            try:
                if hasattr(PyFi, "switch_to") and callable(PyFi.switch_to):
                    logging.info("Using PyFi.switch_to for emergency recovery")
                    await PyFi.switch_to(app)
                    logging.info("PyFi.switch_to completed successfully")
                    return True
            except Exception as e:
                logging.error(f"Error in PyFi.switch_to: {e}")
                # Continue to final fallback
        except Exception as e:
            logging.error(f"Fatal error in go_to_main: {e}")
            return False

    @staticmethod
    async def handle_back_command(screen, tool, custom_feedback=None):
        """
        Standard method to handle 'back', 'exit', 'quit', 'main' commands from any screen.
        This centralizes the navigation logic to avoid duplication.
        
        Args:
            screen: The current screen object
            tool: The tool associated with the screen (for stopping)
            custom_feedback: Optional feedback message to show before navigation
        
        Returns:
            True if navigation was successful, False otherwise
        """
        logging.debug("MainNavigator.handle_back_command called")
        
        # Add detailed UI state diagnostics
        try:
            app = screen.app
            logging.debug(f"BACK_NAV_STATE: Current screen type: {type(screen).__name__}")
            logging.debug(f"BACK_NAV_STATE: Screen stack size: {len(app.screen_stack)}")
            for i, s in enumerate(app.screen_stack):
                logging.debug(f"BACK_NAV_STATE: Screen {i} in stack: {type(s).__name__}")
            
            # Check for input fields in the current screen
            try:
                input_fields = screen.query("Input")
                logging.debug(f"BACK_NAV_STATE: Found {len(input_fields)} input fields in current screen")
                for idx, field in enumerate(input_fields):
                    logging.debug(f"BACK_NAV_STATE: Input field {idx}: id={field.id}, has_focus={field.has_focus}")
            except Exception as e:
                logging.debug(f"BACK_NAV_STATE: Error querying input fields: {e}")
        except Exception as e:
            logging.error(f"Error logging back navigation state: {e}")
        
        # Show feedback if UI element exists
        try:
            feedback = custom_feedback or "Returning to main menu..."
            try:
                # Try tools/scanner style first
                screen.query_one("#command_output", Static).update(f"> {feedback}")
            except:
                try:
                    # Try network style
                    screen.query_one("#network_command_output", Static).update(f"> {feedback}")
                except:
                    try:
                        # Try generic tool style
                        screen.query_one("#tool_output", Static).update(feedback)
                    except:
                        logging.debug("No output widget found for feedback")
            
            # Force UI update and wait for it to be processed
            screen.refresh()
            await asyncio.sleep(0.2)  # Give UI time to update
        except Exception as e:
            logging.warning(f"Error showing feedback: {e}")
        
        # Stop the tool
        try:
            logging.debug(f"Stopping tool: {tool.name}")
            tool.stop()
            logging.debug("Tool stopped successfully")
        except Exception as e:
            logging.error(f"Error stopping tool: {e}")
        
        # Navigate to main
        logging.debug("About to call go_to_main for navigation")
        result = await MainNavigator.go_to_main(screen, tool)
        logging.debug(f"go_to_main returned: {result}")
        
        # Final state check after navigation
        try:
            app = screen.app
            logging.debug(f"BACK_NAV_FINAL: Screen stack size: {len(app.screen_stack)}")
            if len(app.screen_stack) > 0:
                current_screen = app.screen
                logging.debug(f"BACK_NAV_FINAL: Current screen type: {type(current_screen).__name__}")
                
                # Check if it's the main screen
                is_main = isinstance(current_screen, PyFi)
                logging.debug(f"BACK_NAV_FINAL: Current screen is main PyFi: {is_main}")
                
                # Check for input fields in the final screen
                try:
                    input_fields = current_screen.query("Input")
                    logging.debug(f"BACK_NAV_FINAL: Found {len(input_fields)} input fields in final screen")
                    for idx, field in enumerate(input_fields):
                        logging.debug(f"BACK_NAV_FINAL: Input field {idx}: id={field.id}, has_focus={field.has_focus}")
                    
                    # Try a final focus attempt if the main screen is detected
                    if is_main:
                        try:
                            main_input = current_screen.query_one("#main_input", Input)
                            if not main_input.has_focus:
                                logging.debug("BACK_NAV_FINAL: Main input not focused, attempting to focus")
                                main_input.focus()
                                current_screen.call_later(main_input.focus)
                                logging.debug(f"BACK_NAV_FINAL: After focus attempt, has_focus={main_input.has_focus}")
                        except Exception as e:
                            logging.error(f"BACK_NAV_FINAL: Error focusing main input: {e}")
                except Exception as e:
                    logging.debug(f"BACK_NAV_FINAL: Error querying input fields: {e}")
        except Exception as e:
            logging.error(f"Error in final back navigation state check: {e}")
        
        return result

class Main(App):
    SCREENS = {
        "main": PyFi,
    }
    
    async def on_mount(self):
        self.selected_tool = None  # To store a selected tool instance
        self.gps = global_gps # global gps instance from utils/gps.py
        logging.debug("Main app mounting, pushing 'main' screen")
        await self.push_screen("main")
        logging.debug("Main screen pushed successfully")
    
    async def action_back_to_main(self):
        """Action to return to the main menu by completely exiting and restarting the app"""
        logging.debug("action_back_to_main called")
        return await MainNavigator.go_to_main(self)
    
    async def emergency_reset(self):
        """
        Emergency method to reset the app to a clean state when normal navigation fails.
        This is a last resort to avoid freezing.
        """
        logging.critical("EMERGENCY RESET TRIGGERED")
        return await MainNavigator.go_to_main(self)
        
    def pop_to_root(self):
        """
        Pop all screens except the root/first screen.
        This is a safe way to get back to the main menu.
        """
        logging.debug("pop_to_root called")
        # Keep popping until we only have one screen left (the root)
        while len(self.screen_stack) > 1:
            try:
                popped = self.screen_stack.pop()
                logging.debug(f"Popped screen: {type(popped).__name__}")
            except Exception as e:
                logging.error(f"Error popping screen: {e}")
                break
        
        # Make sure we're on the root screen
        if self.screen_stack:
            try:
                self.screen = self.screen_stack[0]
                logging.debug(f"Set screen to: {type(self.screen).__name__}")
            except Exception as e:
                logging.error(f"Error setting screen: {e}")
        
        # If we somehow ended up with no screens, push a main screen
        if not self.screen_stack:
            logging.warning("No screens left after pop_to_root, creating emergency screen")
            try:
                main_screen = PyFi()
                self.screen = main_screen
                self.screen_stack.append(main_screen)
                logging.debug("Emergency screen created and pushed")
            except Exception as e:
                logging.critical(f"Failed to create emergency screen: {e}")
        
        return True

    # Add a safe way to completely reset the app
    """
    Improved Main.safe_reset method implementation that uses Textual's proper APIs
    for screen navigation instead of trying to manipulate the screen_stack directly.
    """

    async def safe_reset(self) -> None:
        """Safely reset the entire application."""
        logging.critical("===== SAFE RESET STARTED =====")
        
        # Log detailed state of the app
        logging.critical(f"Current screen type: {type(self.screen).__name__}")
        logging.critical(f"Screen stack size: {len(self.screen_stack)}")
        for i, screen in enumerate(self.screen_stack):
            logging.critical(f"Screen {i} in stack: {type(screen).__name__}")
        
        # Check focus state before reset
        try:
            if hasattr(self, 'focused'):
                focused = self.focused
                logging.critical(f"App focused element before reset: {type(focused).__name__ if focused else 'None'}, id={focused.id if focused and hasattr(focused, 'id') else 'N/A'}")
        except Exception as e:
            logging.critical(f"Error checking focus before reset: {e}")
        
        # Stop any running tools
        try:
            # Check for a selected tool and stop it
            if hasattr(self, "selected_tool") and self.selected_tool:
                logging.critical(f"Stopping selected tool: {self.selected_tool.name}")
                if hasattr(self.selected_tool, "stop") and callable(self.selected_tool.stop):
                    self.selected_tool.stop()
                self.selected_tool = None
        except Exception as e:
            logging.critical(f"Error stopping tools during reset: {e}")
        
        # Clear any input handlers and timers from screens before popping them
        try:
            # Clear timers from all screens in the stack
            for i, screen in enumerate(self.screen_stack):
                logging.critical(f"Checking screen {i} for timers")
                try:
                    if hasattr(screen, 'clear_intervals') and callable(screen.clear_intervals):
                        screen.clear_intervals()
                        logging.critical(f"Cleared intervals for screen {i}")
                except Exception as e:
                    logging.critical(f"Error clearing intervals for screen {i}: {e}")
        except Exception as e:
            logging.critical(f"Error clearing screen timers: {e}")
        
        # Fix terminal state - critical for text input to work again
        # Apply multiple terminal reset techniques for redundancy
        PyFi.reset_terminal_state()
        
        # Use proper methods to navigate back to the main screen
        try:
            # Log critical information about state before navigation
            logging.critical("===== SAFE RESET: PRE-NAVIGATION STATE =====")
            logging.critical(f"Current screen type: {type(self.screen).__name__}")
            logging.critical(f"Screen stack size: {len(self.screen_stack)}")
            for i, s in enumerate(self.screen_stack):
                logging.critical(f"Stack[{i}]: {type(s).__name__}")
                
                # Clear intervals for this screen
                try:
                    if hasattr(s, 'clear_intervals') and callable(s.clear_intervals):
                        s.clear_intervals()
                        logging.critical(f"Cleared intervals for screen {i}")
                except Exception as e:
                    logging.critical(f"Error clearing intervals for screen {i}: {e}")
            
            # AGGRESSIVE RESET: Instead of popping screens, completely rebuild the stack
            logging.critical("Starting aggressive screen stack reset")
            old_stack = list(self.screen_stack)  # Keep reference for cleanup
            
            # Create a fresh screen
            fresh_screen = PyFi()
            logging.critical("Created fresh PyFi screen")
            
            # Replace entire screen stack
            self.screen_stack = []
            self.screen = fresh_screen
            self.screen_stack.append(fresh_screen)
            
            # Initialize the new screen
            await fresh_screen.on_mount()
            logging.critical("Fresh screen mounted")
            await fresh_screen.on_show()
            logging.critical("Fresh screen on_show called")
            
            # Forcibly try to set focus
            try:
                main_input = fresh_screen.query_one("#main_input", Input)
                main_input.focus()
                logging.critical(f"Focus attempt on fresh screen: has_focus={main_input.has_focus}")
                
                # Schedule multiple focus attempts
                self.call_later(main_input.focus)
                self.call_later(main_input.focus)
            except Exception as e:
                logging.critical(f"Error focusing input on fresh screen: {e}")
            
            # Force screen refresh
            self.refresh(layout=True)
            logging.critical("App refreshed with new screen")
            
            # Try to clean up old screens properly
            for i, old_screen in enumerate(old_stack):
                try:
                    if hasattr(old_screen, 'on_unmount') and callable(old_screen.on_unmount):
                        old_screen.on_unmount()
                        logging.critical(f"Called on_unmount for old screen {i}")
                except Exception as e:
                    logging.critical(f"Error in on_unmount for old screen {i}: {e}")
            
            logging.critical("===== SAFE RESET: COMPLETED AGGRESSIVE RESET =====")
        except Exception as e:
            logging.error(f"Error during aggressive reset: {e}")
            # Last resort - brute force approach
            try:
                logging.critical("Using emergency navigation approach")
                # Just push a new screen and hope it works
                fresh_pyfi = PyFi()
                await self.push_screen(fresh_pyfi)
                logging.debug("Emergency navigation completed")
                
                # One final attempt to focus the input
                try:
                    await asyncio.sleep(0.3)
                    fresh_pyfi.query_one("#main_input", Input).focus()
                    logging.debug("Final focus attempt made")
                except Exception as e:
                    logging.error(f"Error in final focus attempt: {e}")
            except Exception as final_e:
                logging.critical(f"Fatal error in emergency recovery: {final_e}")
        
        logging.info("App reset completed")

if __name__ == "__main__":
    setup()
    logging.basicConfig(level=logging.INFO)
    Main().run()


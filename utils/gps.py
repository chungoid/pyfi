import gpsd
import time
import threading
import logging
import os
from utils.helpers import run_suppressed_cmd  # Your helper to run commands quietly

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class GPS:
    def __init__(self, host="127.0.0.1", port=2947):
        self.host = host
        self.port = port
        self.last_fix = None         # Cache for the last known valid fix (lat, lon)
        self.running = True          # Flag to control the background thread
        self.connect()
        # Start a background thread that continuously updates last_fix.
        self.update_thread = threading.Thread(target=self._update_fix, daemon=True)
        self.update_thread.start()

    def connect(self):
        """
        Connect to gpsd using the provided host and port.
        """
        try:
            gpsd.connect(host=self.host, port=self.port)
            logger.debug("Connected to gpsd at %s:%s", self.host, self.port)
        except Exception as e:
            logger.error("Failed to connect to gpsd: %s", e)

    def _update_fix(self, poll_timeout=10, update_interval=5):
        """
        Background thread that continuously polls for a GPS fix.
        On success, the fix (tuple of latitude and longitude) is cached in self.last_fix.
        """
        while self.running:
            try:
                fix = self._get_fix(timeout=poll_timeout)
                self.last_fix = fix
                logger.debug("Cached new GPS fix: %s", fix)
            except Exception as e:
                logger.error("Failed to update GPS fix: %s", e)
            time.sleep(update_interval)

    def _get_fix(self, timeout=10):
        """
        Blocking call to get the current GPS fix as a tuple (latitude, longitude).
        Waits until a valid 2D fix is acquired or raises an exception if the timeout is reached.
        """
        start_time = time.time()
        while True:
            try:
                packet = gpsd.get_current()
                position = packet.position()  # Raises NoFixError if no fix is available
                logger.debug("Acquired GPS position: %s", position)
                return position
            except gpsd.NoFixError:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    logger.error("No GPS fix acquired after %s seconds.", timeout)
                    raise gpsd.NoFixError(f"Timeout reached: No 2D fix available after {timeout} seconds.")
                logger.debug("No GPS fix yet, waiting... (%0.1f seconds elapsed)", elapsed)
                time.sleep(1)

    def reset_gpsd(self):
        """
        Resets gpsd by stopping its service, removing stale socket and lock files,
        and then restarting the service.
        """
        commands = [
            "sudo systemctl stop gpsd",
            "sudo rm -f /var/run/gpsd.sock",
            "sudo rm -f /var/lock/gpsd.lock",
            "sudo systemctl start gpsd"
        ]
        for cmd in commands:
            logger.debug("Executing: %s", cmd)
            try:
                output = run_suppressed_cmd(cmd, capture_output=True)
                logger.debug("Executed: %s, output: %s", cmd, output)
            except Exception as e:
                logger.error("Command failed: %s", cmd)
                raise e
        time.sleep(2)  # Allow time for gpsd to restart and create its socket
        self.connect()
        if os.path.exists("/var/run/gpsd.sock") or os.path.exists("/run/gpsd.sock"):
            logger.debug("gpsd socket file exists, reset successful.")
        else:
            logger.error("gpsd socket file not found after reset.")

    def get_position_with_auto_reset(self, attempt_timeout=60, max_attempts=3):
        """
        (Optional) Attempts to retrieve a GPS fix manually, resetting gpsd if necessary.
        """
        attempts = 0
        while attempts < max_attempts:
            try:
                return self._get_fix(timeout=attempt_timeout)
            except gpsd.NoFixError as e:
                attempts += 1
                logger.debug("Attempt %d of %d failed to get a fix: %s", attempts, max_attempts, e)
                logger.debug("Resetting gpsd...")
                self.reset_gpsd()
        raise gpsd.NoFixError(f"Failed to get GPS fix after {max_attempts} attempts.")

    def stop(self):
        """
        Stops the background update thread.
        """
        self.running = False

# Create a shared global GPS instance for the application.
global_gps = GPS()

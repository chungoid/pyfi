import gpsd
import time
import threading
import logging
import os
from utils.helpers import run_suppressed_cmd  # Your helper to run commands quietly

# Set a more appropriate log level for this module
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Change from DEBUG to INFO

class GPS:
    _instance = None  # Singleton instance
    
    def __init__(self, host="127.0.0.1", port=2947):
        # Initialize variables but don't connect yet
        self.host = host
        self.port = port
        self.last_fix = None         # Cache for the last known valid fix (lat, lon)
        self.running = False         # Flag to control the background thread, initially False
        self.update_thread = None    # Will be initialized when start() is called
        self.verbose_logging = False
        self.consecutive_failures = 0
        self.max_logged_failures = 3
        self._connected = False      # Track if we've tried to connect
        self._gpsd_available = self._check_gpsd_available()

    def _check_gpsd_available(self):
        """Check if gpsd service is available on the system"""
        try:
            # Quick check if gpsd is installed
            result = run_suppressed_cmd("which gpsd", capture_output=True)
            return bool(result and not result.startswith("which: no gpsd"))
        except Exception as e:
            logger.warning(f"GPS service check failed: {e}")
            return False

    @classmethod
    def get_instance(cls, host="127.0.0.1", port=2947):
        """Get or create the GPS singleton instance"""
        if cls._instance is None:
            cls._instance = GPS(host, port)
        return cls._instance

    def start(self):
        """Start the GPS service and background thread only when needed"""
        if self.running:
            logger.info("GPS service already running")
            return True
            
        if not self._gpsd_available:
            logger.warning("GPS service (gpsd) not available on this system")
            return False
            
        # Connect to gpsd
        if not self.connect():
            return False
        
        # Start the background thread
        self.running = True
        self.update_thread = threading.Thread(target=self._update_fix, daemon=True)
        self.update_thread.start()
        logger.info("GPS service started")
        return True
        
    def connect(self):
        """
        Connect to gpsd using the provided host and port.
        Returns True if connection was successful, False otherwise.
        """
        if self._connected:
            return True  # Already connected
            
        if not self._gpsd_available:
            logger.warning("Cannot connect to GPS: gpsd not available")
            return False
            
        try:
            gpsd.connect(host=self.host, port=self.port)
            logger.info("Connected to gpsd at %s:%s", self.host, self.port)
            self._connected = True
            return True
        except Exception as e:
            logger.error("Failed to connect to gpsd: %s", e)
            self._connected = False  # Mark as attempted but failed
            return False

    def _update_fix(self, poll_timeout=10, update_interval=5):
        """
        Background thread that continuously polls for a GPS fix.
        On success, the fix (tuple of latitude and longitude) is cached in self.last_fix.
        """
        while self.running:
            try:
                fix = self._get_fix(timeout=poll_timeout)
                self.last_fix = fix
                # Only log if verbose or if recovering from failures
                if self.verbose_logging or self.consecutive_failures > 0:
                    logger.debug("Cached new GPS fix: %s", fix)
                self.consecutive_failures = 0  # Reset failure counter on success
            except Exception as e:
                self.consecutive_failures += 1
                # Only log first few consecutive failures to prevent log spam
                if self.consecutive_failures <= self.max_logged_failures:
                    logger.warning("Failed to update GPS fix: %s", e)
                elif self.consecutive_failures % 10 == 0:
                    # Log occasional updates for persistent failures
                    logger.warning("Still failing to get GPS fix after %d consecutive attempts", 
                                 self.consecutive_failures)
            time.sleep(update_interval)

    def _get_fix(self, timeout=10):
        """
        Blocking call to get the current GPS fix as a tuple (latitude, longitude).
        Waits until a valid 2D fix is acquired or raises an exception if the timeout is reached.
        """
        if not self._connected:
            if not self.connect():
                raise RuntimeError("Cannot get GPS fix: not connected to gpsd")
                
        start_time = time.time()
        while True:
            try:
                packet = gpsd.get_current()
                position = packet.position()  # Raises NoFixError if no fix is available
                # Don't log every position acquisition
                if self.verbose_logging:
                    logger.debug("Acquired GPS position: %s", position)
                return position
            except gpsd.NoFixError:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    raise gpsd.NoFixError(f"Timeout reached: No 2D fix available after {timeout} seconds.")
                # Don't log wait messages, they flood the logs
                time.sleep(1)

    def reset_gpsd(self):
        """
        Resets gpsd by stopping its service, removing stale socket and lock files,
        and then restarting the service.
        Returns True if successful, False otherwise.
        """
        if not self._gpsd_available:
            logger.warning("Cannot reset GPS: gpsd not available")
            return False
            
        commands = [
            "sudo systemctl stop gpsd",
            "sudo rm -f /var/run/gpsd.sock",
            "sudo rm -f /var/lock/gpsd.lock",
            "sudo systemctl start gpsd"
        ]
        
        success = True
        for cmd in commands:
            logger.info("Executing GPS reset: %s", cmd)
            try:
                output = run_suppressed_cmd(cmd, capture_output=True)
                if self.verbose_logging:
                    logger.debug("Executed: %s, output: %s", cmd, output)
            except Exception as e:
                logger.error("GPS reset command failed: %s - %s", cmd, e)
                success = False
                
        time.sleep(2)  # Allow time for gpsd to restart and create its socket
        
        # Try to reconnect after reset
        self._connected = False  # Force reconnection attempt
        if not self.connect():
            success = False
            
        if os.path.exists("/var/run/gpsd.sock") or os.path.exists("/run/gpsd.sock"):
            logger.info("gpsd socket file exists, reset successful.")
        else:
            logger.error("gpsd socket file not found after reset.")
            success = False
            
        return success

    def get_position_with_auto_reset(self, attempt_timeout=60, max_attempts=3):
        """
        Attempts to retrieve a GPS fix, resetting gpsd if necessary.
        Returns a tuple (latitude, longitude) or None if unsuccessful.
        """
        if not self._gpsd_available:
            logger.warning("Cannot get GPS position: gpsd not available")
            return None
            
        if not self.running:
            if not self.start():  # Make sure we're connected before attempting
                return None
            
        attempts = 0
        while attempts < max_attempts:
            try:
                return self._get_fix(timeout=attempt_timeout)
            except Exception as e:
                attempts += 1
                logger.info("Attempt %d of %d failed to get a fix: %s", 
                           attempts, max_attempts, e)
                if attempts < max_attempts:
                    self.reset_gpsd()
                    
        logger.error("Failed to get GPS fix after %d attempts", max_attempts)
        return None

    def stop(self):
        """
        Stops the background update thread.
        """
        if not self.running:
            return
            
        self.running = False
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=1.0)  # Give it time to terminate
            logger.info("GPS service stopped")
        
    def set_verbose_logging(self, verbose=False):
        """
        Set whether to use verbose logging for GPS updates.
        """
        self.verbose_logging = verbose
        logger.info("GPS verbose logging set to: %s", verbose)

    def get_current_position(self):
        """
        Get the current GPS position (lat, lon).
        Will start the GPS service if not running and GPS is available.
        Returns a tuple (latitude, longitude) or None if unavailable.
        """
        if not self._gpsd_available:
            return None
            
        if not self.running:
            if not self.start():  # Start GPS service if not running
                return None
            
        if self.last_fix:
            return self.last_fix
        else:
            try:
                return self._get_fix(timeout=5)  # Try to get a quick fix
            except Exception as e:
                logger.warning(f"Unable to get GPS position: {e}")
                return None

    def is_available(self):
        """
        Check if GPS functionality is available on this system.
        """
        return self._gpsd_available

# Create a placeholder for the global GPS instance
# It will only be initialized when explicitly requested
global_gps = None

def get_gps():
    """
    Get the global GPS instance, initializing it if necessary.
    This is the primary way to access GPS functionality from other modules.
    """
    global global_gps
    if global_gps is None:
        global_gps = GPS.get_instance()
    return global_gps

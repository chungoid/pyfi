import logging


def setup_logging():
    # Remove any existing handlers from the root logger
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Configure the root logger for general app logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="pyfi.log",  # Log file name in your working directory
        filemode="w"  # Overwrite log file on each run; use "a" to append
    )
    logging.debug("Logging has been configured.")
    
    # Set specific log levels for noisy modules
    logging.getLogger("utils.gps").setLevel(logging.INFO)
    logging.getLogger("gpsd").setLevel(logging.WARNING)
    
    # You can add more modules that need custom log levels here
    # Example: logging.getLogger("noisy_module").setLevel(logging.WARNING)


if __name__ == "__main__":
    setup_logging()
    logging.info("This is an info message to test logging output.")
    logging.debug("This is a debug message.")

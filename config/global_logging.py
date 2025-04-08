import logging


def setup_logging():
    # Remove any existing handlers from the root logger
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="pyfi.log",  # Log file name in your working directory
        filemode="w"  # Overwrite log file on each run; use "a" to append
    )
    logging.debug("Logging has been configured.")


if __name__ == "__main__":
    setup_logging()
    logging.info("This is an info message to test logging output.")
    logging.debug("This is a debug message.")

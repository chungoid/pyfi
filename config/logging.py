import logging

def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="pyfi.log",  # Log file name in your working directory
        filemode="w"          # Overwrite log file on each run; use "a" to append
    )

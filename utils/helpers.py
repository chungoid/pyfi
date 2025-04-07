def run_suppressed_cmd(command: str, capture_output: bool = True) -> str:
    """
    Run a CLI command in the background and return its output.

    If capture_output is True, stdout and stderr are captured and returned.
    Otherwise, both stdout and stderr are redirected to DEVNULL, and an empty string is returned.
    """
    import subprocess
    from concurrent.futures import ThreadPoolExecutor
    _executor = ThreadPoolExecutor(max_workers=5)

    if capture_output:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True
        )
        return result.stdout.strip() or result.stderr.strip()
    else:
        subprocess.run(
            command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return ""

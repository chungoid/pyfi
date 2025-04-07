import os
import requests


def download_from_wpasec(tool, api_key: str, results_dir: str) -> str | None:
    """
    Downloads data from WPA-sec using the provided API key and saves it as 'founds.txt'
    in the specified results' directory.
    """
    url = "https://wpa-sec.stanev.org/?api&dl=1"
    headers = {"Cookie": f"key={api_key}"}
    tool.logger.debug("Downloading founds from WPA-sec...")

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises an exception for 4xx/5xx responses.

        # Ensure the results directory exists.
        os.makedirs(results_dir, exist_ok=True)
        founds_path = os.path.join(results_dir, "founds.txt")

        with open(founds_path, "w") as f:
            f.write(response.text)

        tool.logger.info(f"Downloaded founds and saved to {founds_path}")
        return founds_path
    except Exception as e:
        tool.logger.exception(f"Error downloading from WPA-sec: {e}")
        return None
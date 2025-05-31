import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
import urllib.parse


class VoIPService:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        # e.g. "voip.example.com"
        self.server = self.config.get("server_url", "").lstrip("https://")
        self.apikey = self.config.get("apikey", "")
        self.base_url = f"https://{self.server}/ns-api/v2"
        self.key_info: Dict[str, Any] = {}

    def validate_key(self) -> None:
        """Checks the key info endpoint and scope."""
        url = f"{self.base_url}/apikeys/~"
        headers = {"Authorization": f"Bearer {self.apikey}"}
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            raise ValueError("Invalid API key")
        info = resp.json()
        if info.get("scope") != "Office Manager":
            raise PermissionError("Key must have Office Manager scope")
        self.key_info = info

    def fetch_calls(self) -> List[Dict[str, Any]]:
        """Fetches all calls from (now-3mo) to (now-8h) with pagination."""
        now = datetime.now(timezone.utc)
        datetimestart = urllib.parse.quote((now - timedelta(days=90)).isoformat())
        datetimeend = urllib.parse.quote((now - timedelta(hours=8)).isoformat())

        url = f"{self.base_url}/cdrs?datetime-start={datetimestart}&datetime-end={datetimeend}"
        headers = {"Authorization": f"Bearer {self.apikey}"}
        params = {
            "start": 0,
            "limit": 1000,
        }

        all_calls: List[Dict[str, Any]] = []
        while True:
            # concactonate the start and limit onto the URL
            r = requests.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
            all_calls.extend(data["items"])
            if not data:
                break
            params["start"] += params["limit"]
        return all_calls

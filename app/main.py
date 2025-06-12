import requests
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


class VoIPService:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        # e.g. "voip.example.com"
        self.server = self.config.get("server_url", "").lstrip("https://")
        self.apikey = self.config.get("apikey", "")
        self.base_url = f"https://{self.server}/ns-api/v2"
        self.key_info: Dict[str, Any] = {}
        self.base_data_dir = Path(self.config.get("data_directory", ""))

    def _get_date_path(self, iso_timestamp: str) -> Path:
        """
        Given an ISO8601 timestamp (e.g. "2025-05-30T21:19:16+00:00"),
        create/return a Path like base_data_dir/YYYY/MM/DD.
        """
        dt = datetime.fromisoformat(iso_timestamp)
        folder = (
            self.base_data_dir / f"{dt.year:04d}" / f"{dt.month:02d}" / f"{dt.day:02d}"
        )
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def validate_key(self) -> None:
        url = f"{self.base_url}/apikeys/~"
        headers = {"Authorization": f"Bearer {self.apikey}"}
        try:
            resp = requests.get(url, headers=headers, timeout=(5, 30))
            resp.raise_for_status()
        except requests.exceptions.ConnectTimeout as e:
            raise RuntimeError("Network timeout while validating API key") from e
        info = resp.json()
        if info.get("user-scope") != "Office Manager":
            scope = info.get("user-scope")
            raise PermissionError(f"API key needs Office Manager scope: {scope}")
        self.key_info = info

    def fetch_calls(self) -> List[Dict[str, Any]]:
        """Fetches all calls from (now-3mo) to (now-8h) with pagination."""
        # Compute time window
        now = datetime.now(timezone.utc)
        datetime_end = (now - timedelta(hours=8)).isoformat().replace("+00:00", "Z")
        datetime_start = (now - timedelta(days=90)).isoformat().replace("+00:00", "Z")

        # Base URL without pagination
        base_url = f"{self.base_url}/domains/~/cdrs?datetime-start={datetime_start}&datetime-end={datetime_end}"

        headers = {"Authorization": f"Bearer {self.apikey}"}
        all_calls: List[Dict[str, Any]] = []

        # Pagination variables
        start = 0
        limit = 1000

        while True:
            # 4) Construct the paginated URL
            paged_url = f"{base_url}&start={start}&limit={limit}"

            r = requests.get(paged_url, headers=headers)
            r.raise_for_status()
            data = r.json()

            items = data
            if not items:
                # No more call records
                break

            all_calls.extend(items)

            # 5) If fewer items than 'limit' were returned, we've reached the last page
            if len(items) < limit:
                break

            # Otherwise, advance to the next page
            start += limit

        return all_calls

    def save_call_metadata(self, call: Dict[str, Any]) -> None:
        """
        Saves the full call record dict to a JSON file in its date folder.
        Filename: {call_id}_meta.json
        """
        # 1) Extract the timestamp and ID
        timestamp = call.get("call-start-datetime")
        if not timestamp:
            raise KeyError("Missing 'call-start-datetime' in call record")
        call_id = (
            call.get("id")
            or call.get("call-orig-call-id")
            or call.get("call-term-call-id")
            or call.get("call-through-call-id")
            or call.get("call-parent-cdr-id")
            or "<unknown>"
        )
        directions = {
            "0": "out",
            "1": "in",
            "2": "missed",
            "3": "local",
            "4": "unknown",
        }
        src_element_list = {
            "0": "",
            "1": "",
            "2": "",
            "3": "",
            "4": "unknown"
        }

        direction = call.get("call-direction") or "4"

        call_direction = directions.get(direction)
        timestamp_list = re.split(r'T|\+', call.get("call-start-datetime"))
        timestamp = timestamp_list[1].replace(":", "-")
        # build source element selector
        src_element = 

        # build dst element selector
        # build src / dst element identifier
        # 2) Find (and create) the YYYY/MM/DD folder
        folder = self._get_date_path(timestamp)

        # 3) Build the metadata filepath
        meta_file = folder / f"{timestamp}_{call_direction}_{call_id}_meta.json"

        # 4) Write the JSON
        try:
            with meta_file.open("w", encoding="utf-8") as f:
                json.dump(call, f, indent=2)
        except Exception as e:
            # let the caller handle/log exceptions if needed
            raise RuntimeError(f"Failed to save metadata for call {call_id}") from e

import json
import requests
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class VoIPService:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.token: Optional[str] = None

    def authenticate(self) -> None:
        # TODO: Replace with real OAuth2 flow
        self.token = "my_oauth_token"
        print("Authenticated with token:", self.token)

    def fetch_call_history(self) -> List[Dict[str, Any]]:
        """
        Stub: Replace with an API call that returns a list of call records,
        each including at least:
          - an 'id' field (string)
          - a 'timestamp' field (ISO8601 string)
          - optionally 'recording_url' and 'transcription' fields
        """
        # Example response:
        return [
            {
                "id": "call123",
                "timestamp": "2025-05-30T14:23:05Z",
                "recording_url": "https://api.voip.com/recordings/call123.wav",
                "transcription": "Hello, world!",
            },
            # … more records …
        ]

    def _get_date_path(self, timestamp: str) -> Path:
        """
        Given an ISO8601 timestamp, return a path like:
            {data_dir}/YYYY/MM/DD
        """
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        base = Path(self.config["data_directory"])
        # e.g. /path/to/data/2025/05/30
        return base / f"{dt.year:04d}" / f"{dt.month:02d}" / f"{dt.day:02d}"

    def _save_metadata(self, record: Dict[str, Any], dest: Path) -> None:
        """
        Write out metadata for a single call as JSON.
        """
        meta_file = dest / f"{record['id']}_meta.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        print(f"→ Saved metadata: {meta_file}")

    def _download_recording(self, url: str, dest: Path) -> None:
        """
        Download a .wav file and save it to dest.
        """
        r = requests.get(url, stream=True)
        r.raise_for_status()
        wav_path = dest / Path(url).name
        with open(wav_path, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
        print(f"→ Downloaded recording: {wav_path}")

    def process_history(self) -> None:
        """
        Fetches all call records and saves them into a date-based folder
        with metadata and recordings.
        """
        if not self.token:
            raise RuntimeError("Not authenticated")

        calls = self.fetch_call_history()
        for rec in calls:
            date_folder = self._get_date_path(rec["timestamp"])
            # Create directories if they don't exist
            date_folder.mkdir(parents=True, exist_ok=True)  #

            # Save metadata
            self._save_metadata(rec, date_folder)

            # Download recording if present
            if rec.get("recording_url"):
                try:
                    self._download_recording(rec["recording_url"], date_folder)
                except Exception as e:
                    print(f"⚠️ Failed to download {rec['recording_url']}: {e}")

    def run(self) -> None:
        self.authenticate()
        self.process_history()

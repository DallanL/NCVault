import requests
import json
from pathlib import Path
from urllib.parse import quote
from datetime import datetime, timedelta, timezone, date
from typing import Any, Dict, List, Optional
import re
import logging


class VoIPService:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        # e.g. "voip.example.com"
        self.server = self.config.get("server_url", "").lstrip("https://")
        self.apikey = self.config.get("apikey", "")
        self.base_url = f"https://{self.server}/ns-api/v2"
        self.key_info: Dict[str, Any] = {}
        self.base_data_dir = Path(self.config.get("data_directory", ""))

    def _generate_call_filename(
        self, call: Dict[str, Any], label: str, extension: str = "json"
    ) -> str:
        """
        Build a filename for this call dict, e.g.
        "15-20-53_out_1234_meta.json" or
        "15-20-53_in_103_to_5622970000_meta.json"
        """
        # --- extract timestamp ---
        dt_str = call.get("call-start-datetime")
        if not dt_str:
            raise KeyError("Missing 'call-start-datetime' in call record")
        # parse and reformat time
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone()
        timestamp = local_dt.strftime("%H-%M-%S")

        # --- call ID fallback chain ---
        call_id = (
            call.get("id")
            or call.get("call-orig-call-id")
            or call.get("call-term-call-id")
            or call.get("call-through-call-id")
            or call.get("call-parent-cdr-id")
            or "<unknown>"
        )

        # --- direction mapping ---
        directions = {
            "0": "out",
            "1": "in",
            "2": "missed",
            "3": "local",
            "4": "unknown",
        }
        direction_key = str(call.get("call-direction", "4"))
        call_dir = directions.get(direction_key, "unknown")

        # --- src/dst mapping ---
        src_map = {
            "0": "call-orig-user",
            "1": "call-orig-from-uri",
            "2": "call-orig-from-uri",
            "3": "call-orig-user",
            "4": None,
        }
        dst_map = {
            "0": "call-orig-to-user",
            "1": "call-term-user",
            "2": "call-term-user",
            "3": "call-term-user",
            "4": None,
        }

        if direction_key in ("1", "2"):  # incoming or missed since they have uri format
            raw = call.get(src_map[direction_key], "sip:unknown@unknown")
            user = re.split(r":|@", raw)[1]
            src = re.sub(r"[^a-zA-Z0-9]", "", user)
        elif src_map[direction_key]:
            src = call.get(src_map[direction_key], "unknown")
        else:
            src = None

        dst = call.get(dst_map[direction_key]) if dst_map[direction_key] else None

        # --- build the filename body ---
        if call_dir == "unknown":
            body = f"{timestamp}_{call_dir}_{call_id}"
        else:
            body = f"{timestamp}_{call_dir}_{src}_to_{dst}"

        return f"{body}_{label}.{extension}"

    def _get_date_path(self, iso_timestamp: str) -> Path:
        """
        Given an ISO8601 timestamp (e.g. "2025-05-30T21:19:16+00:00"),
        create/return a Path like base_data_dir/YYYY/MM/DD.
        """
        dt = datetime.fromisoformat(iso_timestamp)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone()
        folder = (
            self.base_data_dir
            / f"{local_dt.year:04d}"
            / f"{local_dt.month:02d}"
            / f"{local_dt.day:02d}"
        )
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def _get_last_saved_date(self) -> Optional[date]:
        """
        Scans self.data_root/YYYY/MM/DD folders and returns the most
        recent date for which we already have saved calls.
        """
        dates: List[date] = []
        # look for folders matching data_root/<year>/<month>/<day>
        for day_path in self.base_data_dir.glob("*/ */ *"):
            try:
                y, m, d = (int(part) for part in day_path.parts[-3:])
                dates.append(date(y, m, d))
            except Exception:
                continue
        return max(dates) if dates else None

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
        """
        Fetches all calls from either:
          • the most recent saved day forward, or
          • the past 3 months (if no saved data)
        up to (now - 8h), using pagination.
        """
        now = datetime.now(timezone.utc)
        end_ts = (now - timedelta(hours=8)).isoformat().replace("+00:00", "Z")

        last_saved = self._get_last_saved_date()
        if last_saved:
            # start at midnight UTC of the day after last_saved
            start_dt = datetime.combine(
                last_saved, datetime.min.time(), tzinfo=timezone.utc
            )
        else:
            # default to 90 days ago
            start_dt = now - timedelta(days=90)

        start_ts = start_dt.isoformat().replace("+00:00", "Z")

        base_url = (
            f"{self.base_url}/domains/~/cdrs"
            f"?datetime-start={start_ts}"
            f"&datetime-end={end_ts}"
            f"&raw=yes"
        )
        headers = {"Authorization": f"Bearer {self.apikey}"}
        all_calls: List[Dict[str, Any]] = []

        start = 0
        limit = 1000

        while True:
            paged_url = f"{base_url}&start={start}&limit={limit}"
            r = requests.get(paged_url, headers=headers)
            r.raise_for_status()
            items = r.json()
            if not items:
                break
            all_calls.extend(items)
            if len(items) < limit:
                break
            start += limit

        return all_calls

    def save_call_transcript(self, call: Dict[str, Any]) -> None:
        id = (
            call.get("id")
            or call.get("call-orig-call-id")
            or call.get("call-term-call-id")
            or call.get("call-through-call-id")
            or call.get("call-parent-cdr-id")
            or "<unknown>"
        )
        logging.info(f"saving transcript for {id}")
        prefilled_url = call.get("prefilled-transcription-api")
        if prefilled_url == "None" or prefilled_url is None:
            logging.info("Empty transcript url")
            return
        transcript_url = f"https://{self.server}{prefilled_url}"
        logging.info(f"transcript url: {transcript_url}")
        headers = {"Authorization": f"Bearer {self.apikey}"}
        response = requests.get(transcript_url, headers=headers)
        if response.status_code == 200:
            dt_str = call.get("call-start-datetime") or "unknown"
            folder: Path = self._get_date_path(dt_str)
            filename = self._generate_call_filename(call, label="transcript")
            transcript_file = folder / filename
            data = json.loads(response.text)
            try:
                with transcript_file.open("w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                raise RuntimeError(f"Failed to save transcript for call {id}") from e

            return
        else:
            logging.info(f"Response code {response.status_code} for call: {id}")
            return

    def save_call_recording(self, call: Dict[str, Any]) -> None:
        id = str(call.get("call-orig-call-id")) or None
        if id is None:
            return

        logging.info(f"saving recording for {id}")
        dt_str = call.get("call-start-datetime") or "unknown"
        folder: Path = self._get_date_path(dt_str)
        filename = self._generate_call_filename(
            call, label="recording", extension="wav"
        )
        recording_file = folder / filename
        encoded_id = quote(id, safe="")
        recording_url = f"{self.base_url}/domains/~/recordings/{encoded_id}"
        headers = {"Authorization": f"Bearer {self.apikey}"}
        response = requests.get(recording_url, headers=headers)
        response_json = json.loads(response.text)
        if response.status_code == 200 and response_json.get(
            "call-recording-status"
        ) == ("converted" or "archived"):
            download_url = response_json.get("file-access-url")
            try:
                with requests.get(download_url, headers=headers, stream=True) as r:
                    r.raise_for_status()
                    with open(recording_file, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
            except Exception as e:
                raise RuntimeError(
                    f"Failed to save call recording for call {id}"
                ) from e
        else:
            logging.info(
                f"Failed to get download link for callid: {id}\nResponse code: {response.status_code}\nRecording Status: {response_json.get('call-recording-status')}"
            )

        return

    def save_call_metadata(self, call: Dict[str, Any]) -> None:
        """
        Saves the full call record dict to a JSON file in its date folder.
        """
        dt_str = call.get("call-start-datetime") or "unknown"
        # get (and create) the YYYY/MM/DD folder
        folder: Path = self._get_date_path(dt_str)
        filename = self._generate_call_filename(call, label="meta")
        meta_file = folder / filename

        # write JSON meta data
        try:
            with meta_file.open("w", encoding="utf-8") as f:
                json.dump(call, f, indent=2)
        except Exception as e:
            raise RuntimeError(
                f"Failed to save metadata for call {call.get('id')}"
            ) from e

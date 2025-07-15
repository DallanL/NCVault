import requests
import json
from pathlib import Path
from urllib.parse import quote
from datetime import datetime, timedelta, timezone, date
from typing import Any, Dict, List, Optional
import re
import logging
from dataclasses import dataclass


@dataclass
class VoIPServiceConfig:
    server_url: str
    apikey: str
    data_directory: str


class VoIPService:
    def __init__(self, config: VoIPServiceConfig) -> None:
        self.config = config
        # e.g. "voip.example.com"
        self.server = self.config.server_url.lstrip("https://")
        self.apikey = self.config.apikey
        self.base_url = f"https://{self.server}/ns-api/v2"
        self.key_info: Dict[str, Any] = {}
        self.base_data_dir = Path(self.config.data_directory)

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

        rawdst = call.get(dst_map[direction_key]) if dst_map[direction_key] else None
        strrawdst = str(rawdst)
        if strrawdst:
            dst = re.sub(r"[^a-zA-Z0-9]", "", strrawdst)
        else:
            dst = None

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
        # look for folders matching data_dir/<year>/<month>/<day>
        for day_path in self.base_data_dir.glob("*/*/*"):
            if not day_path.is_dir():
                continue
            try:
                y, m, d = map(int, day_path.parts[-3:])
                dates.append(date(y, m, d))
            except ValueError as e:
                logging.debug(f"Skipping non-date folder {day_path}: {e}")
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

    def fetch_calls(
        self,
        start_dt: Optional[datetime] = None,
        end_dt: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetches calls within a specified datetime range, using pagination.
        If start_dt and end_dt are not provided, it fetches from the most
        recent saved day forward, or the past 3 months (if no saved data)
        up to now.
        """
        if start_dt is None or end_dt is None:
            now = datetime.now(timezone.utc)
            end_dt = now
            logging.debug("Checking last saved record")
            last_saved = self._get_last_saved_date()
            if last_saved:
                # start at midnight UTC of the day after last_saved
                start_dt = datetime.combine(
                    last_saved, datetime.min.time(), tzinfo=timezone.utc
                )
                logging.info(
                    f"Found previous records, setting start date to {start_dt}"
                )
            else:
                # default to 90 days ago
                start_dt = now - timedelta(days=90)
                logging.info(
                    f"Found no previous records, setting start date to {start_dt}"
                )

        start_ts = start_dt.isoformat().replace("+00:00", "Z")
        end_ts = end_dt.isoformat().replace("+00:00", "Z")

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
        """
        Attempt to save a call recording by iterating over possible call-ID fields.
        """
        headers = {"Authorization": f"Bearer {self.apikey}"}
        dt_str = call.get("call-start-datetime", "unknown")
        folder: Path = self._get_date_path(dt_str)
        filename = self._generate_call_filename(
            call, label="recording", extension="wav"
        )
        recording_file = folder / filename

        # List of fields to try, in priority order
        id_fields = [
            "call-parent-call-id",
            "call-term-call-id",
            "call-orig-call-id",
        ]

        for field in id_fields:
            call_id: Optional[str] = call.get(field)
            if not call_id:
                continue

            logging.info(f"Trying recording for {field} = {call_id}")
            encoded_id = quote(str(call_id), safe="")
            url = f"{self.base_url}/domains/~/recordings/{encoded_id}"
            resp = requests.get(url, headers=headers)

            # If not found, try next ID
            if resp.status_code == 404:
                logging.info(f"No recording at {field} ({call_id}); trying next ID")
                continue

            # Parse JSON and validate recording status
            data = resp.json()
            status = data.get("call-recording-status")
            if resp.status_code == 200 and status in ("converted", "archived"):
                download_url = data.get("file-access-url")
                if not download_url:
                    logging.info(f"No download URL in response for {call_id}")
                    continue

                # Stream download to file
                try:
                    with requests.get(download_url, headers=headers, stream=True) as dl:
                        dl.raise_for_status()
                        with open(recording_file, "wb") as f:
                            for chunk in dl.iter_content(chunk_size=8192):
                                f.write(chunk)
                    logging.info(f"Saved recording: {filename}")
                    return
                except Exception as e:
                    raise RuntimeError(
                        f"Failed to save recording for call {call_id}"
                    ) from e

            logging.info(
                f"Recording not ready for {call_id}: status={resp.status_code}, "
                f"recording-status={status}"
            )

        logging.info("No valid recording found for any call-ID field")

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

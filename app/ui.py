import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
import os
import logging
from app.helpers import validate_and_normalize_domain
from app.config_manager import load_config, save_config, set_apikey
import threading
import time
from app.main import VoIPService, VoIPServiceConfig
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)


class TextHandler(logging.Handler):
    def __init__(self, text_widget: ScrolledText):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record) + "\n"
        # append in the UI thread
        self.text_widget.after(0, self.append, msg)

    def append(self, msg: str):
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, msg)
        self.text_widget.configure(state="disabled")
        self.text_widget.yview(tk.END)


class PlaceholderEntry(tk.Entry):
    """A tkinter Entry widget that displays placeholder text."""

    def __init__(
        self,
        master=None,
        placeholder: str = "Enter text...",
        color: str = "grey",
        **kwargs,
    ) -> None:
        super().__init__(master, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = color
        # Store default foreground color, defaulting to black if not specified
        self.default_fg_color = self.cget("fg")
        if self.default_fg_color == self.placeholder_color or not self.default_fg_color:
            self.default_fg_color = "black"

        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)

        self._put_placeholder()  # Initialize with placeholder

    def _put_placeholder(self) -> None:
        """Adds the placeholder text and color."""
        if self.winfo_exists():
            # Clear existing text only if it's not the placeholder already
            # Prevents unnecessary delete/insert if focus out leaves it empty
            current_text = super().get()
            if current_text != self.placeholder:
                self.delete(0, tk.END)
                self.insert(0, self.placeholder)
            self.config(fg=self.placeholder_color)

    def _on_focus_in(self, event) -> None:
        """Removes placeholder text on focus."""
        _ = event
        if self.winfo_exists() and super().get() == self.placeholder:
            self.delete(0, tk.END)
            self.config(fg=self.default_fg_color)

    def _on_focus_out(self, event) -> None:
        """Adds placeholder if the entry is empty."""
        _ = event
        # Check value after stripping whitespace
        if self.winfo_exists() and not super().get().strip():
            self._put_placeholder()

    def get_value(self) -> str:
        """Returns the entry's value, or an empty string if it contains the placeholder."""
        if not self.winfo_exists():
            return ""
        val = super().get()
        if val == self.placeholder:
            return ""
        return val  # Return the actual value, stripping can be done by caller if needed

    def set_value(self, text: str) -> None:
        """Sets the entry's text, removing placeholder state."""
        if not self.winfo_exists():
            return
        self.delete(0, tk.END)
        self.insert(0, text)
        self.config(fg=self.default_fg_color)
        # If text is empty, trigger focus out to potentially show placeholder
        if not text:
            self._on_focus_out(None)


# --- Main Configuration UI ---
class ConfigUI:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("NCVault")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start Sync button
        self.start_button = tk.Button(
            master, text="Start Sync", command=self.start_sync
        )
        self.start_button.grid(row=3, column=2, padx=5, pady=10)

        # Stop button
        self.stop_event = threading.Event()
        self.stop_button = tk.Button(
            master, text="Stop Sync", command=self.stop_sync, state=tk.DISABLED
        )
        self.stop_button.grid(row=3, column=3, padx=5, pady=10)

        # scrollable log window
        self.log_window = ScrolledText(master, state="disabled", height=10)
        self.log_window.grid(
            row=5, column=0, columnspan=4, padx=5, pady=(10, 5), sticky="nsew"
        )
        master.grid_rowconfigure(5, weight=1)
        master.grid_columnconfigure(1, weight=1)
        text_handler = TextHandler(self.log_window)
        text_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        log.addHandler(text_handler)

        # load existing JSON (or empty dict)
        self.config_data = load_config() or {}
        self.todays_records = []
        self.pending_calls = []

        # --- UI Elements ---
        tk.Label(master, text="Server URL:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_url = PlaceholderEntry(
            master, placeholder="voip.example.com", width=75
        )
        self.entry_url.grid(row=0, column=1, padx=5, pady=5)
        if url := self.config_data.get("server_url"):
            self.entry_url.set_value(url)

        tk.Label(master, text="API Key:").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_apikey = PlaceholderEntry(
            master, placeholder="nsd-erfwu4432hjkl......", width=75
        )
        self.entry_apikey.grid(row=1, column=1, padx=5, pady=5)
        if apikey := self.config_data.get("apikey"):
            self.entry_apikey.set_value(apikey)

        tk.Label(master, text="Data Directory:").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_directory = PlaceholderEntry(
            master, placeholder="Select directory for storing data", width=65
        )
        self.entry_directory.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W + tk.E)
        if dd := self.config_data.get("data_directory"):
            self.entry_directory.set_value(dd)

        self.browse_button = tk.Button(
            master, text="Browse...", command=self.browse_directory
        )
        self.browse_button.grid(row=2, column=2, padx=5, pady=5)

        self.save_button = tk.Button(
            master, text="Save Configuration", command=self.save_configuration
        )
        self.save_button.grid(row=3, column=1, pady=10)

        tk.Label(master, text="Sync Interval (minutes):").grid(
            row=4, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_interval = PlaceholderEntry(master, placeholder="5", width=10)
        self.entry_interval.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        sync_interval_value = self.config_data.get("sync_interval", "5")
        self.entry_interval.set_value(str(sync_interval_value))

        self.status_label = tk.Label(master, text="", fg="green")
        self.status_label.grid(row=4, column=0, columnspan=3, pady=5)

        self.progress_bar = ttk.Progressbar(
            master, orient="horizontal", length=400, mode="determinate"
        )
        self.progress_bar.grid(
            row=6, column=0, columnspan=4, padx=5, pady=5, sticky="ew"
        )

        for entry in (self.entry_url, self.entry_apikey, self.entry_directory):
            entry.bind(
                "<KeyRelease>",
                lambda _: self.save_button.config(
                    state=tk.NORMAL, text="Save Configuration"
                ),
            )

    def _set_ui_state(self, enabled: bool) -> None:
        """Enables or disables the UI widgets."""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.entry_url.config(state=state)
        self.entry_apikey.config(state=state)
        self.entry_directory.config(state=state)
        self.browse_button.config(state=state)
        self.save_button.config(state=state)
        self.start_button.config(state=state)

    def start_sync(self) -> None:
        valid, cfg = self.validate_data()
        if not valid:
            return

        # Prepare cancellation event
        self.stop_event.clear()

        # Disable Start, enable Stop
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.update_status("Syncing…", "blue")
        self._set_ui_state(False)

        # Launch background thread
        t = threading.Thread(
            target=self._sync_orchestrator, args=(cfg, self.stop_event), daemon=True
        )
        t.start()

    def stop_sync(self) -> None:
        # Signal the thread to stop
        self.stop_event.set()
        self.update_status("Stopping…", "orange")

    def _perform_initial_sync(
        self, svc: VoIPService, stop_event: threading.Event
    ) -> None:
        self.update_status("Fetching historical call data...", "blue")
        calls = svc.fetch_calls()
        self.update_status(f"Processing {len(calls)} historical calls...", "blue")
        log.info(f"Fetched {len(calls)} historical calls.")
        calls.reverse()  # Process in reverse order
        self._process_calls(svc, calls, stop_event, len(calls))
        self.update_status("Initial sync complete.", "green")
        log.info("Initial sync complete.")

    def _perform_periodic_sync(
        self, svc: VoIPService, sync_interval_minutes: int, stop_event: threading.Event
    ) -> None:
        while not stop_event.is_set():
            self.master.after(
                0, lambda: self.progress_bar.config(value=0)
            )  # Reset progress bar
            self.update_status("Starting periodic sync...", "blue")
            log.info("Starting periodic sync...")
            # Process pending calls first
            if self.pending_calls:
                self.update_status(
                    f"Attempting to process {len(self.pending_calls)} pending calls.",
                    "blue",
                )
                log.info(
                    f"Attempting to process {len(self.pending_calls)} pending calls."
                )
                calls_to_retry = list(self.pending_calls)
                self.pending_calls.clear()
                self._process_calls(
                    svc, calls_to_retry, stop_event, len(calls_to_retry)
                )

            # Fetch new calls since the last check
            now = datetime.now(timezone.utc)
            # Fetch calls from the last `sync_interval_minutes`
            # Add a small buffer (e.g., 1 minute) to ensure no calls are missed due to timing
            start_time_for_new_calls = now - timedelta(
                minutes=sync_interval_minutes + 1
            )
            new_calls = svc.fetch_calls(start_dt=start_time_for_new_calls, end_dt=now)

            # Filter out calls already processed today
            new_calls_to_process = []
            processed_call_ids = {call.get("id") for call in self.todays_records}
            for call in new_calls:
                if call.get("id") not in processed_call_ids:
                    new_calls_to_process.append(call)

            if new_calls_to_process:
                self.update_status(
                    f"Found {len(new_calls_to_process)} new calls to process.", "blue"
                )
                log.info(f"Found {len(new_calls_to_process)} new calls to process.")
                new_calls_to_process.reverse()  # Process in reverse order
                self._process_calls(
                    svc, new_calls_to_process, stop_event, len(new_calls_to_process)
                )
            else:
                self.update_status("No new calls found.", "green")
                log.info("No new calls found.")

            if not stop_event.is_set():
                total_seconds = sync_interval_minutes * 60
                self.master.after(
                    0,
                    lambda: self.progress_bar.config(
                        maximum=total_seconds, value=total_seconds
                    ),
                )
                for remaining_seconds in range(total_seconds, 0, -1):
                    if stop_event.is_set():
                        break
                    minutes = remaining_seconds // 60
                    seconds = remaining_seconds % 60
                    self.master.after(
                        0,
                        lambda m=minutes, s=seconds: self.update_status(
                            f"Periodic sync complete. Next sync in {m:02d}:{s:02d}...",
                            "green",
                        ),
                    )
                    self.master.after(
                        0, lambda v=remaining_seconds: self.progress_bar.config(value=v)
                    )
                    time.sleep(1)  # Use time.sleep for second-by-second updates

                if not stop_event.is_set():
                    self.master.after(
                        0, lambda: self.progress_bar.config(value=0)
                    )  # Reset after countdown
                log.info(
                    f"Periodic sync complete. Waiting for {sync_interval_minutes} minutes..."
                )
        self.update_status("Periodic sync stopped.", "orange")
        log.info("Periodic sync stopped.")

    def _sync_orchestrator(self, cfg: dict, stop_event: threading.Event) -> None:
        try:
            log.info("🔄 Starting sync orchestrator…")
            service_config = VoIPServiceConfig(
                server_url=cfg["server_url"],
                apikey=cfg["apikey"],
                data_directory=cfg["data_directory"],
            )
            svc = VoIPService(service_config)

            # 1) Validate key
            log.info("Validating API key…")
            svc.validate_key()
            log.info("API key valid.")

            # 2) Perform initial sync
            self._perform_initial_sync(svc, stop_event)

            # Get sync interval for waiting
            sync_interval_minutes = int(cfg.get("sync_interval", 5))

            # 3) Start periodic sync
            self._perform_periodic_sync(svc, sync_interval_minutes, stop_event)

            # 4) Final status
            if stop_event.is_set():
                msg, color = "Sync canceled by user.", "orange"
                log.warning("🛑 Sync was canceled.")
            else:
                msg, color = "✅ Sync complete!", "green"
                log.info("🎉 Sync completed successfully.")

            # Update the status label on the main thread
            self.master.after(0, lambda: self.update_status(msg, color))

        except Exception as e:
            logging.exception("🚨 Sync failed unexpectedly")
            err_msg = f"Error: {e}"
            self.master.after(0, lambda m=err_msg: self.update_status(m, "red"))

        finally:
            # Re-enable Start, disable Stop buttons
            self.master.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            self.master.after(0, lambda: self._set_ui_state(True))

    def _process_calls(
        self,
        svc: VoIPService,
        calls: list,
        stop_event: threading.Event,
        total_calls: int,
    ) -> None:
        for idx, call in enumerate(calls, start=1):
            self.master.after(
                0, lambda: self.progress_bar.config(value=(idx / total_calls) * 100)
            )
            if stop_event.is_set():
                log.warning("⏹ Stop requested; aborting call processing.")
                break

            call_id = call.get("call-parent-cdr-id", "<unknown>")
            log.info(f"[{idx}/{len(calls)}] Processing call ID={call_id}")

            # a) save metadata
            try:
                svc.save_call_metadata(call)
                log.debug(f"✔️ Metadata saved for {call_id}")
            except Exception as e:
                log.error(f"❌ Metadata save failed for {call_id}: {e}", exc_info=True)
                continue  # Skip to next call if metadata save fails

            # b) transcription
            transcript_saved = False
            try:
                if call.get("prefilled-transcription-api"):
                    svc.save_call_transcript(call)
                    log.debug(f"✔️ Transcript saved for {call_id}")
                    transcript_saved = True
                else:
                    log.debug(f"✔️ No Transcript for {call_id}")
                    transcript_saved = (
                        True  # Consider it 'saved' if there's no transcript to fetch
                    )
            except Exception as e:
                log.error(
                    f"❌ Transcript save failed for {call_id}: {e}", exc_info=True
                )

            # c) recording
            recording_saved = False
            try:
                if call.get("prefilled-transcription-api"):
                    svc.save_call_recording(call)
                    log.debug(f"✔️ Call Recording saved for {call_id}")
                    recording_saved = True
                else:
                    log.debug(f"✔️ No Call Recording for {call_id}")
                    recording_saved = (
                        True  # Consider it 'saved' if there's no recording to fetch
                    )
            except Exception as e:
                log.error(
                    f"❌ Call Recording save failed for {call_id}: {e}",
                    exc_info=True,
                )

            if transcript_saved and recording_saved:
                self.todays_records.append(call)
            else:
                self.pending_calls.append(call)
                log.info(f" buffering call {call_id} for retry")

    def browse_directory(self) -> None:
        """Opens a dialog to choose a directory and updates the entry."""
        directory = filedialog.askdirectory(mustexist=True)
        if directory:
            self.entry_directory.set_value(directory)
            self.update_status("", "black")

    def validate_data(self) -> tuple[bool, dict | None]:
        """Validates inputs and returns (isValid, config_dict or None)."""
        server_url_input = self.entry_url.get_value().strip()
        apikey = self.entry_apikey.get_value().strip()
        data_directory = self.entry_directory.get_value().strip()
        sync_interval = self.entry_interval.get_value().strip()
        if not sync_interval:  # If the field is empty (due to placeholder behavior)
            sync_interval = "5"  # Set to default value

        if not server_url_input:
            messagebox.showerror(
                "Validation Error", "Server URL (FQDN) is required.", parent=self.master
            )
            return False, None

        try:
            normalized_domain = validate_and_normalize_domain(server_url_input)
            full_url = f"https://{normalized_domain}"
        except (ValueError, TypeError) as e:
            messagebox.showerror(
                "Validation Error",
                f"Invalid Server URL: {e}\nPlease enter a valid domain name (e.g., voip.example.com).",
                parent=self.master,
            )
            return False, None

        if not apikey:
            messagebox.showerror(
                "Validation Error", "API Key is required.", parent=self.master
            )
            return False, None

        if not data_directory:
            messagebox.showerror(
                "Validation Error", "Data Directory is required.", parent=self.master
            )
            return False, None
        if not os.path.isdir(data_directory):
            messagebox.showerror(
                "Validation Error",
                f"Selected Data Directory does not exist or is not accessible:\n{data_directory}",
                parent=self.master,
            )
            return False, None

        try:
            sync_interval_int = int(sync_interval)
            if sync_interval_int < 5:
                sync_interval_int = 5
                log.info("Sync interval set to minimum of 5 minutes.")
            elif sync_interval_int > 120:
                sync_interval_int = 120
                log.info("Sync interval set to maximum of 120 minutes.")
            sync_interval = str(sync_interval_int)
            self.entry_interval.set_value(sync_interval)
        except ValueError:
            messagebox.showerror(
                "Validation Error",
                "Sync Interval must be a number.",
                parent=self.master,
            )
            return False, None

        self.entry_url.set_value(full_url)

        config = {
            "server_url": full_url,
            "apikey": apikey,
            "data_directory": data_directory,
            "sync_interval": sync_interval,
        }
        return True, config

    def save_configuration(self) -> None:
        self.update_status("", "black")
        is_valid, config = self.validate_data()
        if not is_valid or config is None:
            return

        # Extract secret before disk write
        apikey = (self.entry_apikey.get_value() or "").strip()
        server_url = (self.entry_url.get_value() or "").strip()

        # 1) Write secret to keyring first (so user sees a clear error if keyring is misconfigured)
        if apikey:
            if not set_apikey(server_url, apikey):
                messagebox.showerror(
                    "Keyring Error",
                    "Failed to save API key to the system keychain. "
                    "Please ensure a keyring is available (Windows Credential Manager, macOS Keychain, or Secret Service/KWallet).",
                    parent=self.master,
                )
                self.update_status("Error saving API key.", "red")
                return

        # 2) Remove apikey from config dict before saving to disk
        config.pop("apikey", None)

        # 3) Save the rest of the config to JSON
        if save_config(config):
            logging.info("Configuration saved without secrets.")
            self.config_data = config
            self.save_button.config(text="Config Saved", state=tk.DISABLED)
            self.update_status("Configuration saved.", "green")
        else:
            messagebox.showerror(
                "File Error",
                "Failed to save configuration file.\n\nCheck directory permissions.",
                parent=self.master,
            )
            self.update_status("Error saving configuration.", "red")

    def update_status(self, message: str, color: str) -> None:
        """Updates the status label."""
        self.status_label.config(text=message, fg=color)

    def on_closing(self) -> None:
        """Handles the window close event."""
        logging.info("Configuration UI closing.")
        self.master.destroy()

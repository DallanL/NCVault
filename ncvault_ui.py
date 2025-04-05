import tkinter as tk
from tkinter import filedialog, messagebox
import json
import os
import logging
from app.helpers import validate_and_normalize_domain
from app.config import Config

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
log = logging.getLogger(__name__)


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
        if self.winfo_exists() and super().get() == self.placeholder:
            self.delete(0, tk.END)
            self.config(fg=self.default_fg_color)

    def _on_focus_out(self, event) -> None:
        """Adds placeholder if the entry is empty."""
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
        master.title("VoIP Service Configuration")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.config_data = {}

        # --- UI Elements ---
        tk.Label(master, text="Server URL:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_url = PlaceholderEntry(
            master, placeholder="voip.example.com", width=75
        )
        self.entry_url.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(master, text="API Key:").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_apikey = PlaceholderEntry(
            master, placeholder="nsd-erfwu4432hjkl......", width=75
        )
        self.entry_apikey.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(master, text="Data Directory:").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.entry_directory = PlaceholderEntry(
            master, placeholder="Select directory for storing data", width=65
        )
        self.entry_directory.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W + tk.E)
        self.browse_button = tk.Button(
            master, text="Browse...", command=self.browse_directory
        )
        self.browse_button.grid(row=2, column=2, padx=5, pady=5)

        self.save_button = tk.Button(
            master, text="Save Configuration", command=self.save_configuration
        )
        self.save_button.grid(row=3, column=1, pady=10)

        self.status_label = tk.Label(master, text="", fg="green")
        self.status_label.grid(row=4, column=0, columnspan=3, pady=5)

    def browse_directory(self) -> None:
        """Opens a dialog to choose a directory and updates the entry."""
        directory = filedialog.askdirectory(mustexist=True)
        if directory:
            self.entry_directory.set_value(directory)  # Use set_value
            self.update_status("", "black")

    def validate_data(self) -> tuple[bool, dict | None]:
        """Validates inputs and returns (isValid, config_dict or None)."""
        # Use get_value() to correctly handle placeholder text
        server_url_input = self.entry_url.get_value().strip()
        apikey = self.entry_apikey.get_value().strip()
        data_directory = self.entry_directory.get_value().strip()

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

        self.entry_url.set_value(full_url)  # Use set_value

        config = {
            "server_url": full_url,
            "apikey": apikey,
            "data_directory": data_directory,
        }
        return True, config

    def save_configuration(self) -> None:
        """Validates inputs and saves them to a JSON file in the data directory."""
        self.update_status("", "black")
        isValid, config = self.validate_data()

        if not isValid or config is None:
            return

        data_dir = config["data_directory"]
        config_filepath = os.path.join(data_dir, Config.CONFIG_FILENAME)

        try:
            os.makedirs(data_dir, exist_ok=True)
            logging.info(f"Ensured data directory exists: {data_dir}")

            with open(config_filepath, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
            logging.info(f"Configuration saved successfully to: {config_filepath}")
            self.config_data = config

            self.update_status(f"Configuration saved: {config_filepath}", "green")
            self.save_button.config(text="Config Saved", state=tk.DISABLED)

        except OSError as e:
            logging.error(
                f"Failed to create directory or save config file: {e}", exc_info=True
            )
            messagebox.showerror(
                "File Error",
                f"Failed to save configuration file:\n{e}\n\nPlease check permissions for directory:\n{data_dir}",
                parent=self.master,
            )
            self.update_status(f"Error saving configuration.", "red")
        except Exception as e:
            logging.error(
                f"An unexpected error occurred during save: {e}", exc_info=True
            )
            messagebox.showerror(
                "Error", f"An unexpected error occurred:\n{e}", parent=self.master
            )
            self.update_status(f"Error saving configuration.", "red")

    def update_status(self, message: str, color: str) -> None:
        """Updates the status label."""
        self.status_label.config(text=message, fg=color)

    def on_closing(self) -> None:
        """Handles the window close event."""
        logging.info("Configuration UI closing.")
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ConfigUI(root)
    root.mainloop()

import tkinter as tk
import logging
from app.ui import ConfigUI
from app.config_manager import migrate_apikey_to_keyring, _get_pointer_filepath

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    # One-time migration to secure API keys
    migrate_apikey_to_keyring(_get_pointer_filepath())

    root = tk.Tk()
    app = ConfigUI(root)
    root.mainloop()

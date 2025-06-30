import tkinter as tk
import logging
from app.ui import ConfigUI

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    root = tk.Tk()
    app = ConfigUI(root)
    root.mainloop()
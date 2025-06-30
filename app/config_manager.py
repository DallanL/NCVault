import json
import os
import logging
import platformdirs

log = logging.getLogger(__name__)

class Config:
    """Holds application-wide constants and potentially default settings."""

    # Application identification (used for data directories)
    APP_NAME = "NCVault"
    APP_AUTHOR = "NCVaultDev"

    # Filenames
    POINTER_FILENAME = (
        "ncvault_pointer.json"  # Stores the location of the data dir pointer
    )
    CONFIG_FILENAME = (
        "ncvault_config.json"  # The main config file within data_directory
    )
    LOG_FILENAME = "ncvault.log"  # Log file within data_directory

    # Default configuration values
    DEFAULT_CHECK_INTERVAL_MINUTES = (
        5  # How often we check with the API for new records
    )


def _get_app_data_dir() -> str:
    """Gets the platform-specific user data directory for this app."""
    # Use constants from Config class
    return platformdirs.user_data_dir(Config.APP_NAME, Config.APP_AUTHOR, roaming=True)


def _get_pointer_filepath() -> str:
    """Gets the full path to the pointer file."""
    app_data_dir = _get_app_data_dir()
    # Use constant from Config class
    return os.path.join(app_data_dir, Config.POINTER_FILENAME)


def load_config() -> dict | None:
    """
    Loads the application configuration using the pointer file.
    Returns the config dict or None if not found or invalid.
    """
    pointer_filepath = _get_pointer_filepath()
    log.debug(f"Attempting to load pointer file: {pointer_filepath}")

    if not os.path.isfile(pointer_filepath):
        log.info("Pointer file not found. Configuration likely not set up yet.")
        return None

    try:
        with open(pointer_filepath, "r", encoding="utf-8") as f:
            pointer_data = json.load(f)
        data_directory = pointer_data.get("data_directory")
        if (
            not data_directory
            or not isinstance(data_directory, str)
            or not os.path.isdir(data_directory)
        ):
            log.error(
                f"Pointer file '{pointer_filepath}' is invalid or data directory '{data_directory}' not found."
            )
            return None
        log.info(f"Pointer indicates Data Directory: {data_directory}")

    except (json.JSONDecodeError, OSError, TypeError) as e:
        log.error(
            f"Error reading or parsing pointer file '{pointer_filepath}': {e}",
            exc_info=True,
        )
        return None

    # Use constant from Config class
    config_filepath = os.path.join(data_directory, Config.CONFIG_FILENAME)
    log.debug(f"Attempting to load main config file: {config_filepath}")

    if not os.path.isfile(config_filepath):
        log.warning(
            f"Main config file not found at expected location: {config_filepath}"
        )
        return None

    try:
        with open(config_filepath, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        required_keys = ["server_url", "apikey", "data_directory"]
        if not all(k in config_data for k in required_keys):
            log.error(f"Config file '{config_filepath}' is missing required keys.")
            return None
        if config_data.get("data_directory") != data_directory:
            log.warning(
                f"Mismatch between pointer data dir ('{data_directory}') and config data dir ('{config_data.get('data_directory')}'). Using pointer."
            )
            config_data["data_directory"] = data_directory

        log.info(f"Successfully loaded configuration from {config_filepath}")
        return config_data

    except (json.JSONDecodeError, OSError, TypeError) as e:
        log.error(
            f"Error reading or parsing config file '{config_filepath}': {e}",
            exc_info=True,
        )
        return None


def save_config(config_dict: dict) -> bool:
    """
    Saves the main config file and updates the pointer file.
    Returns True on success, False on failure.
    """
    data_directory = config_dict.get("data_directory")
    if not data_directory or not isinstance(data_directory, str):
        log.error("Cannot save config: 'data_directory' missing or invalid.")
        return False

    # Use constant from Config class
    config_filepath = os.path.join(data_directory, Config.CONFIG_FILENAME)
    try:
        os.makedirs(data_directory, exist_ok=True)
        with open(config_filepath, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=4)
        log.info(f"Main configuration saved to: {config_filepath}")
    except OSError as e:
        log.error(f"Failed to save config file '{config_filepath}': {e}", exc_info=True)
        return False

    pointer_filepath = _get_pointer_filepath()
    app_data_dir = os.path.dirname(pointer_filepath)
    pointer_data = {"data_directory": data_directory}
    try:
        os.makedirs(app_data_dir, exist_ok=True)
        # Use constant from Config class
        with open(pointer_filepath, "w", encoding="utf-8") as f:
            json.dump(pointer_data, f, indent=4)
        log.info(f"Pointer file updated at: {pointer_filepath}")
        return True
    except OSError as e:
        log.error(
            f"Failed to save pointer file '{pointer_filepath}': {e}", exc_info=True
        )
        return False
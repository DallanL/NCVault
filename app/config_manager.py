import json
import os
import logging
from typing import Optional, Dict, Any
import platformdirs
import keyring
import keyring.errors

log = logging.getLogger(__name__)

KEYRING_SERVICE = "NCVault"


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


def _get_pointer_filepath() -> str:
    """Gets the full path to the pointer file."""
    app_data_dir = platformdirs.user_data_dir(
        Config.APP_NAME, Config.APP_AUTHOR, roaming=True
    )
    # Use constant from Config class
    return os.path.join(app_data_dir, Config.POINTER_FILENAME)


def _read_config_file(config_path: str) -> Dict[str, Any]:
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        log.error(f"Failed to read config '{config_path}': {e}", exc_info=True)
        return {}


def _write_config_file(config_path: str, cfg: Dict[str, Any]) -> bool:
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
        return True
    except Exception as e:
        log.error(f"Failed to write config '{config_path}': {e}", exc_info=True)
        return False


def _keyring_backend_name() -> str:
    try:
        kr = keyring.get_keyring()
        return getattr(kr, "__class__", type(kr)).__name__
    except Exception:
        return "unknown"


def get_apikey(server_url: str) -> Optional[str]:
    """Read API key for a given server URL from the OS keyring."""
    if not server_url:
        return None
    try:
        return keyring.get_password(KEYRING_SERVICE, server_url)  # never log the value
    except Exception as e:
        log.error(
            f"Keyring read failed ({_keyring_backend_name()}): {e}", exc_info=True
        )
        return None


def set_apikey(server_url: str, apikey: str) -> bool:
    """Write/replace API key in the OS keyring."""
    if not (server_url and apikey):
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, server_url, apikey)
        return True
    except Exception as e:
        log.error(
            f"Keyring write failed ({_keyring_backend_name()}): {e}", exc_info=True
        )
        return False


def delete_apikey(server_url: str) -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, server_url)
    except keyring.errors.PasswordDeleteError:
        pass  # nothing stored
    except Exception as e:
        log.warning(f"Keyring delete failed: {e}")


def migrate_apikey_to_keyring(config_path: str) -> None:
    """
    One-time migration:
      - If config JSON contains 'apikey', move it into keyring under (service=NCVault, username=server_url).
      - Remove 'apikey' from the JSON and rewrite the file.
      - Idempotent: safe to run on every startup.
    """
    cfg = _read_config_file(config_path)
    if not cfg:
        return

    server_url = cfg.get("server_url", "")
    file_key = cfg.pop("apikey", None)

    if file_key and server_url:
        backend = _keyring_backend_name()
        # Fail closed on obviously unsafe/null backends so we never "migrate" into plaintext.
        if "Plaintext" in backend or backend in {"Keyring", "NullKeyring"}:
            log.error(
                f"Refusing to migrate secret: insecure or null keyring backend detected ({backend}). "
                "Install/enable a real OS keyring."
            )
            return

        if set_apikey(server_url, file_key):
            log.info("API key migrated to OS keyring.")
            # re-write file without 'apikey'
            if not _write_config_file(config_path, cfg):
                log.error(
                    "Config rewrite without 'apikey' failed; consider manual cleanup."
                )
        else:
            log.error("Migration failed: could not write to keyring.")


def load_config() -> Dict[str, Any]:
    """
    Load config from JSON. Never returns the API key; callers must use get_apikey(server_url).
    """
    config_filepath = _get_pointer_filepath()  # <-- your existing resolver
    cfg = _read_config_file(config_filepath)
    # Ensure callers never see 'apikey' from disk even if some old file still has it.
    if "apikey" in cfg:
        cfg.pop("apikey", None)
    return cfg


def save_config(config_dict: Dict[str, Any]) -> bool:
    """
    Save non-secret config values to JSON. Secrets are handled separately via set_apikey().
    """
    config_filepath = _get_pointer_filepath()  # <-- your existing resolver
    # Hard block if caller tries to persist secrets.
    config_sans_secret = {k: v for k, v in config_dict.items() if k != "apikey"}
    ok = _write_config_file(config_filepath, config_sans_secret)
    if not ok:
        log.error("Failed to save configuration.")
    return ok

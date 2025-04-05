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

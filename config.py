import json
import os


EXPECTED_KEYS = ("interface", "gateway_ip", "subnet", "db_path")


def load_config() -> dict:
    """Load and validate configuration from config.json in the repo root."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")

    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing required config file: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Malformed JSON in config file '{config_path}': {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})"
        ) from exc

    if not isinstance(config, dict):
        raise RuntimeError("Configuration must be a JSON object (dictionary).")

    missing_keys = [key for key in EXPECTED_KEYS if key not in config]
    if missing_keys:
        raise RuntimeError(
            "Missing required config keys: " + ", ".join(sorted(missing_keys))
        )

    return config
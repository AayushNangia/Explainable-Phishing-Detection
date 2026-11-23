"""Central configuration (environment variables with safe defaults)."""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(BASE_DIR.parent / ".env", BASE_DIR / ".env"), extra="ignore")

    frontend_origin: str = "http://localhost:5173"
    mongodb_uri: str = ""
    mongodb_db: str = "phishing_detection"
    store_full_input: bool = False      # privacy: off by default
    force_local_storage: bool = False

    models_dir: Path = BASE_DIR / "models"
    datasets_dir: Path = BASE_DIR / "datasets"
    local_store_dir: Path = BASE_DIR / "local_store"
    max_url_length: int = 2048
    max_email_chars: int = 20000


settings = Settings()

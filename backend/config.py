"""
config.py — Environment-based configuration for the Phishing Detector backend.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

_backend_dir = Path(__file__).parent
load_dotenv(_backend_dir / ".env")

_is_vercel = bool(os.environ.get("VERCEL"))


class Config:
    """Base configuration loaded from environment variables."""

    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH",
        "/tmp/phishing.db" if _is_vercel else str(_backend_dir / "db" / "phishing.db"),
    )
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    RATE_LIMIT: str = os.getenv("RATE_LIMIT", "30 per minute")
    FLASK_ENV: str = os.getenv("FLASK_ENV", "development")

    MODELS_DIR: Path = _backend_dir / "models"
    MODEL_PATH: Path = MODELS_DIR / "model.joblib"
    SCALER_PATH: Path = MODELS_DIR / "scaler.joblib"
    META_PATH: Path = MODELS_DIR / "meta.json"

    DATA_DIR: Path = _backend_dir / "data"
    DATASET_PATH: Path = DATA_DIR / "dataset.csv"

    LOGS_DIR: Path = Path("/tmp/logs") if _is_vercel else (_backend_dir / "logs")

    @property
    def is_production(self) -> bool:
        return self.FLASK_ENV == "production"


config = Config()

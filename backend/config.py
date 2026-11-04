"""
config.py — Environment-based configuration for the Phishing Detector backend.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from the backend directory
_backend_dir = Path(__file__).parent
load_dotenv(_backend_dir / ".env")


class Config:
    """Base configuration loaded from environment variables."""

    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", str(_backend_dir / "db" / "phishing.db"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    RATE_LIMIT: str = os.getenv("RATE_LIMIT", "30 per minute")
    FLASK_ENV: str = os.getenv("FLASK_ENV", "development")

    # Model artifact paths
    MODELS_DIR: Path = _backend_dir / "models"
    MODEL_PATH: Path = MODELS_DIR / "model.joblib"
    SCALER_PATH: Path = MODELS_DIR / "scaler.joblib"
    META_PATH: Path = MODELS_DIR / "meta.json"

    # Dataset
    DATA_DIR: Path = _backend_dir / "data"
    DATASET_PATH: Path = DATA_DIR / "dataset.csv"

    # Logs
    LOGS_DIR: Path = _backend_dir / "logs"

    @property
    def is_production(self) -> bool:
        return self.FLASK_ENV == "production"


config = Config()

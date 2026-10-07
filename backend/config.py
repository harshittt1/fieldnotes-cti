import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

MONGODB_URI = os.getenv("MONGODB_URI")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

DATABASE_NAME = "cti_7_2"


if not MONGODB_URI:
    raise ValueError("MONGODB_URI is missing from .env")

if not THREATFOX_API_KEY:
    raise ValueError(
        "THREATFOX_API_KEY is missing from .env"
    )

if not URLHAUS_API_KEY:
    raise ValueError(
        "URLHAUS_API_KEY is missing from .env"
    )

if not MALWAREBAZAAR_API_KEY:
    raise ValueError(
        "MALWAREBAZAAR_API_KEY is missing from .env"
    )

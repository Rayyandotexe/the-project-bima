# src/config.py
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
DB_URL = os.getenv('DB_URL', f'sqlite:///{BASE_DIR/"bima.db"}')
USER_AGENT = os.getenv('USER_AGENT', 'the-project-bima-crawler/1.0')
RATE_LIMIT_PER_SECOND = float(os.getenv('RATE_LIMIT', '1.0'))
CATEGORY_LIST = [
    'online gambling','phishing','malware','fraud','spam','pornography'
]

# Decision thresholds (tunable)
RULES_HIGH = float(os.getenv('RULES_HIGH', '0.75'))   # rules score >= => phishing
RULES_LOW  = float(os.getenv('RULES_LOW',  '0.25'))   # rules score <= => legit
ML_HIGH    = float(os.getenv('ML_HIGH',    '0.70'))   # ml prob >= => phishing
ML_LOW     = float(os.getenv('ML_LOW',     '0.30'))   # ml prob <= => legit
HYBRID_ALPHA = float(os.getenv('HYBRID_ALPHA', '0.6'))  # weight for ML in hybrid
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '8'))  # seconds
ML_DECISION_THRESHOLD = float(os.getenv("ML_DECISION_THRESHOLD", "0.35"))

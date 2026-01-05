# config.py
import os
from dataclasses import dataclass

@dataclass
class Config:
    URLSCAN_API_KEY: str | None = os.getenv("URLSCAN_API_KEY")
    VT_API_KEY: str | None = os.getenv("VT_API_KEY")
    ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY")
    
    # Безопасный режим: не отправлять данные в публичные API
    OSINT_PUBLIC_SCAN: bool = os.getenv("OSINT_PUBLIC_SCAN", "false").lower() == "true"

config = Config()
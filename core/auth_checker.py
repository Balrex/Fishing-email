# core/auth_checker.py
import spf
import dkim
from authres import AuthenticationResults

def check_spf(domain: str, ip: str, helo: str = "") -> bool:
    try:
        result = spf.check(i=ip, s=domain, h=helo)
        return result == "pass"
    except:
        return False

def check_dkim(msg_bytes: bytes) -> bool:
    try:
        return dkim.verify(msg_bytes)
    except:
        return False

def parse_dmarc(auth_results: str) -> bool:
    # Простой парсинг — в продакшене использовать библиотеку dmarcparse
    return "dmarc=pass" in auth_results.lower()
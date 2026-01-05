# core/parser.py
import email
from email.message import Message
from typing import Optional

def parse_eml(file_path: str) -> Optional[Message]:
    """Парсит .eml файл по RFC 5322."""
    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_bytes(f.read())
        return msg
    except Exception as e:
        raise ValueError(f"Failed to parse EML: {e}")

def extract_headers(msg: Message) -> dict:
    """Извлекает ключевые заголовки."""
    return {
        "from": msg.get("From"),
        "return_path": msg.get("Return-Path"),
        "reply_to": msg.get("Reply-To"),
        "message_id": msg.get("Message-ID"),
        "received": msg.get_all("Received", []),
        "x_originating_ip": msg.get("X-Originating-IP") or msg.get("X-Original-IP"),
        "auth_results": msg.get("Authentication-Results", ""),
    }
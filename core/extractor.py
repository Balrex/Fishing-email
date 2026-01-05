# core/extractor.py
import re
from typing import List, Set
from urllib.parse import urlparse

def extract_ips_from_received(received_headers: List[str]) -> Set[str]:
    """Извлекает IP-адреса из цепочки Received."""
    ips = set()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for header in received_headers:
        ips.update(ip_pattern.findall(header))
    return ips

def extract_domains_from_email(email_str: str | None) -> Set[str]:
    """Извлекает домен из email (From, Reply-To)."""
    if not email_str:
        return set()
    # Простой парсинг email
    match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", email_str)
    return {match.group(1)} if match else set()

def extract_urls_from_body(body: str) -> Set[str]:
    """Извлекает все URL из HTML/текста."""
    # Поддержка http/https и ссылок без протокола
    url_pattern = re.compile(
        r"(https?://[^\s\"'<>,]+|www\.[^\s\"'<>,]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s\"'<>,]*)"
    )
    urls = set()
    for url in url_pattern.findall(body):
        if url.startswith(("http", "www")):
            urls.add(url if url.startswith("http") else f"http://{url}")
        else:
            # Предполагаем как домен с путём
            urls.add(f"http://{url}")
    return urls

def normalize_urls(urls: Set[str]) -> Set[str]:
    """Оставляет только домен + путь без параметров."""
    normalized = set()
    for url in urls:
        parsed = urlparse(url)
        normalized.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
    return normalized
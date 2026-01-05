# main.py
import asyncio
import argparse
from pathlib import Path
from core.parser import parse_eml, extract_headers
from core.auth_checker import check_spf, parse_dmarc
from osint.urlscan import scan_url
import aiohttp

async def analyze_eml(file_path: str):
    msg = parse_eml(file_path)
    headers = extract_headers(msg)

    # Пример извлечения IP и домена
    ip = headers["x_originating_ip"] or "unknown"
    domain = headers["from"].split("@")[-1].strip(">") if headers["from"] else "unknown"

    # Проверка аутентификации
    spf_ok = check_spf(domain, ip)
    dmarc_ok = parse_dmarc(headers["auth_results"])
    auth_ok = spf_ok and dmarc_ok

    # OSINT-проверка
    async with aiohttp.ClientSession() as session:
        urlscan_result = await scan_url(f"https://{domain}", session)

    # Оценка
    risk = evaluate_risk(auth_ok, {"urlscan": [urlscan_result] if urlscan_result else []})
    print(f"[{file_path}] Risk level: {risk}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", help="Paths to .eml files")
    args = parser.parse_args()

    for file in args.files:
        if Path(file).exists():
            asyncio.run(analyze_eml(file))
        else:
            print(f"File not found: {file}")

if __name__ == "__main__":
    main()
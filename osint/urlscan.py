# osint/urlscan.py
import asyncio
import aiohttp
from core.config import config

async def scan_url(url: str, session: aiohttp.ClientSession) -> dict | None:
    if not config.URLSCAN_API_KEY:
        return None

    try:
        # 1. Отправка на сканирование
        async with session.post(
            "https://urlscan.io/api/v1/scan/",
            json={"url": url, "public": str(config.OSINT_PUBLIC_SCAN).lower()},
            headers={"API-Key": config.URLSCAN_API_KEY}
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            uuid = data["uuid"]

        # 2. Ожидание и получение результата
        await asyncio.sleep(10)
        async with session.get(f"https://urlscan.io/api/v1/result/{uuid}/") as result_resp:
            if result_resp.status == 200:
                return await result_resp.json()
    except Exception as e:
        print(f"[urlscan] Error scanning {url}: {e}")
    return None
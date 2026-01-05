# osint/virustotal.py
import asyncio
import aiohttp
from typing import Dict, Any, Optional
from config import config

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def _get(self, endpoint: str) -> Optional[Dict[Any, Any]]:
        if not config.VT_API_KEY:
            return None
        try:
            async with self.session.get(
                f"{self.BASE_URL}/{endpoint}",
                headers={"x-apikey": config.VT_API_KEY}
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                return None
        except Exception as e:
            print(f"[VT] Error: {e}")
            return None

    async def check_url(self, url: str) -> Dict[str, Any]:
        # VirusTotal требует base64-url-encoded URL
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        data = await self._get(f"urls/{url_id}")
        if not data:
            return {"url": url, "is_malicious": False, "score": 0}
        
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        score = malicious / total if total else 0
        return {
            "url": url,
            "is_malicious": malicious > 0,
            "score": round(score, 2),
            "vt_id": data["data"]["id"]
        }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        data = await self._get(f"ip_addresses/{ip}")
        if not data:
            return {"ip": ip, "is_malicious": False}
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "ip": ip,
            "is_malicious": stats.get("malicious", 0) > 0,
            "reputation": data["data"]["attributes"].get("reputation", 0)
        }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        data = await self._get(f"domains/{domain}")
        if not data:
            return {"domain": domain, "is_malicious": False}
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "domain": domain,
            "is_malicious": stats.get("malicious", 0) > 0
        }
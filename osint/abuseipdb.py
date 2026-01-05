# osint/abuseipdb.py
import asyncio
import aiohttp
from config import config

async def check_ip_abuseipdb(ip: str, session: aiohttp.ClientSession) -> dict:
    if not config.ABUSEIPDB_API_KEY:
        return {"ip": ip, "is_malicious": False, "abuse_score": 0}

    try:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                report = data["data"]
                score = report.get("abuseConfidenceScore", 0)
                return {
                    "ip": ip,
                    "is_malicious": score > 20,
                    "abuse_score": score,
                    "total_reports": report.get("totalReports", 0)
                }
    except Exception as e:
        print(f"[AbuseIPDB] Error for {ip}: {e}")
    return {"ip": ip, "is_malicious": False, "abuse_score": 0}
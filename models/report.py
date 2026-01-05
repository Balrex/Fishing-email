# models/report.py
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class PhishingReport:
    file_path: str
    from_email: Optional[str]
    return_path: Optional[str]
    spf_pass: bool
    dmarc_pass: bool
    extracted_ips: List[str]
    extracted_domains: List[str]
    extracted_urls: List[str]
    osint_results: Dict[str, List[Dict[str, Any]]]
    risk_level: str  # "low", "medium", "high"
    verdict: str

    def to_json(self) -> dict:
        return asdict(self)
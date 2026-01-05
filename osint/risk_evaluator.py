# core/risk_evaluator.py
from typing import Dict, List

def evaluate_risk(
    auth_ok: bool,
    osint_results: Dict[str, List[dict]]
) -> str:
    score = 0

    if not auth_ok:
        score += 50  # серьёзный признак подделки

    # Проверка репутации
    for source, results in osint_results.items():
        if any(r.get("is_malicious") for r in results):
            score += 40

    if score >= 70:
        return "high"
    elif score >= 30:
        return "medium"
    return "low"
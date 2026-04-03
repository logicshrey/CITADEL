from __future__ import annotations

import re
from collections import Counter
from typing import Any


DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

MULTILINGUAL_GLOSSARY = {
    "spanish": {
        "credenciales": "credentials",
        "contrasena": "password",
        "claves": "keys",
        "phishing": "phishing",
        "base de datos": "database",
        "filtracion": "leak",
        "cuentas": "accounts",
        "acceso": "access",
        "banco": "bank",
        "dump": "dump",
    },
    "portuguese": {
        "credenciais": "credentials",
        "senha": "password",
        "vazamento": "leak",
        "banco de dados": "database",
        "contas": "accounts",
        "acesso": "access",
        "golpe": "phishing",
    },
    "french": {
        "identifiants": "credentials",
        "mot de passe": "password",
        "fuite": "leak",
        "base de donnees": "database",
        "acces": "access",
        "attaque": "attack",
    },
    "hinglish": {
        "maal": "goods",
        "pakka": "verified",
        "bikau": "for sale",
        "khata": "account",
        "setting": "arrangement",
        "otp": "otp",
    },
    "russian_romanized": {
        "dannye": "data",
        "parol": "password",
        "dostup": "access",
        "sliv": "leak",
        "akkaunt": "account",
        "baza": "database",
    },
}

SLANG_LEXICON = {
    "fresh logs": {"meaning": "stolen credentials or infostealer session logs", "category": "Credential Leak"},
    "combo": {"meaning": "paired usernames and passwords", "category": "Credential Leak"},
    "combo list": {"meaning": "paired usernames and passwords", "category": "Credential Leak"},
    "fullz": {"meaning": "full victim identity package", "category": "Database Dump"},
    "carded": {"meaning": "fraudulent payment card activity", "category": "Database Dump"},
    "cc dump": {"meaning": "credit card database dump", "category": "Database Dump"},
    "panel access": {"meaning": "administrative control panel access", "category": "Credential Leak"},
    "rdp": {"meaning": "remote desktop access", "category": "Credential Leak"},
    "stealer": {"meaning": "credential stealing malware", "category": "Malware Sale"},
    "crypter": {"meaning": "malware obfuscation tool", "category": "Malware Sale"},
    "loader": {"meaning": "malware delivery component", "category": "Malware Sale"},
    "fud": {"meaning": "fully undetectable malware claim", "category": "Malware Sale"},
    "drop": {"meaning": "stolen data release or malware delivery", "category": "Database Dump"},
    "kit": {"meaning": "phishing or malware toolkit", "category": "Phishing"},
    "otp relay": {"meaning": "real-time one-time-password interception", "category": "Phishing"},
    "onion mirror": {"meaning": "hidden service clone", "category": "Phishing"},
}


def normalize_multilingual_text(text: str) -> dict[str, Any]:
    lowered = text.lower()
    translated_terms = []
    language_scores: Counter[str] = Counter()
    normalized_text = lowered

    for language, glossary in MULTILINGUAL_GLOSSARY.items():
        for source_term, english_term in glossary.items():
            if source_term in normalized_text:
                language_scores[language] += 1
                translated_terms.append(
                    {
                        "language": language,
                        "source": source_term,
                        "normalized": english_term,
                    }
                )
                normalized_text = normalized_text.replace(source_term, english_term)

    language = language_scores.most_common(1)[0][0] if language_scores else "english_or_unknown"
    return {
        "language": language,
        "score": language_scores.get(language, 0),
        "translated_terms": translated_terms,
        "normalized_text": normalized_text,
    }


def decode_slang(text: str) -> dict[str, Any]:
    lowered = text.lower()
    decoded = []
    normalized_text = lowered

    for phrase, metadata in SLANG_LEXICON.items():
        if phrase in normalized_text:
            decoded.append(
                {
                    "phrase": phrase,
                    "meaning": metadata["meaning"],
                    "category": metadata["category"],
                }
            )
            normalized_text = normalized_text.replace(phrase, f"{phrase} {metadata['meaning']}")

    return {
        "decoded_terms": decoded,
        "normalized_text": normalized_text,
    }


def extract_enriched_entities(text: str, regex_matches: dict[str, list[str]]) -> list[dict[str, str]]:
    entities = []
    domains = list(dict.fromkeys(DOMAIN_PATTERN.findall(text)))
    for domain in domains:
        if not any(domain in email for email in regex_matches.get("emails", [])):
            entities.append({"text": domain, "label": "DOMAIN"})

    for email in regex_matches.get("emails", []):
        entities.append({"text": email, "label": "EMAIL"})
    for handle in regex_matches.get("telegram_handles", []):
        entities.append({"text": handle, "label": "HANDLE"})
    for wallet in regex_matches.get("bitcoin_wallets", []):
        entities.append({"text": wallet, "label": "WALLET"})

    return entities


def estimate_impact(
    threat_type: str,
    text: str,
    regex_matches: dict[str, list[str]],
    entities: list[dict[str, str]],
    slang: dict[str, Any],
) -> dict[str, Any]:
    lowered = text.lower()
    data_types = []

    if regex_matches.get("emails"):
        data_types.append("email addresses")
    if regex_matches.get("passwords"):
        data_types.append("passwords")
    if regex_matches.get("credit_cards"):
        data_types.append("payment card data")
    if regex_matches.get("bitcoin_wallets"):
        data_types.append("crypto wallet identifiers")
    if regex_matches.get("ips"):
        data_types.append("infrastructure indicators")
    if any(term["category"] == "Database Dump" for term in slang.get("decoded_terms", [])):
        data_types.append("bulk personal records")

    if any(keyword in lowered for keyword in ("million", "bulk", "full dump", "archive", "database", "records")):
        estimated_records = "10k+"
        impact_score = 85
    elif any(keyword in lowered for keyword in ("admin", "panel", "vpn", "rdp", "access")):
        estimated_records = "high privilege access"
        impact_score = 78
    elif any(keyword in lowered for keyword in ("kit", "campaign", "phishing", "sms")):
        estimated_records = "campaign scale unknown"
        impact_score = 70
    else:
        estimated_records = "limited exposure"
        impact_score = 55

    if threat_type == "Database Dump":
        business_risk = "Severe data disclosure risk"
        impact_score += 8
    elif threat_type == "Credential Leak":
        business_risk = "Account takeover and fraud risk"
        impact_score += 6
    elif threat_type == "Malware Sale":
        business_risk = "Operational compromise risk"
        impact_score += 7
    elif threat_type == "Phishing":
        business_risk = "Customer impersonation risk"
        impact_score += 4
    else:
        business_risk = "Limited immediate business risk"

    affected_orgs = [entity["text"] for entity in entities if entity["label"] == "ORG"]
    summary = f"{business_risk}; likely affected assets: {', '.join(affected_orgs[:3]) or 'unknown'}."

    deduped_data_types = list(dict.fromkeys(data_types)) or ["undetermined data type"]
    return {
        "estimated_records": estimated_records,
        "exposed_data_types": deduped_data_types,
        "business_risk": business_risk,
        "impact_score": min(100, impact_score),
        "summary": summary,
    }


def correlate_alerts(candidate_result: dict[str, Any], recent_alerts: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_entities = {entity.get("text", "").lower() for entity in candidate_result.get("entities", []) if entity.get("text")}
    candidate_domains = {
        entity.get("text", "").lower()
        for entity in candidate_result.get("enriched_entities", [])
        if entity.get("label") in {"DOMAIN", "HANDLE", "EMAIL", "WALLET"}
    }
    candidate_slang = {term["phrase"] for term in candidate_result.get("slang_decoder", {}).get("decoded_terms", [])}
    candidate_threat = candidate_result.get("threat_type")

    matches = []
    recurring_signal_counter: Counter[str] = Counter()

    for alert in recent_alerts:
        result = alert.get("results", alert)
        shared_entities = candidate_entities.intersection(
            {entity.get("text", "").lower() for entity in result.get("entities", []) if entity.get("text")}
        )
        shared_domains = candidate_domains.intersection(
            {
                entity.get("text", "").lower()
                for entity in result.get("enriched_entities", [])
                if entity.get("label") in {"DOMAIN", "HANDLE", "EMAIL", "WALLET"}
            }
        )
        shared_slang = candidate_slang.intersection(
            {term["phrase"] for term in result.get("slang_decoder", {}).get("decoded_terms", [])}
        )
        same_threat = candidate_threat == result.get("threat_type")

        score = 0
        if same_threat:
            score += 15
        score += len(shared_entities) * 14
        score += len(shared_domains) * 12
        score += len(shared_slang) * 9

        shared_signals = sorted(shared_entities.union(shared_domains).union(shared_slang))
        if score >= 20 and shared_signals:
            matches.append(
                {
                    "threat_type": result.get("threat_type"),
                    "timestamp": result.get("timestamp"),
                    "shared_signals": shared_signals[:8],
                    "score": score,
                }
            )
            recurring_signal_counter.update(shared_signals)

    matches.sort(key=lambda item: item["score"], reverse=True)
    campaign_score = min(100, sum(match["score"] for match in matches[:5]))
    return {
        "correlated_alerts_count": len(matches),
        "campaign_score": campaign_score,
        "top_matches": matches[:5],
        "recurring_signals": [signal for signal, _ in recurring_signal_counter.most_common(8)],
    }


def prioritize_alert(
    risk_level: str,
    confidence_score: float,
    impact_assessment: dict[str, Any],
    correlation: dict[str, Any],
) -> dict[str, Any]:
    risk_base = {"LOW": 18, "MEDIUM": 42, "HIGH": 70}.get(risk_level, 18)
    confidence_component = int(confidence_score * 20)
    impact_component = int(impact_assessment.get("impact_score", 0) * 0.2)
    correlation_component = int(correlation.get("campaign_score", 0) * 0.18)

    priority_score = min(100, risk_base + confidence_component + impact_component + correlation_component)
    if priority_score >= 85:
        priority = "CRITICAL"
    elif priority_score >= 65:
        priority = "HIGH"
    elif priority_score >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "priority": priority,
        "priority_score": priority_score,
        "rationale": [
            f"Risk level contributed {risk_base} points.",
            f"Confidence contributed {confidence_component} points.",
            f"Impact estimation contributed {impact_component} points.",
            f"Correlation contributed {correlation_component} points.",
        ],
    }

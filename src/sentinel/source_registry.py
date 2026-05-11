SOURCE_CATEGORIES: dict[str, str] = {
    "anthropic_claude": "llm_behavioral",
    "virustotal": "community_reputation",
    "abuseipdb": "community_reputation",
}


def are_independent(source_a: str, source_b: str) -> bool:
    cat_a = SOURCE_CATEGORIES.get(source_a)
    cat_b = SOURCE_CATEGORIES.get(source_b)
    if cat_a is None or cat_b is None:
        return False
    return cat_a != cat_b

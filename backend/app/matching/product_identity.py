from __future__ import annotations


GENERIC_PRODUCT_NAMES = {
    "app",
    "application",
    "component",
    "core",
    "cms",
    "engine",
    "forms",
    "framework",
    "kernel",
    "library",
    "module",
    "package",
    "platform",
    "plugin",
    "portal",
    "product",
    "server",
    "service",
    "software",
    "system",
    "tool",
    "tools",
    "web",
}

PRODUCT_CONTEXT_TOKENS = {"com", "extension", "for", "joomla", "module", "plugin"}

PRODUCT_MATCH_SCORES = {
    "identifier": 100,
    "package": 95,
    "exact": 90,
    "alias": 80,
    "token": 60,
    "context": 45,
}

MIN_PRODUCT_CANDIDATE_SCORE = PRODUCT_MATCH_SCORES["context"]
MIN_CONCLUSIVE_PRODUCT_SCORE = PRODUCT_MATCH_SCORES["alias"]


def product_match_strength(score: int) -> str:
    for strength in ("identifier", "package", "exact", "alias", "token", "context"):
        if score >= PRODUCT_MATCH_SCORES[strength]:
            return strength
    return "none"

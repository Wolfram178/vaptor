import re


def normalize_target(target):
    """Normalize a target for stable comparison and storage."""
    return target.strip().lower()


def safe_filename(value):
    """Convert a target or label into a Windows-safe file component."""
    cleaned = normalize_target(value)
    cleaned = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", cleaned)
    cleaned = re.sub(r"\s+", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned).strip("._ ")
    return cleaned or "target"


def dedupe_targets(targets):
    """Normalize and deduplicate targets while preserving order."""
    seen = set()
    result = []

    for target in targets:
        normalized = normalize_target(target)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    return result

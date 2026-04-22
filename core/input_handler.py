import os

from core.normalizer import dedupe_targets


def load_targets(file_path):
    """Load targets from a text file and normalize them."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip()]

    return dedupe_targets(targets)

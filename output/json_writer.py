import json
import os


def write_json(findings, output_file):
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4, ensure_ascii=False)

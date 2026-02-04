import argparse
import csv
from collections import Counter, defaultdict
from typing import Dict, List


def load_rows(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        raw_headers = next(reader, [])
        fieldnames = [header.strip() for header in raw_headers]
        rows = []
        for values in reader:
            row = {fieldnames[i]: (values[i].strip() if i < len(values) else "") for i in range(len(fieldnames))}
            rows.append(row)
    return rows


def summarize_counts(rows, field: str) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    missing = 0
    for row in rows:
        value = (row.get(field) or "").strip()
        if value:
            counter[value] += 1
        else:
            missing += 1
    if missing:
        counter["__missing__"] = missing
    return dict(counter)


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick EDA for valid8 log CSV.")
    parser.add_argument("input", help="Path to ml/valid8_logs.csv")
    args = parser.parse_args()

    rows = load_rows(args.input)

    print(f"rows: {len(rows)}")

    fields = [
        "result",
        "provider",
        "role_based",
        "accept_all",
        "full_inbox",
        "temporary_mail",
        "force_live",
        "temp_error",
        "smtp_code",
        "source",
    ]

    for field in fields:
        counts = summarize_counts(rows, field)
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
        print(f"\n{field} (top 10):")
        for key, count in top:
            print(f"  {key}: {count}")

    domain_counts = Counter()
    for row in rows:
        domain = (row.get("domain") or "").strip().lower()
        if domain:
            domain_counts[domain] += 1
    print("\nTop domains (top 10):")
    for domain, count in domain_counts.most_common(10):
        print(f"  {domain}: {count}")

    missing = defaultdict(int)
    for row in rows:
        for key, value in row.items():
            if not (value or "").strip():
                missing[key] += 1
    print("\nMissing fields:")
    for key, count in sorted(missing.items(), key=lambda x: x[1], reverse=True):
        print(f"  {key}: {count}")


if __name__ == "__main__":
    main()

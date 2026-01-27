import argparse
import csv
import os


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean valid8 logs CSV and keep unique emails.")
    parser.add_argument("input", help="Path to ml/valid8_logs.csv")
    parser.add_argument(
        "--output",
        default="valid8_logs_clean.csv",
        help="Output CSV path (default: valid8_logs_clean.csv)",
    )
    parser.add_argument(
        "--require-result",
        action="store_true",
        help="Drop rows without a result label.",
    )
    parser.add_argument(
        "--exclude-results",
        default="Database Error,Verification Error,Email does not exist",
        help="Comma-separated result labels to exclude.",
    )
    args = parser.parse_args()

    excluded = {item.strip() for item in args.exclude_results.split(",") if item.strip()}
    seen = {}
    with open(args.input, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        raw_headers = next(reader, [])
        fieldnames = [header.strip() for header in raw_headers]

        for values in reader:
            row = {fieldnames[i]: (values[i].strip() if i < len(values) else "") for i in range(len(fieldnames))}
            email = (row.get("email") or "").strip().lower()
            if not email:
                continue
            result = (row.get("result") or "").strip()
            if args.require_result and not result:
                continue
            if result and result in excluded:
                continue
            existing = seen.get(email)
            if existing is None:
                seen[email] = row
            else:
                existing_time = (existing.get("timestamp") or "")
                new_time = (row.get("timestamp") or "")
                if new_time and new_time > existing_time:
                    seen[email] = row

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in seen.values():
            writer.writerow(row)


if __name__ == "__main__":
    main()

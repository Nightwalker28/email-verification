import argparse
import csv
import os
from typing import Dict, List, Tuple

from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
import joblib


FEATURE_FIELDS = [
    "domain",
    "mx_host",
    "smtp_code",
    "force_live",
    "temp_error",
    "source",
]


def row_to_features(row: Dict[str, str]) -> Dict[str, str]:
    features = {}
    for field in FEATURE_FIELDS:
        value = (row.get(field) or "").strip()
        if value:
            features[field] = value
    return features


def load_csv(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        raw_headers = next(reader, [])
        fieldnames = [header.strip() for header in raw_headers]
        rows = []
        for values in reader:
            row = {fieldnames[i]: (values[i].strip() if i < len(values) else "") for i in range(len(fieldnames))}
            rows.append(row)
    return rows


def train_classifier(
    rows: List[Dict[str, str]],
    label_field: str,
    output_path: str,
    min_label_count: int,
) -> None:
    raw_pairs: List[Tuple[Dict[str, str], str]] = []
    for row in rows:
        label = (row.get(label_field) or "").strip()
        if label:
            raw_pairs.append((row_to_features(row), label))

    if not raw_pairs:
        raise ValueError(f"No rows with label '{label_field}' found.")

    label_counts: Dict[str, int] = {}
    for _, label in raw_pairs:
        label_counts[label] = label_counts.get(label, 0) + 1

    filtered = [
        (features, label)
        for features, label in raw_pairs
        if label_counts.get(label, 0) >= min_label_count
    ]
    if not filtered:
        raise ValueError(
            f"No rows with label '{label_field}' after filtering min count {min_label_count}."
        )

    X = [item[0] for item in filtered]
    y = [item[1] for item in filtered]

    stratify = y if min(label_counts.values()) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=stratify
    )

    pipeline = Pipeline(
        [
            ("vectorizer", DictVectorizer(sparse=True)),
            ("model", LogisticRegression(max_iter=1000)),
        ]
    )

    pipeline.fit(X_train, y_train)
    preds = pipeline.predict(X_test)

    print(f"\nModel: {label_field}")
    print(classification_report(y_test, preds))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(pipeline, output_path)
    print(f"Saved model to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train baseline models from valid8 logs CSV.")
    parser.add_argument("input", help="Path to ml/valid8_logs.csv")
    parser.add_argument(
        "--outdir",
        default="ml/models",
        help="Output directory for trained models (default: ml/models)",
    )
    parser.add_argument(
        "--min-label-count",
        type=int,
        default=2,
        help="Minimum samples per class to keep (default: 2).",
    )
    args = parser.parse_args()

    rows = load_csv(args.input)
    train_classifier(
        rows, "result", os.path.join(args.outdir, "deliverability.joblib"), args.min_label_count
    )
    train_classifier(
        rows, "provider", os.path.join(args.outdir, "provider.joblib"), args.min_label_count
    )


if __name__ == "__main__":
    main()

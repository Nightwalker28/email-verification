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
    with open(path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def train_classifier(rows: List[Dict[str, str]], label_field: str, output_path: str) -> None:
    filtered: List[Tuple[Dict[str, str], str]] = []
    for row in rows:
        label = (row.get(label_field) or "").strip()
        if label:
            filtered.append((row_to_features(row), label))

    if not filtered:
        raise ValueError(f"No rows with label '{label_field}' found.")

    X = [item[0] for item in filtered]
    y = [item[1] for item in filtered]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline(
        [
            ("vectorizer", DictVectorizer(sparse=True)),
            ("model", LogisticRegression(max_iter=1000, n_jobs=1)),
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
    args = parser.parse_args()

    rows = load_csv(args.input)
    train_classifier(rows, "result", os.path.join(args.outdir, "deliverability.joblib"))
    train_classifier(rows, "provider", os.path.join(args.outdir, "provider.joblib"))


if __name__ == "__main__":
    main()

"""
train_model.py
--------------
Optional supervised + unsupervised ML layer for the IDS.

Models:
    Logistic Regression  - SUPERVISED, linear, fast, interpretable coefficients
    Random Forest        - SUPERVISED, non-linear, robust, feature importances
    Isolation Forest     - UNSUPERVISED, isolates outliers, no labels needed

Difference in one line:
    Supervised  = learns from labelled examples of normal AND suspicious.
    Unsupervised= learns only what "normal" looks like, flags deviations.

Usage:
    python -m ml.train_model
"""

from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import DATASET_PATH, ML_MODEL_PATH, RANDOM_SEED, REPORT_DIR
from ids.feature_extractor import ML_FEATURE_COLUMNS, extract_network_features


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------

def load_features(csv_path=DATASET_PATH) -> tuple[pd.DataFrame, np.ndarray]:
    """Load the synthetic dataset and engineer features for ML."""
    df = pd.read_csv(csv_path)
    rows = [extract_network_features(r) for r in df.to_dict("records")]
    X = pd.DataFrame(rows)[ML_FEATURE_COLUMNS].astype(float)
    y = (df["label"].str.upper() == "SUSPICIOUS").astype(int).to_numpy()
    return X, y


# --------------------------------------------------------------------------
# Evaluation helper
# --------------------------------------------------------------------------

def evaluate_model(name: str, y_true, y_pred, y_proba=None) -> dict:
    """Compute the standard classification metrics."""
    metrics = {
        "model": name,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }
    if y_proba is not None:
        try:
            metrics["roc_auc"] = round(roc_auc_score(y_true, y_proba), 4)
        except ValueError:
            metrics["roc_auc"] = None
    return metrics


def print_metrics(m: dict) -> None:
    tn, fp, fn, tp = m["confusion_matrix"][0][0], m["confusion_matrix"][0][1], \
                     m["confusion_matrix"][1][0], m["confusion_matrix"][1][1]
    print(f"\n{'='*62}")
    print(f" MODEL: {m['model']}")
    print(f"{'='*62}")
    print(f" Accuracy : {m['accuracy']}")
    print(f" Precision: {m['precision']}")
    print(f" Recall   : {m['recall']}")
    print(f" F1 Score : {m['f1']}")
    if m.get("roc_auc") is not None:
        print(f" ROC-AUC  : {m['roc_auc']}")
    print(f" Confusion Matrix  [ [TN={tn}, FP={fp}], [FN={fn}, TP={tp}] ]")
    print(" NOTE: Accuracy alone is misleading on imbalanced security data.")
    print("       Recall matters most (missed detections = missed incidents),")
    print("       but high FP volume causes analyst alert fatigue.")


# --------------------------------------------------------------------------
# Training
# --------------------------------------------------------------------------

def train_all(csv_path=DATASET_PATH) -> dict:
    X, y = load_features(csv_path)
    print(f"[*] Loaded {len(X):,} flows | suspicious={int(y.sum()):,} "
          f"| normal={int((y == 0).sum()):,}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    results = []

    # ---------------- Logistic Regression ----------------
    lr = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced",
                                   random_state=RANDOM_SEED)),
    ])
    lr.fit(X_train, y_train)
    lr_pred = lr.predict(X_test)
    lr_proba = lr.predict_proba(X_test)[:, 1]
    results.append(evaluate_model("Logistic Regression", y_test, lr_pred, lr_proba))

    # ---------------- Random Forest ----------------
    rf = RandomForestClassifier(
        n_estimators=250, max_depth=None, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]
    results.append(evaluate_model("Random Forest", y_test, rf_pred, rf_proba))

    # ---------------- Isolation Forest (unsupervised) ----------------
    # Trained ONLY on normal traffic, as a real anomaly detector would be.
    iso = IsolationForest(contamination=0.30, random_state=RANDOM_SEED)
    iso.fit(X_train[y_train == 0])
    iso_raw = iso.predict(X_test)                # -1 = anomaly, 1 = normal
    iso_pred = (iso_raw == -1).astype(int)
    iso_score = -iso.score_samples(X_test)       # higher = more anomalous
    results.append(evaluate_model("Isolation Forest (unsupervised)",
                                  y_test, iso_pred, iso_score))

    for m in results:
        print_metrics(m)

    # ---------------- Pick and save the best supervised model ----------------
    best = max([r for r in results if "Isolation" not in r["model"]],
               key=lambda r: r["f1"])
    best_name = best["model"]
    best_model = lr if best_name == "Logistic Regression" else rf

    joblib.dump(best_model, ML_MODEL_PATH)
    print(f"\n[+] Best supervised model: {best_name} (F1={best['f1']})")
    print(f"[+] Saved -> {ML_MODEL_PATH}")

    # ---------------- Feature importances ----------------
    importances = None
    if best_name == "Random Forest":
        importances = dict(zip(ML_FEATURE_COLUMNS,
                               [round(float(v), 4) for v in rf.feature_importances_]))
        print("\n[*] Feature importances:")
        for k, v in sorted(importances.items(), key=lambda kv: -kv[1]):
            print(f"    {k:<26} {v}")

    report = {
        "results": results,
        "best_model": best_name,
        "feature_importances": importances,
        "dataset_size": len(X),
        "feature_columns": ML_FEATURE_COLUMNS,
    }
    (REPORT_DIR / "ml_evaluation.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Full evaluation report -> {REPORT_DIR / 'ml_evaluation.json'}")

    return report


if __name__ == "__main__":
    train_all()
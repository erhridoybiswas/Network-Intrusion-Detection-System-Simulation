"""
evaluate.py
-----------
Re-evaluates the saved model on the test split and prints a readable
confusion matrix plus a plain-English interpretation.

Usage:
    python -m ml.evaluate
"""

from __future__ import annotations

from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split

from config import DATASET_PATH, RANDOM_SEED
from ml.predict import load_model
from ml.train_model import load_features


def main() -> None:
    model = load_model()
    if model is None:
        print("[!] No trained model found. Run: python -m ml.train_model")
        return

    X, y = load_features(DATASET_PATH)
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y)

    proba = model.model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    cm = confusion_matrix(y_test, pred)
    tn, fp, fn, tp = cm.ravel()

    print("=" * 60)
    print(" CONFUSION MATRIX")
    print("=" * 60)
    print(f"                  Predicted NORMAL   Predicted SUSPICIOUS")
    print(f" Actual NORMAL         {tn:>6}              {fp:>6}")
    print(f" Actual SUSPICIOUS     {fn:>6}              {tp:>6}")
    print()
    print(f" True Positives  (TP) = {tp:>6}  correctly flagged suspicious")
    print(f" True Negatives  (TN) = {tn:>6}  correctly passed as normal")
    print(f" False Positives (FP) = {fp:>6}  normal traffic flagged (alert fatigue)")
    print(f" False Negatives (FN) = {fn:>6}  suspicious traffic missed (dangerous)")
    print()
    print(f" Accuracy : {accuracy_score(y_test, pred):.4f}")
    print(f" Precision: {precision_score(y_test, pred, zero_division=0):.4f}")
    print(f" Recall   : {recall_score(y_test, pred, zero_division=0):.4f}")
    print(f" F1 Score : {f1_score(y_test, pred, zero_division=0):.4f}")
    print()
    print(" Interpretation:")
    print("  * Precision answers: when we alert, how often are we right?")
    print("  * Recall answers: of all real suspicious flows, how many did we catch?")
    print("  * F1 balances both.")
    print("  * Security teams watch RECALL closely (missed detections are costly),")
    print("    but must also manage FP volume to avoid analyst alert fatigue.")


if __name__ == "__main__":
    main()
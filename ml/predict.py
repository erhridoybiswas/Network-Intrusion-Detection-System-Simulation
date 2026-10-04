"""
predict.py
----------
Loads the trained model and exposes a simple prediction interface.

The pipeline calls `model.predict_probability(features)` and receives a
float in [0, 1] representing the probability that the flow is suspicious.
"""

from __future__ import annotations

import joblib
import numpy as np
import pandas as pd

from config import ML_MODEL_PATH
from ids.feature_extractor import ML_FEATURE_COLUMNS


class IDSModel:
    """Thin wrapper around a scikit-learn estimator."""

    def __init__(self, model):
        self.model = model

    def predict_probability(self, features: dict) -> float:
        """Return P(suspicious) for one engineered feature dict."""
        row = pd.DataFrame([{c: float(features.get(c, 0.0) or 0.0)
                             for c in ML_FEATURE_COLUMNS}])
        if hasattr(self.model, "predict_proba"):
            return float(self.model.predict_proba(row)[0][1])
        # Fallback for estimators without predict_proba
        score = float(self.model.decision_function(row)[0])
        return float(1 / (1 + np.exp(-score)))

    def predict_label(self, features: dict) -> int:
        return int(self.predict_probability(features) >= 0.5)


def load_model(path=ML_MODEL_PATH) -> IDSModel | None:
    """Load the trained model, or return None if it has not been trained."""
    try:
        return IDSModel(joblib.load(path))
    except (FileNotFoundError, OSError):
        return None
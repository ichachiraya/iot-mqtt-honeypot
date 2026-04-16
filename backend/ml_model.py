from __future__ import annotations

from pathlib import Path
from typing import Optional

import joblib
import pandas as pd

from backend.schemas import FeatureEvent, MlDecision

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "artifacts" / "model.pkl"


class ModelService:
    def __init__(self) -> None:
        self.model = None
        self.labels: list[str] = []
        self.reload()

    def reload(self) -> None:
        if MODEL_PATH.exists():
            self.model = joblib.load(MODEL_PATH)
        else:
            self.model = None

    @property
    def available(self) -> bool:
        return self.model is not None

    def predict(self, features: FeatureEvent) -> Optional[MlDecision]:
        if self.model is None:
            return None

        frame = pd.DataFrame(
            [
                {
                    "connect_rate": features.connect_rate,
                    "message_rate": features.message_rate,
                    "topic_count": features.topic_count,
                    "avg_payload_size": features.avg_payload_size,
                    "failed_auth_count": features.failed_auth_count,
                }
            ]
        )

        prediction = self.model.predict(frame)[0]
        confidence = 0.55

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(frame)[0]
            confidence = float(max(probabilities))

        return MlDecision(
            predicted_attack_type=str(prediction),
            confidence=round(confidence, 2),
        )

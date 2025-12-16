"""Train a toy malware detector and persist the pipeline."""
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import pickle

MODEL_PATH = Path(__file__).resolve().parent.parent / "model.pkl"


def build_synthetic_dataset(samples: int = 1500) -> pd.DataFrame:
    """Create synthetic telemetry that mixes benign and malicious patterns."""
    rng = np.random.default_rng(42)
    packet_rate = rng.uniform(20, 1200, size=samples)
    anomaly_score = rng.beta(2, 5, size=samples) * 100
    urgent_flag = rng.choice([0, 1], size=samples, p=[0.85, 0.15])
    threat = ((packet_rate > 400) | (anomaly_score > 60) | urgent_flag).astype(int)
    return pd.DataFrame(
        {
            "packet_rate": packet_rate,
            "anomaly_score": anomaly_score,
            "urgent_flag": urgent_flag,
            "threat": threat,
        }
    )


def train_pipeline(data: pd.DataFrame) -> Pipeline:
    """Train a simple model on the synthetic data."""
    features = data[["packet_rate", "anomaly_score", "urgent_flag"]]
    labels = data["threat"]
    pipeline = Pipeline(
        [
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(solver="liblinear", class_weight="balanced", random_state=42)),
        ]
    )
    pipeline.fit(features, labels)
    return pipeline


def main() -> None:
    data = build_synthetic_dataset()
    pipeline = train_pipeline(data)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb") as out:
        pickle.dump(pipeline, out)
    print("Model saved to", MODEL_PATH)


if __name__ == "__main__":
    main()

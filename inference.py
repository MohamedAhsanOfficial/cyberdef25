"""Bundle that runs malware inference over log files."""
from __future__ import annotations

import argparse
import logging
import pickle
from pathlib import Path
from typing import Iterable

import pandas as pd

INPUT_DIR = Path("/input/logs")
OUTPUT_DIR = Path("/output")
MODEL_PATH = Path(__file__).resolve().with_name("model.pkl")


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_model() -> object:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model file missing at {MODEL_PATH}")
    with MODEL_PATH.open("rb") as model_stream:
        return pickle.load(model_stream)


def list_log_files(directory: Path) -> Iterable[Path]:
    if not directory.exists():
        logging.warning("Input directory %s does not exist", directory)
        return []
    return sorted(directory.glob("*.csv"))


def read_logs(paths: Iterable[Path]) -> pd.DataFrame:
    frames = []
    for path in paths:
        try:
            frames.append(pd.read_csv(path))
        except Exception as exc:
            logging.warning("Skipping %s (%s)", path.name, exc)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True).reset_index(drop=True)


def ensure_features(logs: pd.DataFrame) -> pd.DataFrame:
    logs["packet_rate"] = pd.to_numeric(logs.get("packet_rate", 0), errors="coerce").fillna(0)
    logs["anomaly_score"] = pd.to_numeric(logs.get("anomaly_score", 0), errors="coerce").fillna(0)
    logs["urgent_flag"] = pd.to_numeric(logs.get("urgent_flag", 0), errors="coerce").fillna(0)
    return logs


def emit_alerts(logs: pd.DataFrame, model: object, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    feature_cols = ["packet_rate", "anomaly_score", "urgent_flag"]
    predictions = model.predict(logs[feature_cols])
    proba = model.predict_proba(logs[feature_cols])

    results = logs.assign(
        alert=predictions.astype(bool),
        threat_score=proba[:, 1],
    )

    target_columns = [
        col for col in ["timestamp", "src_ip", "dest_ip", "protocol"] if col in results.columns
    ]
    target_columns += ["packet_rate", "anomaly_score", "urgent_flag", "alert", "threat_score"]
    results = results.loc[:, target_columns]
    results.to_csv(output, index=False)
    logging.info("Alerts written to %s (rows=%d)", output, len(results))


def run(input_dir: Path, output_file: Path) -> None:
    model = load_model()
    log_paths = list_log_files(input_dir)
    logs = read_logs(log_paths)
    if logs.empty:
        logging.warning("No log data found under %s", input_dir)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame().to_csv(output_file, index=False)
        return
    logs = ensure_features(logs)
    emit_alerts(logs, model, output_file)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the malware inference pipeline")
    parser.add_argument("--input", type=Path, default=INPUT_DIR, help="Folder containing log CSVs")
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR / "alerts.csv", help="Target CSV")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    logging.info("Loading logs from %s", args.input)
    run(args.input, args.output)


if __name__ == "__main__":
    main()

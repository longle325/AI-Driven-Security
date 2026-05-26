from __future__ import annotations

from dataclasses import dataclass

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from src.config import ensure_directories, settings
from src.data_loader import normalize_dataframe, save_processed_dataset
from src.feature_engineering import feature_matrix


@dataclass
class ProcessedData:
    x_train: pd.DataFrame
    x_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    label_encoder: LabelEncoder
    scaler: StandardScaler


def prepare_training_data(df: pd.DataFrame, test_size: float = 0.25, random_state: int = 42) -> ProcessedData:
    ensure_directories()
    clean = normalize_dataframe(df)
    x = feature_matrix(clean)
    labels = clean["label"].astype(str)

    label_encoder = LabelEncoder()
    y = pd.Series(label_encoder.fit_transform(labels), name="label")

    stratify = y if y.nunique() > 1 and y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    scaler = StandardScaler()
    scaler.fit(x_train)
    joblib.dump(label_encoder, settings.label_encoder_path)
    joblib.dump(scaler, settings.scaler_path)

    train_df = x_train.copy()
    train_df["label"] = y_train.values
    test_df = x_test.copy()
    test_df["label"] = y_test.values
    train_df.to_csv(settings.processed_data_dir / "train.csv", index=False)
    test_df.to_csv(settings.processed_data_dir / "test.csv", index=False)
    save_processed_dataset(clean)

    return ProcessedData(x_train, x_test, y_train, y_test, label_encoder, scaler)

import pandas as pd

from src.data_loader import normalize_dataframe
from src.download_dataset import _sample_rows


def test_cicids_labels_and_flow_features_are_mapped_to_lab_schema():
    df = pd.DataFrame(
        [
            {
                "Destination Port": 80,
                "Flow Duration": 1000000,
                "Total Fwd Packets": 12,
                "Total Length of Fwd Packets": 4800,
                "Flow Packets/s": 180.0,
                "Flow Bytes/s": 22000.0,
                "Flow IAT Mean": 5500.0,
                "Flow IAT Std": 1200.0,
                "Fwd Packet Length Max": 900,
                "Bwd Packet Length Max": 1200,
                "Packet Length Mean": 480.0,
                "Packet Length Std": 260.0,
                "Packet Length Variance": 67600.0,
                "PSH Flag Count": 1,
                "ACK Flag Count": 1,
                "FIN Flag Count": 0,
                "Attack Type": "Web Attacks",
            },
            {
                "Destination Port": 4444,
                "Flow Duration": 300000,
                "Total Fwd Packets": 4,
                "Total Length of Fwd Packets": 240,
                "Flow Packets/s": 90.0,
                "Flow Bytes/s": 1200.0,
                "Flow IAT Mean": 1000.0,
                "Flow IAT Std": 400.0,
                "Packet Length Mean": 60.0,
                "Packet Length Std": 20.0,
                "Packet Length Variance": 400.0,
                "Attack Type": "Port Scanning",
            },
        ]
    )

    normalized = normalize_dataframe(df)

    assert normalized["label"].tolist() == ["web_attack", "port_scan"]
    assert normalized.loc[0, "payload_risk_score"] > 0
    assert normalized.loc[1, "unique_ports_1m"] > 0
    assert normalized.loc[0, "event_type"] == "network_flow"


def test_sampler_keeps_only_ids2025_taxonomy_labels(tmp_path):
    source = tmp_path / "source.csv"
    output = tmp_path / "sample.csv"
    pd.DataFrame(
        [
            {"Destination Port": 80, "Flow Packets/s": 12, "Attack Type": "Normal Traffic"},
            {"Destination Port": 443, "Flow Packets/s": 18, "Attack Type": "Web Attacks"},
            {"Destination Port": 4444, "Flow Packets/s": 30, "Attack Type": "Port Scanning"},
            {"Destination Port": 53, "Flow Packets/s": 4, "Attack Type": "Infiltration"},
        ]
    ).to_csv(source, index=False)

    info = _sample_rows(source, output, per_label=1, chunksize=2)

    assert info["rows"] == 3
    assert info["label_counts"] == {"normal": 1, "web_attack": 1, "infiltration": 1}

import pandas as pd

from src.data_loader import normalize_dataframe, normalize_label
from src.download_dataset import _sample_rows_from_files


def test_ids2025_labels_and_flow_columns_map_to_lab_schema():
    df = pd.DataFrame(
        [
            {
                "Dst Port": 443,
                "Protocol": 6,
                "Timestamp": "02/03/2018 09:21:10",
                "Tot Fwd Pkts": 18,
                "Flow Pkts/s": 880.0,
                "Flow IAT Mean": 850.0,
                "Flow IAT Std": 250.0,
                "Pkt Len Mean": 420.0,
                "Pkt Len Std": 190.0,
                "Pkt Len Var": 36100.0,
                "Fwd Pkt Len Max": 920,
                "Bwd Pkt Len Max": 1400,
                "PSH Flag Cnt": 1,
                "Label": "Bot",
            },
            {
                "Dst Port": 80,
                "Protocol": 6,
                "Timestamp": "22/02/2018 11:00:12",
                "Tot Fwd Pkts": 8,
                "Flow Pkts/s": 210.0,
                "Flow IAT Mean": 1200.0,
                "Flow IAT Std": 300.0,
                "Pkt Len Mean": 360.0,
                "Pkt Len Std": 250.0,
                "Pkt Len Var": 62500.0,
                "Fwd Pkt Len Max": 870,
                "Label": "SQL Injection",
            },
            {
                "Dst Port": 22,
                "Protocol": 6,
                "Timestamp": "28/02/2018 12:00:00",
                "Tot Fwd Pkts": 40,
                "Flow Pkts/s": 120.0,
                "Flow IAT Mean": 4000.0,
                "Flow IAT Std": 2000.0,
                "Pkt Len Mean": 140.0,
                "Pkt Len Std": 90.0,
                "Pkt Len Var": 8100.0,
                "Label": "Infilteration",
            },
        ]
    )

    normalized = normalize_dataframe(df)

    assert normalized["label"].tolist() == ["botnet", "web_attack", "infiltration"]
    assert normalized.loc[0, "endpoint"] == "/port/443"
    assert normalized.loc[0, "request_count_1m"] > 0
    assert normalized.loc[1, "payload_risk_score"] > 0
    assert normalized.loc[2, "failed_login_count_5m"] > 0


def test_ids2025_sampler_balances_multiple_csv_files(tmp_path):
    first = tmp_path / "bot.csv"
    second = tmp_path / "web.csv"
    output = tmp_path / "sample.csv"
    pd.DataFrame(
        [
            {"Dst Port": 443, "Flow Pkts/s": 120, "Label": "Benign"},
            {"Dst Port": 443, "Flow Pkts/s": 900, "Label": "Bot"},
            {"Dst Port": 443, "Flow Pkts/s": 910, "Label": "Bot"},
        ]
    ).to_csv(first, index=False)
    pd.DataFrame(
        [
            {"Dst Port": 80, "Flow Pkts/s": 200, "Label": "SQL Injection"},
            {"Dst Port": 80, "Flow Pkts/s": 210, "Label": "Brute Force -XSS"},
            {"Dst Port": 22, "Flow Pkts/s": 40, "Label": "SSH-Bruteforce"},
        ]
    ).to_csv(second, index=False)

    info = _sample_rows_from_files([first, second], output, per_label=1, chunksize=2)

    assert info["rows"] == 4
    assert info["label_counts"] == {"normal": 1, "botnet": 1, "web_attack": 1, "brute_force": 1}
    assert output.exists()


def test_ids2025_original_labels_collapse_to_demo_taxonomy():
    labels = {
        "Benign": "normal",
        "Bot": "botnet",
        "FTP-BruteForce": "brute_force",
        "SSH-Bruteforce": "brute_force",
        "DDoS attacks-LOIC-HTTP": "dos_ddos",
        "DDOS attack-HOIC": "dos_ddos",
        "DoS attacks-Hulk": "dos_ddos",
        "Infilteration": "infiltration",
        "Brute Force -Web": "web_attack",
        "Brute Force -XSS": "web_attack",
        "SQL Injection": "web_attack",
    }

    assert {raw: normalize_label(raw) for raw in labels} == labels

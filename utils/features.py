from typing import List, Dict, Any
import os

import numpy as np
import pandas as pd

try:
    from joblib import load as joblib_load
except Exception:  # pragma: no cover
    joblib_load = None


FEATURE_COLUMNS = [
    "length",
    "is_icmp",
    "is_tcp",
    "is_udp",
    "syn_flag",
    "ack_flag",
    "fin_flag",
    "rst_flag",
    "src_count",
    "dst_count",
    "icmp_type",
]


class ModelManager:
    def __init__(self, icmp_model_path: str, tcp_model_path: str, udp_model_path: str):
        self.paths = {
            "ICMP": icmp_model_path,
            "TCP": tcp_model_path,
            "UDP": udp_model_path,
        }
        self.models = {k: self._safe_load(v) for k, v in self.paths.items()}

    def _safe_load(self, path: str):
        try:
            if os.path.exists(path) and joblib_load is not None:
                return joblib_load(path)
        except Exception:
            return None
        return None

    def predict(self, features_df: pd.DataFrame) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        # split by protocol flag columns
        for idx, row in features_df.iterrows():
            proto = "ICMP" if row.get("is_icmp") else ("TCP" if row.get("is_tcp") else ("UDP" if row.get("is_udp") else ""))
            model = self.models.get(proto)
            pred = None
            proba = None
            if model is not None:
                try:
                    # Select intersection of expected columns if model has feature_names_in_
                    cols = FEATURE_COLUMNS
                    if hasattr(model, "feature_names_in_"):
                        cols = [c for c in FEATURE_COLUMNS if c in model.feature_names_in_]
                    x = pd.DataFrame([row.to_dict()])[cols]
                    pred_value = model.predict(x)[0]
                    pred = int(pred_value) if isinstance(pred_value, (int, np.integer)) else int(float(pred_value))
                    if hasattr(model, "predict_proba"):
                        proba_arr = model.predict_proba(x)[0]
                        proba = float(np.max(proba_arr))
                except Exception:
                    pred = None
                    proba = None
            results.append({"index": int(idx), "protocol": proto, "prediction": pred, "confidence": proba})
        return results


def _flag_bits(flags: Any) -> Dict[str, int]:
    s = str(flags or "").upper()
    return {
        "syn_flag": 1 if "S" in s and "A" not in s else 0,
        "ack_flag": 1 if "A" in s else 0,
        "fin_flag": 1 if "F" in s else 0,
        "rst_flag": 1 if "R" in s else 0,
    }


def build_features_dataframe(packets: List[Dict[str, Any]]) -> pd.DataFrame:
    # frequency counts per src/dst
    src_counts: Dict[str, int] = {}
    dst_counts: Dict[str, int] = {}
    for p in packets:
        if p.get("src"):
            src_counts[p["src"]] = src_counts.get(p["src"], 0) + 1
        if p.get("dst"):
            dst_counts[p["dst"]] = dst_counts.get(p["dst"], 0) + 1

    rows = []
    for p in packets:
        flags = _flag_bits(p.get("flags"))
        rows.append({
            "length": p.get("length") or 0,
            "is_icmp": 1 if p.get("protocol") == "ICMP" else 0,
            "is_tcp": 1 if p.get("protocol") == "TCP" else 0,
            "is_udp": 1 if p.get("protocol") == "UDP" else 0,
            **flags,
            "src_count": src_counts.get(p.get("src"), 0),
            "dst_count": dst_counts.get(p.get("dst"), 0),
            "icmp_type": p.get("icmp_type") or 0,
        })
    df = pd.DataFrame(rows)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df[FEATURE_COLUMNS]


def generate_alerts(packets: List[Dict[str, Any]], predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    # Heuristics for spikes by source and protocol
    src_counts: Dict[str, int] = {}
    tcp_syn_counts: Dict[str, int] = {}
    udp_counts: Dict[str, int] = {}
    icmp_echo_counts: Dict[str, int] = {}

    for p in packets:
        src = p.get("src")
        proto = p.get("protocol")
        if not src or not proto:
            continue
        src_counts[src] = src_counts.get(src, 0) + 1
        if proto == "TCP":
            flags = str(p.get("flags") or "").upper()
            if "S" in flags and "A" not in flags:
                tcp_syn_counts[src] = tcp_syn_counts.get(src, 0) + 1
        elif proto == "UDP":
            udp_counts[src] = udp_counts.get(src, 0) + 1
        elif proto == "ICMP":
            if (p.get("icmp_type") == 8) or ("ECHO" in str(p.get("info") or "").upper()):
                icmp_echo_counts[src] = icmp_echo_counts.get(src, 0) + 1

    def add_alert(msg: str, severity: str, meta: Dict[str, Any]):
        alerts.append({"message": msg, "severity": severity, **meta})

    # Thresholds (can be tuned)
    for src, c in sorted(tcp_syn_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        if c >= 500:
            add_alert(f"Possible SYN Flood detected from {src}: {c} SYN packets", "high", {"type": "tcp_syn"})
        elif c >= 200:
            add_alert(f"Elevated SYN activity from {src}: {c} packets", "medium", {"type": "tcp_syn"})

    for src, c in sorted(udp_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        if c >= 1000:
            add_alert(f"UDP flood from {src}: {c} packets", "high", {"type": "udp_flood"})
        elif c >= 400:
            add_alert(f"High UDP rate from {src}: {c} packets", "medium", {"type": "udp_rate"})

    for src, c in sorted(icmp_echo_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        if c >= 800:
            add_alert(f"ICMP echo storm from {src}: {c} requests", "high", {"type": "icmp_echo"})
        elif c >= 300:
            add_alert(f"High ICMP echo rate from {src}: {c} requests", "medium", {"type": "icmp_echo"})

    # Incorporate model predictions if present
    suspicious = sum(1 for r in predictions if (r.get("prediction") == 1))
    if suspicious >= 1000:
        alerts.append({"message": f"ML models flagged {suspicious} suspicious packets", "severity": "high", "type": "ml"})
    elif suspicious >= 200:
        alerts.append({"message": f"ML models flagged {suspicious} suspicious packets", "severity": "medium", "type": "ml"})

    return alerts



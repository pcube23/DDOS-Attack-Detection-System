import os
from datetime import datetime
from typing import List, Dict, Any

import pandas as pd

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except Exception:  # pragma: no cover
    rdpcap = None
    IP = TCP = UDP = ICMP = None


def _normalize_time(ts) -> Dict[str, Any]:
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.utcfromtimestamp(float(ts))
        else:
            dt = pd.to_datetime(ts, utc=True).to_pydatetime()
        bucket = dt.replace(microsecond=0)
        return {"time": dt.timestamp(), "time_iso": dt.isoformat().replace("+00:00", "Z"), "time_bucket": bucket.isoformat().replace("+00:00", "Z")}
    except Exception:
        return {"time": None, "time_iso": None, "time_bucket": None}


def _protocol_from_row(row: Dict[str, Any]) -> str:
    proto = str(row.get("protocol") or row.get("Protocol") or "").upper()
    if proto in ("ICMP", "TCP", "UDP"):
        return proto
    # try via flags or ports
    if str(row.get("flags") or row.get("Flags") or "").upper() in ("S", "SA", "FA", "R", "P", "F"):
        return "TCP"
    if pd.notna(row.get("icmp_type")):
        return "ICMP"
    if pd.notna(row.get("src_port")) or pd.notna(row.get("dst_port")):
        return "UDP"
    return ""


def parse_csv(path: str) -> List[Dict[str, Any]]:
    df = pd.read_csv(path)
    packets: List[Dict[str, Any]] = []
    for _, r in df.iterrows():
        src = r.get("src") or r.get("Source") or r.get("ip.src")
        dst = r.get("dst") or r.get("Destination") or r.get("ip.dst")
        length = r.get("length") or r.get("Length") or r.get("frame.len")
        flags = r.get("flags") or r.get("Flags")
        info = r.get("info") or r.get("Info")
        time_val = r.get("time") or r.get("Time") or r.get("frame.time_epoch")
        time_meta = _normalize_time(time_val)
        proto = _protocol_from_row(r)
        packets.append({
            **time_meta,
            "src": None if pd.isna(src) else str(src),
            "dst": None if pd.isna(dst) else str(dst),
            "protocol": proto,
            "length": None if pd.isna(length) else int(float(length)),
            "flags": None if pd.isna(flags) else str(flags),
            "info": None if pd.isna(info) else str(info),
            "src_port": None if pd.isna(r.get("src_port")) else int(r.get("src_port")),
            "dst_port": None if pd.isna(r.get("dst_port")) else int(r.get("dst_port")),
            "icmp_type": None if pd.isna(r.get("icmp_type")) else int(r.get("icmp_type")),
        })
    return packets


def parse_pcap(path: str) -> List[Dict[str, Any]]:
    if rdpcap is None:
        return []
    packets: List[Dict[str, Any]] = []
    try:
        pkts = rdpcap(path)
    except Exception:
        return packets

    for p in pkts:
        if IP is None or not p.haslayer(IP):
            continue
        ip = p[IP]
        src = ip.src
        dst = ip.dst
        length = int(len(p))
        ts = getattr(p, "time", None)
        time_meta = _normalize_time(ts)
        proto = ""
        flags = None
        info = None
        src_port = None
        dst_port = None
        icmp_type = None
        if p.haslayer(TCP):
            proto = "TCP"
            tcp = p[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = str(tcp.flags)
        elif p.haslayer(UDP):
            proto = "UDP"
            udp = p[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
        elif p.haslayer(ICMP):
            proto = "ICMP"
            icmp = p[ICMP]
            icmp_type = int(getattr(icmp, "type", 0))

        packets.append({
            **time_meta,
            "src": src,
            "dst": dst,
            "protocol": proto,
            "length": length,
            "flags": flags,
            "info": info,
            "src_port": src_port,
            "dst_port": dst_port,
            "icmp_type": icmp_type,
        })
    return packets


def detect_extension(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def parse_files_to_packets(paths: List[str]) -> List[Dict[str, Any]]:
    all_packets: List[Dict[str, Any]] = []
    for p in paths:
        ext = detect_extension(p)
        if ext == ".csv":
            all_packets.extend(parse_csv(p))
        elif ext in (".pcap", ".pcapng"):
            all_packets.extend(parse_pcap(p))
    # sort by time if available
    all_packets.sort(key=lambda x: (x.get("time") or 0))
    return all_packets


def summarize_packets(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(packets)
    protos = {"ICMP": 0, "TCP": 0, "UDP": 0}
    srcs = set()
    dsts = set()
    times = [p.get("time") for p in packets if p.get("time") is not None]
    for p in packets:
        proto = p.get("protocol")
        if proto in protos:
            protos[proto] += 1
        if p.get("src"):
            srcs.add(p["src"])
        if p.get("dst"):
            dsts.add(p["dst"])
    duration = 0
    if times:
        duration = max(times) - min(times)
    return {
        "total_packets": total,
        "duration_seconds": duration,
        "protocol_ratio": protos,
        "unique_sources": len(srcs),
        "unique_dests": len(dsts),
    }



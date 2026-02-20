import os
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Packet


BASE = os.path.dirname(os.path.dirname(__file__))
OUT = os.path.join(BASE, "samples")
os.makedirs(OUT, exist_ok=True)


def set_time(pkt: Packet, t: float) -> Packet:
    pkt.time = t
    return pkt


def build_icmp_packets(start: float):
    return [
        set_time(IP(src="192.168.0.10", dst="10.0.0.5")/ICMP(type=8)/b"ping1", start+0),
        set_time(IP(src="192.168.0.11", dst="10.0.0.5")/ICMP(type=8)/b"ping2", start+1),
        set_time(IP(src="192.168.0.12", dst="10.0.0.6")/ICMP(type=0)/b"pong", start+2),
        set_time(IP(src="192.168.0.13", dst="10.0.0.6")/ICMP(type=8)/b"ping3", start+3),
        set_time(IP(src="192.168.0.10", dst="10.0.0.7")/ICMP(type=8)/b"ping4", start+4),
    ]


def build_tcp_packets(start: float):
    return [
        set_time(IP(src="192.168.0.20", dst="10.0.0.10")/TCP(sport=54321, dport=80, flags="S"), start+0),
        set_time(IP(src="192.168.0.20", dst="10.0.0.10")/TCP(sport=54322, dport=80, flags="S"), start+1),
        set_time(IP(src="10.0.0.10", dst="192.168.0.20")/TCP(sport=80, dport=54321, flags="SA"), start+2),
        set_time(IP(src="192.168.0.21", dst="10.0.0.11")/TCP(sport=50100, dport=443, flags="PA")/b"GET /", start+3),
        set_time(IP(src="192.168.0.22", dst="10.0.0.12")/TCP(sport=50101, dport=22, flags="R"), start+4),
    ]


def build_udp_packets(start: float):
    return [
        set_time(IP(src="192.168.0.30", dst="10.0.0.20")/UDP(sport=53000, dport=53)/b"dns", start+0),
        set_time(IP(src="192.168.0.31", dst="10.0.0.21")/UDP(sport=53001, dport=9999)/("X"*110), start+1),
        set_time(IP(src="192.168.0.30", dst="10.0.0.20")/UDP(sport=53002, dport=53)/b"dns", start+2),
        set_time(IP(src="192.168.0.32", dst="10.0.0.22")/UDP(sport=53003, dport=123)/b"ntp", start+3),
        set_time(IP(src="192.168.0.33", dst="10.0.0.23")/UDP(sport=53004, dport=5555)/b"udp", start+4),
    ]


def build_icmp_packets_25(start: float):
    pkts = []
    for i in range(25):
        src_oct = 10 + (i % 50)
        dst_oct = 5 + (i % 20)
        icmp_type = 8 if i % 5 != 2 else 0  # mostly echo request, some replies
        payload = f"icmp{i}".encode()
        pkts.append(set_time(IP(src=f"192.168.0.{src_oct}", dst=f"10.0.0.{dst_oct}")/ICMP(type=icmp_type)/payload, start + i))
    return pkts


def build_tcp_packets_25(start: float):
    pkts = []
    for i in range(25):
        src_oct = 20 + (i % 50)
        dst_oct = 10 + (i % 20)
        dport = 80 if i % 4 == 0 else (22 if i % 4 == 1 else (443 if i % 4 == 2 else 25))
        flags = "S" if i % 5 in (0,1) else ("SA" if i % 5 == 2 else ("PA" if i % 5 == 3 else "R"))
        sport = 54000 + i
        layer = TCP(sport=sport, dport=dport, flags=flags)
        pkt = IP(src=f"192.168.0.{src_oct}", dst=f"10.0.0.{dst_oct}")/layer
        if "P" in flags:
            pkt = pkt/ b"data"
        pkts.append(set_time(pkt, start + i))
    return pkts


def build_udp_packets_25(start: float):
    pkts = []
    for i in range(25):
        src_oct = 40 + (i % 50)
        dst_oct = 30 + (i % 20)
        dport = 53 if i % 5 in (0,2,4) else (123 if i % 5 == 3 else 9999)
        sport = 53100 + i
        payload_len = 64 if dport == 53 else (90 if dport == 123 else 120)
        payload = bytes([88]) * (payload_len - 8 if payload_len > 8 else 1)
        pkts.append(set_time(IP(src=f"192.168.0.{src_oct}", dst=f"10.0.0.{dst_oct}")/UDP(sport=sport, dport=dport)/payload, start + i))
    return pkts


def main():
    now = datetime(2024, 11, 5).timestamp()
    icmp = build_icmp_packets(now)
    tcp = build_tcp_packets(now)
    udp = build_udp_packets(now)
    wrpcap(os.path.join(OUT, "icmp.pcap"), icmp)
    wrpcap(os.path.join(OUT, "tcp.pcap"), tcp)
    wrpcap(os.path.join(OUT, "udp.pcap"), udp)
    print(f"PCAPs written to {OUT}")
    # 25-packet variants
    icmp25 = build_icmp_packets_25(now + 100)
    tcp25 = build_tcp_packets_25(now + 100)
    udp25 = build_udp_packets_25(now + 100)
    wrpcap(os.path.join(OUT, "icmp_25.pcap"), icmp25)
    wrpcap(os.path.join(OUT, "tcp_25.pcap"), tcp25)
    wrpcap(os.path.join(OUT, "udp_25.pcap"), udp25)
    print("25-packet PCAPs written.")

    # 75 / 63 / 80 variants
    icmp75 = build_icmp_packets_25(now + 200) + build_icmp_packets_25(now + 230) + build_icmp_packets_25(now + 260)
    tcp63 = build_tcp_packets_25(now + 300) + build_tcp_packets_25(now + 330) + build_tcp_packets_25(now + 360)[:13]
    udp80 = build_udp_packets_25(now + 400) + build_udp_packets_25(now + 430) + build_udp_packets_25(now + 460) + build_udp_packets_25(now + 490)[:5]
    wrpcap(os.path.join(OUT, "icmp_75.pcap"), icmp75)
    wrpcap(os.path.join(OUT, "tcp_63.pcap"), tcp63)
    wrpcap(os.path.join(OUT, "udp_80.pcap"), udp80)
    print("75/63/80 packet PCAPs written.")

    # Threat builders
    def build_icmp_storm(count: int, start_ts: float, src_prefix: str = "192.168.99.", dst: str = "10.0.99.9"):
        pkts = []
        for i in range(count):
            src_oct = 10 + (i % 50)
            pkt = IP(src=f"{src_prefix}{src_oct}", dst=dst)/ICMP(type=8)/("E"*48)
            pkts.append(set_time(pkt, start_ts + i*0.02))
        return pkts

    def build_tcp_syn_flood(count: int, start_ts: float, dst: str = "10.0.88.8", dport: int = 80):
        pkts = []
        for i in range(count):
            src_oct = 20 + (i % 200)
            sport = 40000 + (i % 20000)
            pkt = IP(src=f"192.168.88.{src_oct}", dst=dst)/TCP(sport=sport, dport=dport, flags="S")
            pkts.append(set_time(pkt, start_ts + i*0.01))
        return pkts

    def build_udp_flood(count: int, start_ts: float, dst: str = "10.0.77.7", dport: int = 1900):
        pkts = []
        for i in range(count):
            src_oct = 30 + (i % 200)
            sport = 50000 + (i % 10000)
            payload = b"X" * (100 + (i % 200))  # varying payload
            pkt = IP(src=f"192.168.77.{src_oct}", dst=dst)/UDP(sport=sport, dport=dport)/payload
            pkts.append(set_time(pkt, start_ts + i*0.015))
        return pkts

    # Write threat PCAPs
    t0 = now + 600
    icmp50 = build_icmp_storm(50, t0)
    tcp100 = build_tcp_syn_flood(100, t0 + 10)
    udp83 = build_udp_flood(83, t0 + 20)
    icmp63 = build_icmp_storm(63, t0 + 30)
    udp59 = build_udp_flood(59, t0 + 40)
    tcp88 = build_tcp_syn_flood(88, t0 + 50)

    wrpcap(os.path.join(OUT, "icmp_threat_50.pcap"), icmp50)
    wrpcap(os.path.join(OUT, "tcp_threat_100.pcap"), tcp100)
    wrpcap(os.path.join(OUT, "udp_threat_83.pcap"), udp83)
    wrpcap(os.path.join(OUT, "icmp_threat_63.pcap"), icmp63)
    wrpcap(os.path.join(OUT, "udp_threat_59.pcap"), udp59)
    wrpcap(os.path.join(OUT, "tcp_threat_88.pcap"), tcp88)
    print("Threat PCAPs (SYN flood / UDP flood / ICMP storm) written.")

    # Also write CSV equivalents
    import csv
    def write_csv(path: str, rows):
        fields = ["time","src","dst","protocol","length","flags","info","src_port","dst_port","icmp_type"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def packets_to_rows(packets):
        rows = []
        for p in packets:
            ts = getattr(p, 'time', t0)
            length = len(bytes(p))
            src = p[IP].src if p.haslayer(IP) else ''
            dst = p[IP].dst if p.haslayer(IP) else ''
            if p.haslayer(TCP):
                proto = 'TCP'
                flags = str(p[TCP].flags)
                rows.append({"time": ts, "src": src, "dst": dst, "protocol": proto, "length": length, "flags": flags, "info": "SYN" if 'S' in flags and 'A' not in flags else '', "src_port": int(p[TCP].sport), "dst_port": int(p[TCP].dport), "icmp_type": ''})
            elif p.haslayer(UDP):
                proto = 'UDP'
                rows.append({"time": ts, "src": src, "dst": dst, "protocol": proto, "length": length, "flags": '', "info": "High-rate UDP", "src_port": int(p[UDP].sport), "dst_port": int(p[UDP].dport), "icmp_type": ''})
            elif p.haslayer(ICMP):
                proto = 'ICMP'
                rows.append({"time": ts, "src": src, "dst": dst, "protocol": proto, "length": length, "flags": '', "info": "Echo request", "src_port": '', "dst_port": '', "icmp_type": int(getattr(p[ICMP], 'type', 8))})
        return rows

    write_csv(os.path.join(OUT, "icmp_threat_50.csv"), packets_to_rows(icmp50))
    write_csv(os.path.join(OUT, "tcp_threat_100.csv"), packets_to_rows(tcp100))
    write_csv(os.path.join(OUT, "udp_threat_83.csv"), packets_to_rows(udp83))
    write_csv(os.path.join(OUT, "icmp_threat_63.csv"), packets_to_rows(icmp63))
    write_csv(os.path.join(OUT, "udp_threat_59.csv"), packets_to_rows(udp59))
    write_csv(os.path.join(OUT, "tcp_threat_88.csv"), packets_to_rows(tcp88))
    print("Threat CSVs written in samples/.")


if __name__ == "__main__":
    main()



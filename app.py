import os
import uuid
from datetime import datetime
from typing import Dict, Any, List

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS

from utils.parser import parse_files_to_packets, summarize_packets
from utils.features import ModelManager, build_features_dataframe, generate_alerts
from utils.report import generate_pdf_report, generate_csv_report


app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
CORS(app)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-memory analysis cache by session
ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}
ANALYSIS_HISTORY: Dict[str, List[Dict[str, Any]]] = {}


def get_session_id() -> str:
    if "sid" not in session:
        session["sid"] = uuid.uuid4().hex
    return session["sid"]


model_manager = ModelManager(
    icmp_model_path=os.path.join(BASE_DIR, "models", "icmp_model.pkl"),
    tcp_model_path=os.path.join(BASE_DIR, "models", "tcp_model.pkl"),
    udp_model_path=os.path.join(BASE_DIR, "models", "udp_model.pkl"),
)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/upload")
def upload_page():
    return render_template("upload.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/inspector")
def inspector():
    return render_template("inspector.html")


@app.route("/reports")
def reports():
    return render_template("reports.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/manifest.json")
def manifest():
    return app.send_static_file("manifest.json")


@app.route("/service-worker.js")
def service_worker():
    return app.send_static_file("service-worker.js")


@app.post("/api/upload")
def api_upload():
    sid = get_session_id()
    if "files" not in request.files:
        return jsonify({"error": "No files part in request"}), 400

    files = request.files.getlist("files")
    saved_paths: List[str] = []
    for f in files:
        if not f.filename:
            continue
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in [".csv", ".pcap", ".pcapng"]:
            continue
        unique_name = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex}{ext}"
        dest = os.path.join(UPLOAD_DIR, unique_name)
        f.save(dest)
        saved_paths.append(dest)

    if not saved_paths:
        return jsonify({"error": "No valid files uploaded"}), 400

    packets = parse_files_to_packets(saved_paths)
    summary = summarize_packets(packets)

    # Build features and run predictions
    features_df = build_features_dataframe(packets)
    predictions = model_manager.predict(features_df)

    alerts = generate_alerts(packets, predictions)

    analysis = {
        "packets": packets,
        "summary": summary,
        "features": features_df.to_dict(orient="records"),
        "predictions": predictions,
        "alerts": alerts,
        "uploaded_files": [os.path.basename(p) for p in saved_paths],
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    ANALYSIS_CACHE[sid] = analysis
    ANALYSIS_HISTORY.setdefault(sid, []).append(analysis)

    return jsonify({
        "message": "Files uploaded and analyzed",
        "summary": summary,
        "alerts": alerts,
        "files": ANALYSIS_CACHE[sid]["uploaded_files"],
    })


@app.get("/api/overview")
def api_overview():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    return jsonify(data["summary"])


@app.get("/api/traffic")
def api_traffic():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    # Prepare timeseries packets per second by protocol
    packets: List[Dict[str, Any]] = data["packets"]
    buckets: Dict[str, Dict[str, int]] = {}
    for p in packets:
        ts = p.get("time_bucket")
        proto = p.get("protocol")
        if ts is None or proto is None:
            continue
        if ts not in buckets:
            buckets[ts] = {"ICMP": 0, "TCP": 0, "UDP": 0}
        if proto in buckets[ts]:
            buckets[ts][proto] += 1
    # Convert to list sorted by time
    series = [
        {"time": k, **v} for k, v in sorted(buckets.items(), key=lambda x: x[0])
    ]
    return jsonify(series)


@app.get("/api/top-sources")
def api_top_sources():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    counts: Dict[str, int] = {}
    for p in data["packets"]:
        src = p.get("src")
        if not src:
            continue
        counts[src] = counts.get(src, 0) + 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{"ip": ip, "count": count} for ip, count in top])


@app.get("/api/top-dests")
def api_top_dests():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    counts: Dict[str, int] = {}
    for p in data["packets"]:
        dst = p.get("dst")
        if not dst:
            continue
        counts[dst] = counts.get(dst, 0) + 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{"ip": ip, "count": count} for ip, count in top])


@app.get("/api/alerts")
def api_alerts():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    return jsonify({"alerts": data["alerts"], "generated_at": data.get("generated_at")})


@app.get("/api/insights")
def api_insights():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    s = data["summary"]
    pr = s.get("protocol_ratio", {})
    msgs = []
    # Simple GPT-like heuristic explanations
    if pr.get("TCP", 0) > pr.get("ICMP", 0) and pr.get("TCP", 0) > pr.get("UDP", 0):
        msgs.append("Traffic is TCP-dominant; watch for SYN floods (many SYN without ACK).")
    if pr.get("UDP", 0) > max(pr.get("TCP", 0), pr.get("ICMP", 0)):
        msgs.append("UDP volume is leading; high sustained UDP rates can indicate amplification attacks.")
    if pr.get("ICMP", 0) > 0 and pr.get("ICMP", 0) / max(s.get("total_packets", 1), 1) > 0.5:
        msgs.append("ICMP constitutes over half of traffic; check for echo request storms.")
    # Alert-derived insights
    for a in data.get("alerts", [])[:3]:
        if a.get("type") == "tcp_syn":
            msgs.append("Spike in SYN-only packets suggests potential SYN flood toward one or more hosts.")
        if a.get("type") == "udp_flood":
            msgs.append("High-rate UDP from single source suggests volumetric flood.")
        if a.get("type") == "icmp_echo":
            msgs.append("Many ICMP echo requests can saturate links and resources.")
    if not msgs:
        msgs = ["Traffic looks balanced with no dominant protocol spikes detected."]
    return jsonify({"insights": msgs[:5]})


@app.get("/api/compare")
def api_compare():
    sid = get_session_id()
    hist = ANALYSIS_HISTORY.get(sid, [])
    if len(hist) < 2:
        return jsonify({"error": "Need at least two analyses to compare."}), 400
    prev, curr = hist[-2], hist[-1]
    ps, cs = prev["summary"], curr["summary"]
    def diff_ratio(proto):
        pv = ps.get("protocol_ratio", {}).get(proto, 0)
        cv = cs.get("protocol_ratio", {}).get(proto, 0)
        return pv, cv, (cv - pv)
    total_diff = cs.get("total_packets", 0) - ps.get("total_packets", 0)
    udp_prev, udp_curr, udp_delta = diff_ratio("UDP")
    tcp_prev, tcp_curr, tcp_delta = diff_ratio("TCP")
    icmp_prev, icmp_curr, icmp_delta = diff_ratio("ICMP")
    messages = []
    if ps.get("total_packets", 0) > 0:
        change_pct = (total_diff / max(ps.get("total_packets", 1), 1)) * 100
        messages.append(f"Overall traffic changed by {change_pct:.1f}% compared to the previous upload.")
    if udp_prev > 0:
        udp_change = ((udp_curr - udp_prev) / udp_prev) * 100
        messages.append(f"UDP packets changed by {udp_change:.1f}% (prev {udp_prev}, now {udp_curr}).")
    if tcp_prev > 0:
        tcp_change = ((tcp_curr - tcp_prev) / tcp_prev) * 100
        messages.append(f"TCP packets changed by {tcp_change:.1f}% (prev {tcp_prev}, now {tcp_curr}).")
    if icmp_prev > 0:
        icmp_change = ((icmp_curr - icmp_prev) / icmp_prev) * 100
        messages.append(f"ICMP packets changed by {icmp_change:.1f}% (prev {icmp_prev}, now {icmp_curr}).")
    return jsonify({
        "previous": ps,
        "current": cs,
        "deltas": {
            "total_packets": total_diff,
            "udp": udp_delta,
            "tcp": tcp_delta,
            "icmp": icmp_delta,
        },
        "messages": messages
    })


@app.get("/api/packets")
def api_packets():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404

    # Filters
    protocol = request.args.get("protocol")
    src = request.args.get("src")
    dst = request.args.get("dst")
    start = request.args.get("start")
    end = request.args.get("end")

    def within(p):
        if protocol and p.get("protocol") != protocol:
            return False
        if src and p.get("src") != src:
            return False
        if dst and p.get("dst") != dst:
            return False
        if start and p.get("time_iso") and p["time_iso"] < start:
            return False
        if end and p.get("time_iso") and p["time_iso"] > end:
            return False
        return True

    filtered = [
        {
            "time": p.get("time_iso"),
            "src": p.get("src"),
            "dst": p.get("dst"),
            "protocol": p.get("protocol"),
            "length": p.get("length"),
            "flags": p.get("flags"),
            "info": p.get("info"),
        }
        for p in data["packets"] if within(p)
    ]
    return jsonify(filtered[:1000])  # limit


@app.post("/api/report/pdf")
def api_report_pdf():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    options = request.json if request.is_json else {}
    path = generate_pdf_report(data, options=options)
    return send_file(path, as_attachment=True)


@app.post("/api/report/csv")
def api_report_csv():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    path = generate_csv_report(data)
    return send_file(path, as_attachment=True)


@app.post("/api/report/xlsx")
def api_report_xlsx():
    sid = get_session_id()
    data = ANALYSIS_CACHE.get(sid)
    if not data:
        return jsonify({"error": "No analysis available. Upload files first."}), 404
    from utils.report import generate_xlsx_report
    path = generate_xlsx_report(data)
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)



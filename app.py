"""Flask API for single-event and bounded batch CyberGuard analysis."""

from flask import Flask, jsonify, request, send_from_directory

from cyberguard import CyberGuard


app = Flask(__name__, static_folder=".", static_url_path="")
guard = CyberGuard()


@app.get("/")
def project_page():
    return send_from_directory(".", "index.html")


@app.post("/api/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    event = str(payload.get("event", "")).strip()
    if not event:
        return jsonify({"error": "event is required"}), 400
    try:
        return jsonify(guard.assess(event).to_dict())
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


@app.post("/api/batch")
def analyze_batch():
    payload = request.get_json(silent=True) or {}
    events = payload.get("events", [])
    if not isinstance(events, list) or not events:
        return jsonify({"error": "events must be a non-empty list"}), 400
    if len(events) > 1_000:
        return jsonify({"error": "batch limit is 1,000 events"}), 400
    try:
        results = guard.assess_many(str(event) for event in events)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({
        "total": len(results),
        "malicious": sum(item.status == "Malicious" for item in results),
        "results": [item.to_dict() for item in results],
    })


if __name__ == "__main__":
    app.run(debug=True)

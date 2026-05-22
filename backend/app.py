from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timezone
import os
import ipaddress
import logging

app = Flask(__name__)

# Restricted to local access because this IDS is developed in a controlled lab environment
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:8080", "http://localhost:8080"]}})

# Logging configuration.
logging.basicConfig(level=logging.INFO)

# DB Configuration.
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "alerts.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

ALLOWED_SEVERITIES = ["Low", "Medium", "High"]
ADMIN_TOKEN = "change-this-token"


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    source_ip = db.Column(db.String(50), nullable=False, index=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)

    protocol = db.Column(db.String(20), nullable=True)
    threat_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="Medium", index=True)

    description = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description
        }


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_port(port):
    if port is None:
        return True

    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False


with app.app_context():
    db.create_all()


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Real-Time IDS Backend API is running",
        "endpoints": {
            "get_alerts": "/alerts",
            "create_alert": "/alerts",
            "stats": "/stats",
            "clear_alerts": "/alerts/clear"
        }
    })


@app.route("/alerts", methods=["GET"])
def get_alerts():
    limit = request.args.get("limit", default=100, type=int)

    if limit > 500:
        limit = 500

    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()

    return jsonify([alert.to_dict() for alert in alerts])


@app.route("/alerts", methods=["POST"])
def create_alert():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No valid JSON data provided"}), 400

    required_fields = ["source_ip", "threat_type", "description"]

    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    if not is_valid_ip(data["source_ip"]):
        return jsonify({"error": "Invalid source IP address"}), 400

    if data.get("destination_ip") and not is_valid_ip(data["destination_ip"]):
        return jsonify({"error": "Invalid destination IP address"}), 400

    if not is_valid_port(data.get("destination_port")):
        return jsonify({"error": "Invalid destination port"}), 400

    severity = data.get("severity", "Medium")

    if severity not in ALLOWED_SEVERITIES:
        return jsonify({
            "error": "Invalid severity value",
            "allowed_values": ALLOWED_SEVERITIES
        }), 400

    new_alert = Alert(
        source_ip=data.get("source_ip"),
        destination_ip=data.get("destination_ip"),
        destination_port=data.get("destination_port"),
        protocol=data.get("protocol"),
        threat_type=data.get("threat_type"),
        severity=severity,
        description=data.get("description")
    )

    try:
        db.session.add(new_alert)
        db.session.commit()
        logging.info(f"New alert created: {new_alert.threat_type} from {new_alert.source_ip}")

    except Exception as e:
        db.session.rollback()
        logging.error(f"Database error: {e}")
        return jsonify({"error": "Failed to save alert"}), 500

    return jsonify(new_alert.to_dict()), 201


@app.route("/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": Alert.query.count(),

        "attack_counts": {
            "syn_flood": Alert.query.filter_by(threat_type="SYN Flood").count(),
            "port_scan": Alert.query.filter_by(threat_type="Port Scan").count(),
            "icmp_ping_sweep": Alert.query.filter_by(threat_type="ICMP Ping Sweep").count()
        },

        "severity_counts": {
            "high": Alert.query.filter_by(severity="High").count(),
            "medium": Alert.query.filter_by(severity="Medium").count(),
            "low": Alert.query.filter_by(severity="Low").count()
        }
    })


@app.route("/alerts/clear", methods=["DELETE"])
def clear_alerts():
    token = request.headers.get("X-Admin-Token")

    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    deleted_count = Alert.query.delete()
    db.session.commit()

    logging.warning(f"All alerts cleared. Deleted alerts: {deleted_count}")

    return jsonify({
        "message": "All alerts cleared successfully",
        "deleted_alerts": deleted_count
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
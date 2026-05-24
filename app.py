import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from analyser import analyse_pcap
from threat_intel import enrich_threats_with_intel

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyse', methods=['POST'])  # gate: ignore — local analysis tool, unauthenticated POST by design, documented in Gate 2 trust boundary map
def analyse():
    """Upload and analyse a PCAP file"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Only .pcap, .pcapng, .cap allowed"}), 400

    # Save file securely
    filename = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{filename}"
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
    file.save(filepath)
    logger.info(f"File uploaded: {safe_filename}")

    try:
        # Run analysis
        results = analyse_pcap(filepath)

        if "error" in results:
            return jsonify(results), 500

        # Enrich with threat intelligence
        results["threats"] = enrich_threats_with_intel(results["threats"])

        # Count by severity
        high = sum(1 for t in results["threats"] if t["severity"] == "HIGH")
        medium = sum(1 for t in results["threats"] if t["severity"] == "MEDIUM")
        low = sum(1 for t in results["threats"] if t["severity"] == "LOW")

        results["summary"] = {
            "high": high,
            "medium": medium,
            "low": low,
            "total_threats": len(results["threats"])
        }

        # Save report
        report_filename = f"report_{timestamp}.json"
        report_path = os.path.join(REPORT_FOLDER, report_filename)
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Report saved: {report_filename}")

        return jsonify(results)

    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

@app.route('/reports')
def list_reports():
    """List all saved reports"""
    reports = []
    for f in os.listdir(REPORT_FOLDER):
        if f.endswith('.json'):
            reports.append(f)
    return jsonify({"reports": sorted(reports, reverse=True)})

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5001)
from flask import Blueprint, jsonify
import requests
import feedparser
from collections import defaultdict

statistics_bp = Blueprint('statistics_bp', __name__)

# ✅ CISA alerts route
@statistics_bp.route('/api/cisa-alerts')
def get_cisa_alerts():
    try:
        response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Flat list for ThreatFox recent IOCs (for simple entry cards)
@statistics_bp.route('/api/threatfox/raw')
def get_threatfox_raw():
    try:
        url = "https://threatfox.abuse.ch/api/v1/"
        payload = {"query": "get_recent"}
        headers = {"Content-Type": "application/json"}

        res = requests.post(url, json=payload, headers=headers)
        res.raise_for_status()

        data = res.json().get("data", [])
        flat_data = []
        for entry in data:
            flat_data.append({
                "ioc": entry.get("ioc"),
                "threat_type": entry.get("threat_type", "unknown").lower(),
                "malware": entry.get("malware", "Unknown"),
                "confidence": entry.get("confidence_level", "N/A"),
                "reference": entry.get("reference"),
                "tags": entry.get("malware_alias", [])
            })

        return jsonify(flat_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Grouped list by threat_type (for bar chart / advanced view)
@statistics_bp.route('/api/threatfox')
def get_threatfox_grouped():
    try:
        url = "https://threatfox.abuse.ch/api/v1/"
        payload = {"query": "get_recent"}
        headers = {"Content-Type": "application/json"}

        res = requests.post(url, json=payload, headers=headers)
        res.raise_for_status()

        json_data = res.json()
        grouped = defaultdict(list)

        for entry in json_data.get("data", []):
            threat_type = entry.get("threat_type", "unknown").lower()
            grouped[threat_type].append({
                "ioc": entry.get("ioc"),
                "threat_type": threat_type,
                "malware": entry.get("malware", "Unknown"),
                "confidence": entry.get("confidence_level", "N/A"),
                "reference": entry.get("reference"),
                "tags": entry.get("malware_alias", [])
            })

        return jsonify(grouped)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

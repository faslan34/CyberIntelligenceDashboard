
from flask import Flask, request, jsonify
from flask_cors import CORS
import openai
import os
from dotenv import load_dotenv
import requests
import feedparser
from collections import defaultdict

# === Setup ===
app = Flask(__name__)
CORS(app)

# === Load env vars ===

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# === AI Q&A ===
@app.route('/ask', methods=['POST'])
def ask():
    data = request.get_json()
    question = data.get("question", "")
    prompt = f"Answer the following question strictly related to cybersecurity or computer science only. If it's outside those topics, politely refuse.\n\nQuestion: {question}"

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a cybersecurity and computer science expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        answer = response['choices'][0]['message']['content']
        return jsonify({"answer": answer})
    except Exception as e:
        return jsonify({"answer": f"Error: {str(e)}"}), 500

# === Cybersecurity News ===
@app.route('/news', methods=['GET'])
def get_news():
    feeds = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://krebsonsecurity.com/feed/"
    ]
    articles = []
    for feed_url in feeds:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries[:3]:
            articles.append({
                "title": entry.title,
                "summary": entry.summary[:200] + "...",
                "link": entry.link
            })
    return jsonify(articles)

# === CISA KEV Feed ===
@app.route('/api/cisa-alerts')
def get_cisa_alerts():
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for item in vulnerabilities:
            results.append({
                "cveID": item.get("cveID"),
                "vendorProject": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerabilityName": item.get("vulnerabilityName"),
                "dateAdded": item.get("dateAdded"),
                "link": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}"
            })

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === ThreatFox – Flat Real Data ===
@app.route('/api/threatfox', methods=['GET'])
def get_threatfox_from_export():
    try:
        url = "https://threatfox.abuse.ch/export/json/recent/"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        print("✅ Total raw keys:", len(data))
        print("🔍 Sample:", list(data.items())[:1])

        flat_list = []
        for key, value in data.items():
            if isinstance(value, list):
                for entry in value:
                    flat_list.append({
                        "ioc": entry.get("ioc_value"),
                        "threat_type": entry.get("threat_type", "unknown").lower(),
                        "malware": entry.get("malware", "Unknown"),
                        "confidence_level": entry.get("confidence_level", "N/A"),
                        "reference": entry.get("reference"),
                        "tags": entry.get("malware_alias", [])
                    })

        return jsonify({"malware": flat_list})

    except Exception as e:
        print("ThreatFox error:", e)
        return jsonify({"malware": []}), 500


@app.route('/api/threat-intel')
def get_technical_threat_intel():
    import requests
    import feedparser
    from bs4 import BeautifulSoup

    headers = {'User-Agent': 'Mozilla/5.0'}
    feeds = {
        "Microsoft Security Blog": "https://www.microsoft.com/en-us/security/blog/feed/",
        "Check Point Research": "https://research.checkpoint.com/feed/",
        "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
        "Securelist (Kaspersky)": "https://securelist.com/feed/",
        "US-CERT (CISA)": "https://www.cisa.gov/news.xml",
        "FireEye/Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
        "Palo Alto Unit42": "https://unit42.paloaltonetworks.com/feed/"
        
        
    }

    results = []

    for source, url in feeds.items():
        try:
            res = requests.get(url, headers=headers, timeout=15)
            res.raise_for_status()
            feed = feedparser.parse(res.content)

            for entry in feed.entries[:3]:
                raw_html = entry.get("summary", entry.get("description", "No summary available"))
                soup = BeautifulSoup(raw_html, "html.parser")
                clean_text = soup.get_text()
                max_words = 80
                words = clean_text.split()
                if len(words) > max_words:
                    clean_text = " ".join(words[:max_words]) + "..."


                results.append({
                    "source": source,
                    "title": entry.title,
                    "description": clean_text,
                    "link": entry.link
                })
        except Exception as e:
            print(f"❌ {source} feed error:", e)

    print("✅ Total Threat Intel Entries:", len(results))
    return jsonify(results)

# === OSINT Lookup ===
@app.route('/osint-lookup', methods=['POST'])
def osint_lookup():
    data = request.get_json()
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "No input provided"}), 400

    vt_api_key = os.getenv("VT_API_KEY")
    abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
    results = []

    try:
        vt_url = f"https://www.virustotal.com/api/v3/search?query={query}"
        headers = {"x-apikey": vt_api_key}
        vt_res = requests.get(vt_url, headers=headers)
        if vt_res.status_code == 200:
            data = vt_res.json()
            stats = data.get("data", [])[0].get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            results.append({
                "source": "VirusTotal",
                "info": f"Malicious: {malicious}, Suspicious: {suspicious}",
                "link": f"https://www.virustotal.com/gui/search/{query}"
            })
    except:
        results.append({
            "source": "VirusTotal",
            "info": "Error or no result",
            "link": f"https://www.virustotal.com/gui/search/{query}"
        })

    if query.count(".") == 3:
        try:
            abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={query}&maxAgeInDays=90"
            headers = {
                "Key": abuse_api_key,
                "Accept": "application/json"
            }
            abuse_res = requests.get(abuse_url, headers=headers)
            if abuse_res.status_code == 200:
                data = abuse_res.json()["data"]
                results.append({
                    "source": "AbuseIPDB",
                    "info": f"Abuse Score: {data['abuseConfidenceScore']}/100",
                    "link": f"https://www.abuseipdb.com/check/{query}"
                })
        except:
            results.append({
                "source": "AbuseIPDB",
                "info": "Error or not an IP",
                "link": f"https://www.abuseipdb.com/check/{query}"
            })

    if "." in query and " " not in query:
        results.append({
            "source": "URLScan.io",
            "info": "Check scan history for this domain or IP on URLScan.io.",
            "link": f"https://urlscan.io/domain/{query}"
        })

    return jsonify({"results": results})

# === Run the App ===
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)

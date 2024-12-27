from flask import Flask, render_template, request, url_for
from pymongo import MongoClient
import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017")
db = client["api"]
collection = db["cves"]

app = Flask(__name__)

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    per_page_options = [10, 50, 100]
    total_count = collection.count_documents({})
    data = list(collection.find().skip((page - 1) * per_page).limit(per_page))
    cve_list = []
    for document in data:
        cve_list.append({
            "id": document["id"],
            "sourceIdentifier": document["sourceIdentifier"],
            "published": document["published"],
            "lastModified": document["lastModified"],
            "vulnStatus": document["vulnStatus"]
        })
    return render_template('index.html', cve_list=cve_list, page=page, per_page=per_page, per_page_options=per_page_options, total_count=total_count)

@app.route('/cve/<cve_id>')
def cve_details(cve_id):
    cve = collection.find_one({"id": cve_id})
    if cve:
        english_description = next((desc['value'] for desc in cve['descriptions'] if desc['lang'] == 'en'), None)
        cvss_metrics = cve["metrics"].get("cvssMetricV2", [{}])[0]
        cvss_data = cvss_metrics.get("cvssData", {})
        severity = cvss_metrics.get("baseSeverity", "")
        baseScore = cvss_data.get("baseScore", 0)
        accessVector = cvss_data.get("accessVector", "")
        accessComplexity = cvss_data.get("accessComplexity", "")
        authentication = cvss_data.get("authentication", "")
        confidentialityImpact = cvss_data.get("confidentialityImpact", "")
        integrityImpact = cvss_data.get("integrityImpact", "")
        availabilityImpact = cvss_data.get("availabilityImpact", "")
        vectorString = cvss_data.get("vectorString", "")
        impactScore = cvss_metrics.get("impactScore", 0)
        exploitabilityScore = cvss_metrics.get("exploitabilityScore", 0)
        
        configurations = cve.get("configurations", [])
        cpe = []
        for configuration in configurations:
            nodes = configuration.get("nodes", [])
            for node in nodes:
                cpe_match = node.get("cpeMatch", [])
                for item in cpe_match:
                    cpe.append({
                        "criteria": item.get("criteria", ""),
                        "matchCriteriaId": item.get("matchCriteriaId", ""),
                        "vulnerable": item.get("vulnerable", False)
                    })
        
        return render_template('cve_details.html', cve={
            "id": cve["id"],
            "descriptions": english_description,
            "severity": severity,
            "baseScore": baseScore,
            "accessVector": accessVector,
            "accessComplexity": accessComplexity,
            "authentication": authentication,
            "confidentialityImpact": confidentialityImpact,
            "integrityImpact": integrityImpact,
            "availabilityImpact": availabilityImpact,
            "impactScore": impactScore,
            "exploitabilityScore": exploitabilityScore,
            "vectorString": vectorString,
            "cpe": cpe
        })
    else:
        return "CVE not found", 404

if __name__ == '__main__':
    app.run(debug=True)
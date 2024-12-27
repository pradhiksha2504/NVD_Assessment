import requests
from pymongo import MongoClient

# MongoDB connection details
mongo_client = MongoClient('mongodb://localhost:27017')
db = mongo_client['Securin']
cve_collection = db['cves']

# API endpoint and parameters
api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
params = {'startIndex': 0, 'resultsPerPage': 1000}

# Fetch and import CVE data
while True:
    response = requests.get(api_url, params=params)
    response.raise_for_status()
    data = response.json()

    # Insert CVE data into MongoDB
    for cve_item in data['vulnerabilities']:
        cve_collection.insert_one(cve_item['cve'])

    # Update the startIndex for the next request
    params['startIndex'] += params['resultsPerPage']
    if params['startIndex'] >= data['totalResults']:
        break
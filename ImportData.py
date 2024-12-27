import requests
from pymongo import MongoClient

mongo_client = MongoClient('mongodb://localhost:27017')
db = mongo_client['nvd_data']  
cve_collection = db['cves']   

api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
params = {'startIndex': 0, 'resultsPerPage': 2000}  

def fetch_and_store_cves():
    while True:
        response = requests.get(api_url, params=params)
        response.raise_for_status()  
        data = response.json()
        
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            print("No vulnerabilities found or end of data reached.")
            break
        
        for vulnerability in vulnerabilities:
            cve_data = vulnerability.get('cve')
            if cve_data:
                cve_collection.update_one(
                    {'id': cve_data.get('id')}, 
                    {'$set': cve_data}, 
                    upsert=True
                )
        
        print(f"Inserted {len(vulnerabilities)} CVEs starting from index {params['startIndex']}")
        
        params['startIndex'] += params['resultsPerPage']
        if params['startIndex'] >= data.get('totalResults', 0):
            print("Completed importing all CVE data.")
            break

if __name__ == '__main__':
    fetch_and_store_cves()

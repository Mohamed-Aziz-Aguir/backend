import httpx
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError

ASRG_URL = "https://asrg.io/api/v1/vulnerabilities/search"

class ASRGVulnerabilityService:
    def __init__(self, es: Elasticsearch, index_name: str = "asrg-cve"):
        self.es = es
        self.index_name = index_name

    def delete_index_if_exists(self):
        try:
            if self.es.indices.exists(index=self.index_name):
                self.es.indices.delete(index=self.index_name)
                print(f"Deleted existing index: {self.index_name}")
        except Exception as e:
            print(f"Error deleting index: {e}")

    def create_index(self):
        self.es.indices.create(index=self.index_name, ignore=400)

    def fetch_cves(self, keyword: str = "mercedes") -> list:
        payload = {
            "keyword": keyword,
            "dateType": "published",
            "sources": [],
            "dateRange": [None, None]
        }

        try:
            response = httpx.post(ASRG_URL, json=payload, timeout=10.0)
            response.raise_for_status()
            data = response.json()
            return data.get("results", [])
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            return []

    def index_cves(self, cves: list, keyword: str):
        for cve in cves:
            doc = {
                "cve_id": cve.get("cve_id"),
                "url": f"https://asrg.io/AutoVulnDB/#/vulnerabilities/{cve.get('id')}?keyword={keyword}&dateType=published&dateRange=%5Bnull%2Cnull%5D&sources=%5B%5D",
                "description": cve.get("description"),
                "cvss_score": float(cve.get("cvss", {}).get("score", 0)) if cve.get("cvss", {}).get("score") else None,
                "search_term": keyword,
                "timestamp": datetime.utcnow().isoformat()
            }

            self.es.index(index=self.index_name, body=doc)

    def fetch_and_index_cves(self, keyword: str = "mercedes"):
        self.delete_index_if_exists()
        self.create_index()

        cves = self.fetch_cves(keyword)
        if cves:
            self.index_cves(cves, keyword)
            print(f"Indexed {len(cves)} CVEs with keyword: {keyword}")
        else:
            print("No CVEs found or failed to fetch.")

# ✅ Entry point for testing
if __name__ == "__main__":
    es = Elasticsearch("http://localhost:9200")  # Adjust if needed
    service = ASRGVulnerabilityService(es)
    service.fetch_and_index_cves("mercedes")

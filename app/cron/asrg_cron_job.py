from app.services.asrg_vuldb_service import ASRGVulnerabilityService  

if __name__ == "__main__":
    result = ASRGVulnerabilityService.fetch_and_index("cve")
    print(result)

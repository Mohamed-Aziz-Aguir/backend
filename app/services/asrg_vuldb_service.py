import requests
import json
import time
from typing import List, Dict, Any
from fastapi import HTTPException
from app.core.elasticsearch_client import es  
class ASRGVulnerabilityService:
    @staticmethod
    def fetch_all_vulnerabilities(search_term: str) -> List[Dict[str, Any]]:
        """
        Fetch all vulnerabilities from the API using cursor-based pagination.
        
        Args:
            search_term: The search term to filter vulnerabilities
            
        Returns:
            List of all vulnerability records
        """
        base_url = "https://api.asrg.io"
        all_vulnerabilities = []
        cursor = ""
        page_count = 0
        
        # Headers from the original request
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36",
            "Origin": "https://asrg.io",
            "Referer": "https://asrg.io/",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty"
        }
        
        while True:
            # Construct the URL with parameters
            params = {
                "search": search_term,
                "cursor": cursor,
                "sort": "-created"
            }
            
            url = f"{base_url}/vulnerabilities"
            
            try:
                print(f"Fetching page {page_count + 1}...")
                print(f"Current cursor: {cursor[:50]}..." if cursor else "Starting from beginning")
                
                # Make the request
                response = requests.get(url, headers=headers, params=params)
                response.raise_for_status()  # Raise an exception for bad status codes
                
                # Parse JSON response
                data = response.json()
                
                # Extract vulnerabilities from current page
                vulnerabilities = data.get("vulnerabilities", [])
                page_info = data.get("pageInfo", {})
                
                # Add current page vulnerabilities to our collection
                all_vulnerabilities.extend(vulnerabilities)
                page_count += 1
                
                print(f"Fetched {len(vulnerabilities)} vulnerabilities from page {page_count}")
                print(f"Total vulnerabilities collected: {len(all_vulnerabilities)}")
                print(f"Total count from API: {page_info.get('totalCount', 'Unknown')}")
                
                # Check if there are more pages
                has_next_page = page_info.get("hasNextPage", False)
                
                if not has_next_page:
                    print("No more pages to fetch. Done!")
                    break
                
                # Get the cursor for the next page
                cursor = page_info.get("endCursor", "")
                
                if not cursor:
                    print("No end cursor found, stopping pagination")
                    break
                
                # Add a small delay to be respectful to the API
                time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                print(f"Error making request: {e}")
                raise HTTPException(status_code=500, detail=f"API request failed: {str(e)}")
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON response: {e}")
                raise HTTPException(status_code=500, detail="Invalid API response format")
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
                raise HTTPException(status_code=400, detail="Operation cancelled")
        
        return all_vulnerabilities

    @staticmethod
    def index_vulnerabilities(search_term: str, vulnerabilities: List[Dict[str, Any]]) -> Dict:
        """
        Index vulnerabilities in Elasticsearch with the search term as index name.
        Deletes existing index if it exists.
        
        Args:
            search_term: The search term used (will be index name)
            vulnerabilities: List of vulnerabilities to index
            
        Returns:
            Dictionary with operation results
        """
        if not vulnerabilities:
            return {"status": "error", "message": "No vulnerabilities to index"}
        
        index_name = f"asrg-{search_term.lower()}"
        
        try:
            # Delete existing index if it exists
            if es.indices.exists(index=index_name):
                es.indices.delete(index=index_name)
                print(f"Deleted existing index: {index_name}")
            
            # Create new index and add documents
            success_count = 0
            for vuln in vulnerabilities:
                try:
                    # Add some metadata
                    doc = {
                        **vuln,
                        "search_term": search_term,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                    es.index(index=index_name, document=doc)
                    success_count += 1
                except Exception as e:
                    print(f"Error indexing document {vuln.get('name')}: {e}")
            
            # Refresh index to make documents searchable immediately
            es.indices.refresh(index=index_name)
            
            return {
                "status": "success",
                "index": index_name,
                "documents_indexed": success_count,
                "total_documents": len(vulnerabilities),
                "message": f"Successfully indexed {success_count} vulnerabilities"
            }
            
        except Exception as e:
            print(f"Elasticsearch error: {e}")
            raise HTTPException(status_code=500, detail=f"Elasticsearch error: {str(e)}")

    @classmethod
    def fetch_and_index(cls, search_term: str) -> Dict:
        """
        Main method to fetch, filter, and index vulnerabilities.
        """
        print(f"\nStarting vulnerability collection for: {search_term}")

        try:
            # Step 1: Fetch vulnerabilities
            vulnerabilities = cls.fetch_all_vulnerabilities(search_term)

            if not vulnerabilities:
                return {
                    "status": "success",
                    "message": "No vulnerabilities found",
                    "index": f"asrg-{search_term.lower()}",
                    "documents_indexed": 0
                }

            # Step 2: Save raw vulnerabilities to a file (optional)
            raw_file = f"/tmp/{search_term}_raw.jsonl"
            with open(raw_file, "w", encoding="utf-8") as f:
                for vuln in vulnerabilities:
                    f.write(json.dumps(vuln) + "\n")
            print(f"Saved raw data to {raw_file}")

            # Step 3: Filter relevance:true
            filtered_vulnerabilities = [
                vuln for vuln in vulnerabilities
                if vuln.get("relevance", False) or vuln.get("_source", {}).get("relevance", False)
            ]
            print(f"Filtered {len(filtered_vulnerabilities)}/{len(vulnerabilities)} vulnerabilities as relevant")

            # Step 4: Save filtered file (optional)
            filtered_file = f"/tmp/{search_term}_filtered.jsonl"
            with open(filtered_file, "w", encoding="utf-8") as f:
                for vuln in filtered_vulnerabilities:
                    f.write(json.dumps(vuln) + "\n")
            print(f"Saved filtered data to {filtered_file}")

            # Step 5: Index filtered vulnerabilities into Elasticsearch
            index_result = cls.index_vulnerabilities(search_term, filtered_vulnerabilities)

            # Step 6: Prepare severity counts
            severity_counts = {}
            for vuln in filtered_vulnerabilities:
                severity = vuln.get("cvss", {}).get("baseSeverity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            return {
                "status": "success",
                "index": index_result["index"],
                "documents_indexed": len(filtered_vulnerabilities),
                "total_in_api": len(vulnerabilities),
                "severity_counts": severity_counts,
                "latest_cves": [v["name"] for v in filtered_vulnerabilities[:3]]
            }

        except Exception as e:
            print(f"Error: {str(e)}")
            return {
                "status": "error",
                "message": str(e),
                "index": f"asrg-{search_term.lower()}"
            }
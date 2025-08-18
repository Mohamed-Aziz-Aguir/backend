import requests
import json
import time
from typing import List, Dict, Any

def fetch_all_vulnerabilities(base_url: str = "https://api.asrg.io", search_term: str = "mercedes") -> List[Dict[str, Any]]:
    """
    Fetch all vulnerabilities from the API using cursor-based pagination.
    
    Args:
        base_url: The base URL of the API
        search_term: The search term to filter vulnerabilities
    
    Returns:
        List of all vulnerability records
    """
    
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
            break
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {e}")
            break
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            break
    
    return all_vulnerabilities

def save_vulnerabilities_to_file(vulnerabilities: List[Dict[str, Any]], filename: str = "vulnerabilities.json"):
    """Save vulnerabilities to a JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                "total_count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities
            }, f, indent=2, ensure_ascii=False)
        print(f"Saved {len(vulnerabilities)} vulnerabilities to {filename}")
    except Exception as e:
        print(f"Error saving to file: {e}")

def print_summary(vulnerabilities: List[Dict[str, Any]]):
    """Print a summary of the fetched vulnerabilities."""
    if not vulnerabilities:
        print("No vulnerabilities found.")
        return
    
    print(f"\n=== SUMMARY ===")
    print(f"Total vulnerabilities fetched: {len(vulnerabilities)}")
    
    # Count by severity
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln.get("cvss", {}).get("baseSeverity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\nSeverity breakdown:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity.capitalize()}: {count}")
    
    # Show latest vulnerabilities
    print(f"\nLatest 5 vulnerabilities:")
    for i, vuln in enumerate(vulnerabilities[:5]):
        print(f"  {i+1}. {vuln.get('name', 'N/A')} - {vuln.get('cvss', {}).get('baseSeverity', 'N/A')} severity")

if __name__ == "__main__":
    print("Starting vulnerability data collection...")
    print("This may take a while depending on the total number of records.")
    print("Press Ctrl+C to stop at any time.\n")
    
    # Fetch all vulnerabilities
    vulnerabilities = fetch_all_vulnerabilities()
    
    if vulnerabilities:
        # Print summary
        print_summary(vulnerabilities)
        
        # Save to file
        save_vulnerabilities_to_file(vulnerabilities)
        
        # Ask user if they want to save to a different format
        print(f"\nData collection complete!")
        print(f"You can find the results in 'vulnerabilities.json'")
    else:
        print("No vulnerabilities were fetched.")

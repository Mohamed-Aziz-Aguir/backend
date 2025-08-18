from playwright.sync_api import sync_playwright
from selectolax.parser import HTMLParser
from datetime import datetime
from elasticsearch import Elasticsearch
import time
import json
import re

SEARCH_URL = "https://asrg.io/AutoVulnDB/#/vulnerabilities"

# Initialize Elasticsearch
es = Elasticsearch("http://localhost:9200")

def fetch_cves(search_term: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto(SEARCH_URL)
        
        # Wait for search input and perform search
        try:
            page.wait_for_selector("input.pr-32", timeout=30000)
            page.fill("input.pr-32", search_term)
            page.click("button:has-text('Search')")
            page.wait_for_selector("div.border-b.border-asrgGray-200.pb-4", timeout=30000)
        except Exception as e:
            print(f"❌ Search failed: {str(e)}")
            return []

        # Load more content if available
        load_more_attempts = 0
        while load_more_attempts < 5:  # Limit to 5 attempts
            try:
                page.wait_for_selector("svg.lucide-circle-plus", timeout=5000)
                page.click("svg.lucide-circle-plus")
                load_more_attempts += 1
                time.sleep(2)  # Longer wait for content to load
            except:
                break

        # Get final page content
        html = page.content()
        browser.close()

    tree = HTMLParser(html)
    cves = []
    index_name = f"asrg-{search_term.lower()}"
    
    # Debug: Save HTML for inspection
    with open("debug_page.html", "w", encoding="utf-8") as f:
        f.write(html)

    # Find all CVE containers - using more specific selector
    cve_containers = tree.css('div.border-b.border-asrgGray-200.pb-4') or []
    print(f"🔍 Found {len(cve_containers)} potential CVE containers")

    for container in cve_containers:
        try:
            # Extract CVE ID - more robust selection
            cve_node = container.css_first('a[href^="/AutoVulnDB/#/vulnerability/"]')
            if not cve_node:
                print("⚠️ No CVE link found in container")
                continue
                
            cve_id = cve_node.text(strip=True)
            if not cve_id.startswith("CVE-"):
                print(f"⚠️ Invalid CVE ID format: {cve_id}")
                continue

            href = cve_node.attributes.get("href", "")
            full_url = f"https://asrg.io{href}" if href else None

            # Description - using more specific selector
            desc_node = container.css_first('p.whitespace-pre-line')
            description = desc_node.text(strip=True) if desc_node else ""

            # CVSS Score - more robust extraction
            cvss_score = None
            cvss_container = container.css_first('div.flex.items-center.gap-2:has-text("CVSS Base")')
            if cvss_container:
                score_span = cvss_container.css_first('div')
                if score_span:
                    score_text = score_span.text(strip=True)
                    try:
                        cvss_score = float(score_text)
                    except ValueError:
                        print(f"⚠️ Invalid CVSS score format for {cve_id}: {score_text}")

            print(f"Processing {cve_id} - Score: {cvss_score}")  # Debug output

            cve_data = {
                "cve_id": cve_id,
                "url": full_url,
                "description": description,
                "cvss_score": cvss_score,
                "search_term": search_term,
                "timestamp": datetime.now().isoformat()
            }

            cves.append(cve_data)

            # Index to Elasticsearch
            try:
                es.index(index=index_name, body=cve_data)
                time.sleep(0.2)
            except Exception as e:
                print(f"❌ Failed to index {cve_id}: {str(e)}")

        except Exception as e:
            print(f"❌ Error processing container: {str(e)}")
            continue

    print(f"✅ Saved & indexed {len(cves)} CVEs (index: {index_name})")
    return cves
if __name__ == "__main__":
    fetch_cves("ford")
from playwright.sync_api import sync_playwright
from selectolax.parser import HTMLParser
import json
from datetime import datetime
import time

SEARCH_URL = "https://asrg.io/AutoVulnDB/#/vulnerabilities"


def fetch_cves(search_term: str):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)  # set headless=True to run in background
        page = browser.new_page()

        # Open the page and wait for the search bar
        page.goto(SEARCH_URL)
        page.wait_for_selector("input.pr-32", timeout=90000)

        # Fill search term and click Search
        page.fill("input.pr-32", search_term)
        page.click("button:has-text('Search')")

        # Wait for results to appear
        page.wait_for_selector("a.text-lg.font-bold.text-asrgPrimary", timeout=90000)

        # Repeatedly click "load more" button if present
        while True:
            try:
                # Wait briefly for "load more" button to appear
                page.wait_for_selector("svg.lucide-circle-plus", timeout=5000)
                print("🔄 Clicking 'Load More' button to fetch additional results...")
                page.click("svg.lucide-circle-plus")
                time.sleep(1)  # small delay for new results to load
            except:
                print("✅ No more 'Load More' button found. All results loaded.")
                break

        # Get full page content
        html = page.content()

        # Save HTML for debugging
        html_filename = f"page_{search_term}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.html"
        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📄 Saved full HTML to {html_filename}")

        browser.close()

    # Parse HTML
    tree = HTMLParser(html)
    cves = []

    for node in tree.css("a.text-lg.font-bold.text-asrgPrimary"):
        cve_id = node.text(strip=True)
        href = node.attributes.get("href")
        full_url = f"https://asrg.io{href}"

        # Extract description
        parent_div = node.parent.parent.parent
        description = ""
        desc_node = parent_div.css_first("p.whitespace-pre-line")
        if desc_node:
            description = desc_node.text(strip=True)

        cves.append({
            "cve_id": cve_id,
            "url": full_url,
            "description": description
        })

    # Save to JSON
    out_data = {
        "search_term": search_term,
        "date": datetime.utcnow().isoformat() + "Z",
        "results": cves
    }

    json_filename = f"vulnerabilities_{search_term}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)

    print(f"✅ Saved {len(cves)} CVEs to {json_filename}")
    return cves





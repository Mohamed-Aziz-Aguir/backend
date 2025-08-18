from playwright.sync_api import sync_playwright
from elasticsearch import Elasticsearch
import json

# Connect to Elasticsearch (adjust host/port if needed)
es = Elasticsearch("http://localhost:9200")  # or your actual ES host

def scrape_vicone_zerodays():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Go to VicOne Zero-Day Vulns page
        page.goto("https://vicone.com/automotive-zero-day-vulnerabilities", timeout=60000)
        page.wait_for_selector("table")

        # Set entries per page to 100
        try:
            page.wait_for_selector("#dt-length-0", state="visible", timeout=10000)
            page.select_option("#dt-length-0", value="100")
            page.wait_for_selector("table tbody tr", state="visible", timeout=5000)
        except Exception as e:
            print(f"Failed to set entries per page to 100: {e}")
            dropdown_html = page.inner_html("div.dt-layout-row")
            print("Dropdown HTML:", dropdown_html)

        all_data = []
        print("Scraping data...")
        page.wait_for_selector("table tbody tr", state="visible")
        rows = page.query_selector_all("table tbody tr")

        for row in rows:
            cols = row.query_selector_all("td")
            if len(cols) == 4:
                item = {
                    "zero_day_id": cols[0].inner_text().strip(),
                    "cve": cols[1].inner_text().strip(),
                    "category": cols[2].inner_text().strip(),
                    "impact": cols[3].inner_text().strip()
                }
                all_data.append(item)

                # Index each item into Elasticsearch
                es.index(index="zeroday", document=item)

        browser.close()

        # Optional: save locally as backup
        with open("vicone_zero_day_vulns.json", "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)

        print(f"\nScraped and indexed {len(all_data)} entries into Elasticsearch index 'zeroday'.")

if __name__ == "__main__":
    scrape_vicone_zerodays()

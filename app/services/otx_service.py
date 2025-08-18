import re
from datetime import datetime
import httpx
from app.core.config import settings
from app.core.elasticsearch_client import es

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

# detection helpers
_hash_re = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_email_re = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

def _detect_type(ioc: str) -> str:
    """Return the OTX indicator type string for the given IOC."""
    if _hash_re.match(ioc):
        return "file"
    if _ipv4_re.match(ioc):
        return "IPv4"
    if _email_re.match(ioc):
        return "email"
    return "domain"

def get_info_from_otx(ioc: str) -> dict:
    """Get IOC data from OTX, using Elasticsearch as a cache."""
    # 1️⃣ Check cache first
    try:
        query = {"query": {"match": {"ioc": ioc}}}
        res = es.search(index="otx-iocs", body=query)
        if res.get("hits", {}).get("total", {}).get("value", 0) > 0:
            return res["hits"]["hits"][0]["_source"]["raw"]
    except Exception:
        pass  # If ES fails, just call API

    # 2️⃣ Fetch from API
    ind_type = _detect_type(ioc)
    url = f"{OTX_BASE}/{ind_type}/{ioc}/general"
    headers = {"X-OTX-API-KEY": settings.otx_api_key} if getattr(settings, "otx_api_key", None) else {}

    try:
        resp = httpx.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        result = resp.json()

        # Clean duplicate pulses
        pulses = result.get("pulse_info", {}).get("pulses", [])
        unique_pulses = {
            p["id"]: {
                "id": p["id"],
                "name": p["name"],
                "created": p["created"],
                "TLP": p["TLP"],
                "tags": p.get("tags", [])
            }
            for p in pulses if "id" in p
        }
        result["pulse_info"]["pulses"] = list(unique_pulses.values())

        # Save in ES
        doc = {
            "ioc": ioc,
            "type": ind_type,
            "source": "otx",
            "fetched_at": datetime.utcnow().isoformat(),
            "raw": result
        }
        try:
            es.index(index="otx-iocs", document=doc)
        except Exception:
            pass

        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"OTX API error: {e.response.status_code}", "details": e.response.text}
    except Exception as e:
        return {"error": str(e)}

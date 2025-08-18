# app/api/ioc.py
from fastapi import APIRouter
from app.models.ioc_models import IOCRequest
from app.services.otx_service import get_info_from_otx
from app.services.virustotal_service import get_info_from_virustotal
from app.core.elasticsearch_client import es

router = APIRouter()

@router.post("/analyze")
def analyze_ioc(data: IOCRequest):
    ioc_value = data.value.strip()

    # Prepare results dictionary
    results = {
        "ioc": ioc_value,
        "otx": None,
        "virustotal": None
    }

    # 1️⃣ Try to fetch from Elasticsearch first (both indexes in one go)
    try:
        # OTX
        otx_res = es.search(
            index="otx-iocs",
            body={"query": {"match": {"ioc": ioc_value}}}
        )
        if otx_res.get("hits", {}).get("total", {}).get("value", 0) > 0:
            results["otx"] = otx_res["hits"]["hits"][0]["_source"]["raw"]

        # VT
        vt_res = es.search(
            index="vt-iocs",
            body={"query": {"match": {"ioc": ioc_value}}}
        )
        if vt_res.get("hits", {}).get("total", {}).get("value", 0) > 0:
            results["virustotal"] = vt_res["hits"]["hits"][0]["_source"]["raw"]

    except Exception:
        pass  # If ES fails, just skip cache

    # 2️⃣ Call APIs only if missing
    if results["otx"] is None:
        results["otx"] = get_info_from_otx(ioc_value)

    if results["virustotal"] is None:
        results["virustotal"] = get_info_from_virustotal(ioc_value)

    return results

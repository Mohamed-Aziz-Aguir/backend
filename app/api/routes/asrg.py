from fastapi import APIRouter, HTTPException
from app.services.asrg_vuldb_service import ASRGVulnerabilityService

router = APIRouter()

@router.get("/fetch")
async def fetch_cves(term: str):
    try:
        result = await ASRGVulnerabilityService.fetch_and_index(term)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
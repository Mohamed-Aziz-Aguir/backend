from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from app.services.cve_service import CVEService
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/search")
def search_cves(
    q: str = Query(..., description="Search query - can be a CVE name (e.g., CVE-2024-55195) or keywords"),
    page: int = Query(1, ge=1, description="Page number (starts from 1)"),
    page_size: int = Query(10, ge=1, le=100, description="Number of results per page (max 100)")
):
    """
    Universal search endpoint that handles both CVE names and keyword searches with pagination
    """
    try:
        if not q or not q.strip():
            raise HTTPException(status_code=400, detail="Search query cannot be empty")

        service = CVEService()
        result = service.search(q.strip(), page=page, page_size=page_size)
        
        return {
            "count": len(result["results"]),
            "results": result["results"],
            "pagination": result["pagination"],
            "query": result["query"],
            "search_type": result["search_type"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in search_cves: {e}")
        raise HTTPException(status_code=500, detail="Internal server error occurred during search")

@router.get("/browse")
def browse_all_cves(
    page: int = Query(1, ge=1, description="Page number (starts from 1)"),
    page_size: int = Query(10, ge=1, le=100, description="Number of results per page (max 100)")
):
    """
    Browse all CVEs with pagination - useful for getting all CVEs without search query
    """
    try:
        service = CVEService()
        result = service.get_all_cves(page=page, page_size=page_size)
        
        return {
            "count": len(result["results"]),
            "results": result["results"],
            "pagination": result["pagination"],
            "query": "all",
            "search_type": "browse_all"
        }
    except Exception as e:
        logger.error(f"Error in browse_all_cves: {e}")
        raise HTTPException(status_code=500, detail="Internal server error occurred during browse")

# Keep the old endpoint for backward compatibility
@router.get("/search-legacy")
def search_cves_legacy(
    name: Optional[str] = Query(None, description="Exact CVE name like CVE-2021-42718"),
    keyword: Optional[str] = Query(None, description="Keyword to search in description")
):
    """Legacy search endpoint with separate name and keyword parameters"""
    try:
        if not name and not keyword:
            raise HTTPException(status_code=400, detail="You must provide either 'name' or 'keyword'")

        service = CVEService()
        results = service.search_cve(name=name, keyword=keyword)
        
        return {
            "count": len(results), 
            "results": results,
            "query": {
                "name": name,
                "keyword": keyword
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in search_cves_legacy: {e}")
        raise HTTPException(status_code=500, detail="Internal server error occurred during search")

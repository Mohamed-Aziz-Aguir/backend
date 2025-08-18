from typing import List, Dict, Optional, Tuple
from app.core.elasticsearch_client import es
from elasticsearch.exceptions import NotFoundError, ConnectionError
import logging
import re

logger = logging.getLogger(__name__)

class CVEService:
    def __init__(self, index_name: str = "asrg-cve"):
        self.index_name = index_name

    def _is_cve_format(self, query: str) -> bool:
        """Check if the query looks like a CVE identifier"""
        # CVE format: CVE-YYYY-NNNN (where YYYY is year and NNNN is number)
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(cve_pattern, query.upper()))

    def search(self, query: str, page: int = 1, page_size: int = 10) -> Dict:
        """
        Universal search method that handles both CVE names and keywords with pagination
        """
        try:
            # Check if Elasticsearch client is available
            if es is None:
                logger.error("Elasticsearch client is not initialized")
                return self._empty_result()
            
            # Check if the index exists first
            if not es.indices.exists(index=self.index_name):
                logger.error(f"Index '{self.index_name}' does not exist")
                return self._empty_result()
            
            # Validate pagination parameters
            if page < 1:
                page = 1
            if page_size < 1 or page_size > 100:  # Limit max page size
                page_size = 10
            
            # Calculate offset
            offset = (page - 1) * page_size

            if not query or not query.strip():
                # Return all documents if no query provided
                search_query = {"match_all": {}}
            elif self._is_cve_format(query):
                # Exact match for CVE identifiers
                search_query = {
                    "term": {
                        "name.keyword": query.upper()
                    }
                }
            else:
                # Multi-field search for keywords
                search_query = {
                    "multi_match": {
                        "query": query,
                        "fields": ["name^2", "description"],  # Boost name field
                        "type": "best_fields",
                        "operator": "and"
                    }
                }

            # Execute search with pagination
            response = es.search(
                index=self.index_name,
                query=search_query,
                from_=offset,
                size=page_size,
                source=True
            )
            
            total_hits = response["hits"]["total"]["value"]
            results = [hit["_source"] for hit in response["hits"]["hits"]]
            
            # Calculate pagination metadata
            total_pages = (total_hits + page_size - 1) // page_size  # Ceiling division
            has_next = page < total_pages
            has_previous = page > 1
            
            return {
                "results": results,
                "pagination": {
                    "current_page": page,
                    "page_size": page_size,
                    "total_results": total_hits,
                    "total_pages": total_pages,
                    "has_next": has_next,
                    "has_previous": has_previous,
                    "next_page": page + 1 if has_next else None,
                    "previous_page": page - 1 if has_previous else None
                },
                "query": query.strip() if query else "",
                "search_type": "cve_exact" if query and self._is_cve_format(query.strip()) else "keyword"
            }
            
        except NotFoundError as e:
            logger.error(f"Index not found: {e}")
            return self._empty_result()
        except ConnectionError as e:
            logger.error(f"Elasticsearch connection error: {e}")
            return self._empty_result()
        except Exception as e:
            logger.error(f"Unexpected error during CVE search: {e}")
            return self._empty_result()

    def _empty_result(self) -> Dict:
        """Return empty result structure"""
        return {
            "results": [],
            "pagination": {
                "current_page": 1,
                "page_size": 10,
                "total_results": 0,
                "total_pages": 0,
                "has_next": False,
                "has_previous": False,
                "next_page": None,
                "previous_page": None
            },
            "query": "",
            "search_type": "keyword"
        }

    def get_all_cves(self, page: int = 1, page_size: int = 10) -> Dict:
        """
        Get all CVEs with pagination - useful for browsing all CVEs
        """
        return self.search("", page=page, page_size=page_size)

    def search_cve(self, name: Optional[str] = None, keyword: Optional[str] = None) -> List[Dict]:
        """Legacy method - use search() instead"""
        if name:
            result = self.search(name, page=1, page_size=100)
            return result["results"]
        elif keyword:
            result = self.search(keyword, page=1, page_size=100)
            return result["results"]
        else:
            result = self.search("", page=1, page_size=100)
            return result["results"]

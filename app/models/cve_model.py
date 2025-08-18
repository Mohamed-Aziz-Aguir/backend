from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class CVSS(BaseModel):
    baseScore: float
    baseSeverity: str

class CVEItem(BaseModel):
    id: str
    name: str
    description: str
    cvss: CVSS
    createdBy: str
    created: datetime
    modified: datetime
    relevance: bool
    sectors: List[str]
    search_term: str
    timestamp: datetime

class CVESearchResponse(BaseModel):
    total: int
    results: List[CVEItem]

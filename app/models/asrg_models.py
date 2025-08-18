from pydantic import BaseModel

class CVEItem(BaseModel):
    cve_id: str
    url: str
    description: str

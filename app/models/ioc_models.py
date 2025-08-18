from pydantic import BaseModel

class IOCRequest(BaseModel):
    value: str

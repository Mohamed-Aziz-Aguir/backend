
from fastapi import FastAPI
from app.api.routes import ioc, asrg, cve_router


app = FastAPI(title="Cyber Threat Intelligence Dashboard")

app.include_router(ioc.router, prefix="/api/ioc", tags=["IOC"])

app.include_router(asrg.router, prefix="/api/asrg", tags=["ASRG CVEs"])
 
app.include_router(cve_router.router, prefix="/api/search", tags=["search"])
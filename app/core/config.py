from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    elastic_host: str
    redis_host: str
    otx_api_key: str
    virustotal_api_key: str
    class Config:
        env_file = ".env"

settings = Settings()

from elasticsearch import Elasticsearch
from app.core.config import settings

es = Elasticsearch(
    [settings.elastic_host],
    verify_certs=False,  # or True if using proper certs
    ssl_show_warn=False
)

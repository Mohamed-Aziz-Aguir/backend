#!/bin/bash
export PYTHONPATH="/home/coding/backend"
export ELASTIC_HOST="http://localhost:9200"
export REDIS_HOST="dummy"
export OTX_API_KEY="dummy"
source /home/coding/backend/venv/bin/activate
python3 /home/coding/backend/app/cron/zeroday.py
python3 /home/coding/backend/app/cron/asrg_cron_job.py

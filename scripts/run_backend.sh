#!/usr/bin/env bash
cd "$(dirname "$0")/../backend"
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

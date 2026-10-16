#!/bin/sh
# First start: train the model and load a simulated hard log so the demo is not empty.
set -e
if [ ! -f "$THREAT_MODEL" ]; then
  echo "Training model..."
  python -m src.ml.train --auto --out "$THREAT_MODEL"
fi
if [ ! -f "$THREAT_DB" ]; then
  echo "Seeding demo data..."
  python src/generator.py --hard --seed 42 --out data >/dev/null
  python -m src.ingest data/auth.log --db "$THREAT_DB"
fi
exec uvicorn src.api:app --host 0.0.0.0 --port "${PORT:-8000}"

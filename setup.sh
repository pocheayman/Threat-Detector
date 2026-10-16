#!/usr/bin/env bash
# One-shot setup for Ubuntu 22.04 (also works on other Debian/Ubuntu releases).
# Usage:  bash setup.sh
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Checking system packages (python3-venv, python3-pip, git)"
missing=()
for pkg in python3 python3-venv python3-pip git; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "    Installing: ${missing[*]}  (sudo password may be requested)"
  sudo apt update
  sudo apt install -y "${missing[@]}"
else
  echo "    All present."
fi

echo "==> Python: $(python3 --version)"

echo "==> Creating virtual environment in ./venv"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

echo "==> Installing Python dependencies"
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Generating HARD simulated logs (slow attacks, shared office, VPN users)"
python src/generator.py --hard

echo "==> Training the Isolation Forest on a clean simulated month"
python -m src.ml.train --auto

echo "==> Rules only vs rules + ML, scored against the answer key"
python -m src.main --trusted 115.249.0.0/16
python -m src.main --trusted 115.249.0.0/16 --model models/iforest.joblib --out data/alerts_hybrid.json

echo "==> Loading the alerts into the dashboard database (hybrid)"
THREAT_TRUSTED_NETWORKS=115.249.0.0/16 python -m src.ingest data/auth.log

echo "==> Benchmark on held-out seeds (takes about a minute)"
python -m src.benchmark

echo "==> Running tests"
python -m pytest -q

cat <<'EOF'

Setup complete.

Start the dashboard:
    source venv/bin/activate
    uvicorn src.api:app --reload
then open http://127.0.0.1:8000   (API docs: http://127.0.0.1:8000/docs)

Every new terminal, activate the environment first:
    cd threat-detector
    source venv/bin/activate
EOF

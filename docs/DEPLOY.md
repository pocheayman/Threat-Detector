# Deploying a free live demo

The app is one container: FastAPI + SQLite + the dashboard. On first start it trains the
model and loads simulated data, so a fresh deploy is never empty. Run it **read-only** on
the public internet: there is no login, so anyone could otherwise upload logs or change alert status.

## Render (free web service)

1. Push the project to GitHub (see below).
2. render.com -> New -> Web Service -> connect the repo -> Runtime: **Docker**.
3. Instance type: Free. Add environment variables:
   - `THREAT_READONLY=1`
   - `THREAT_TRUSTED_NETWORKS=115.249.0.0/16`
4. Deploy. Render sets `PORT`; the entrypoint uses it. Health check path: `/api/health`.
5. Put the URL on your resume and in the README.

Notes
* Free instances sleep when idle, so the first visit can take ~30-60 s while the container
  starts and re-trains. Say so in the README ("first load is slow on the free tier").
* The disk is ephemeral. That is fine here: demo data is regenerated on every cold start.
* Fly.io, Railway or Hugging Face Spaces (Docker) work the same way; set the same variables
  and expose the port in `PORT`.

## Local Docker check

```bash
docker build -t threat-detector .
docker run --rm -p 8000:8000 -e THREAT_READONLY=1 threat-detector
curl localhost:8000/api/config      # {"readonly": true, "ml": true, ...}
```

## Push to GitHub

```bash
cd threat-detector
git init && git add . && git commit -m "Threat detector with ML layer"
git branch -M main
git remote add origin https://github.com/<you>/threat-detector.git
git push -u origin main
```

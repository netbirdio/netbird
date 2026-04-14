# Device Auth Test Stand

Quick start:
1. `cd` to repo root (the `feature/tpm-cert-auth` branch)
2. `bash infrastructure_files/scripts/up-device-auth-stand.sh`
3. Open http://localhost and create an account
4. Go to Account Settings → Personal Access Token and generate one
5. `NETBIRD_TOKEN=<token> bash infrastructure_files/scripts/setup-device-auth.sh`
6. Open http://localhost/device-security to see the Device Security UI

Flags:
- `--rebuild` — force rebuild of the management image (use after code changes)

Dashboard with our changes (live reload):
```
cd netbird-dashboard && npm install && npm run dev
```
Then open http://localhost:3000

Custom dashboard Docker image (serves our build at http://localhost):
```
cd netbird-dashboard && docker build -f docker/Dockerfile -t netbird/dashboard:tpm-dev .
# Then re-run up-device-auth-stand.sh — it detects the image automatically
```

Stop:
```
docker compose -f infrastructure_files/stand/docker-compose.yml down
```

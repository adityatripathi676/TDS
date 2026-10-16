# AI-Driven HIDS and Threat Detection System

An organized, professional full-stack Host Intrusion Detection System built with:

- Python + FastAPI for backend APIs and monitoring logic
- React + Vite for the frontend dashboard

## Project Structure

```text
TDS/
|-- app/
|   |-- api/
|   |-- core/
|   |-- models/
|   |-- static/
|   |-- templates/
|   `-- main.py
|-- data/
|-- frontend/
|   |-- src/
|   |-- package.json
|   `-- vite.config.js
|-- scripts/
|-- tests/
|-- run.py
|-- README.md
`-- requirements.txt
```

## Features

- Host event ingestion and scoring
- Adaptive baseline anomaly detection
- Rule-based threat enrichment
- Persistent alerts and events
- Professional React dashboard
- Real host monitoring with CPU, memory, disk, process, and connection snapshots
- Manual scan controls and background monitor loop
- Attack simulation for demos

## Setup

```bash
python -m pip install -r requirements.txt
```

## Environment Variables

Create a local `.env` file in the project root to load secrets automatically through `run.py`.

Example:

```text
GEMINI_API_KEY=your_gemini_api_key_here
```

You can copy from `.env.example`.

## Run

```bash
python run.py
```

Open `http://127.0.0.1:8000`

`run.py` will:

- check Python requirements
- install missing Python packages
- install frontend Node packages if needed
- build the React frontend if needed
- load variables from `.env` if present
- start the FastAPI server

## Frontend Development

```bash
cd frontend
npm install
npm run dev
```

For local frontend development, Vite runs on `http://127.0.0.1:5173` and proxies API calls to FastAPI.

## Background Service Deployment (Run continuously on boot)

AI-HIDS Sentinel includes automated background service wrapper scripts for Windows and Linux.

### Windows Background Service (Run as Administrator)

```powershell
# Install & start Windows Service
powershell -ExecutionPolicy Bypass -File .\scripts\install_windows_service.ps1

# Uninstall Windows Service
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall_windows_service.ps1
```

### Linux Systemd Service (Run with sudo)

```bash
# Install & start Systemd service
sudo bash ./scripts/install_linux_service.sh

# Uninstall Systemd service
sudo bash ./scripts/uninstall_linux_service.sh
```

### Service Manager Helper

```bash
python scripts/service_manager.py
```

## Main API

- `GET /api/health`
- `POST /api/auth/login`
- `GET /api/metrics`
- `GET /api/events`
- `GET /api/alerts`
- `GET /api/system`
- `GET /api/monitor/status`
- `POST /api/monitor/start`
- `POST /api/monitor/stop`
- `POST /api/response/kill-process`
- `POST /api/response/block-ip`
- `POST /api/scan/yara`
- `GET /api/agents`
- `GET /api/soar/status`
- `GET /api/soar/history`
- `WS /ws/telemetry`

## Test

```bash
python -m unittest discover -s tests -v
```


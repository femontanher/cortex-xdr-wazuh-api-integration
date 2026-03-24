# Cortex-XDR-integration-with-Wazuh-via-API
The solution handles authentication with the Cortex XDR API, periodically retrieves events, processes the data, and forwards it in a structured format to Wazuh, enabling centralized security monitoring.

> A lightweight Python collector that continuously polls the **Palo Alto Cortex XDR SaaS API** for alerts and forwards them into the **Wazuh** log ingestion pipeline via a shared log file — enabling unified SIEM visibility across both platforms.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Installation](#installation)
  - [1. Clone the repository](#1-clone-the-repository)
  - [2. Create directories and files](#2-create-directories-and-files)
  - [3. Set ownership and permissions](#3-set-ownership-and-permissions)
  - [4. Install Python dependencies](#4-install-python-dependencies)
  - [5. Configure the collector](#5-configure-the-collector)
  - [6. Deploy the systemd service](#6-deploy-the-systemd-service)
- [Configuration Reference](#configuration-reference)
- [Running and Monitoring](#running-and-monitoring)
- [Dependencies](#dependencies)
- [License](#license)

---

## Overview

This integration runs as a **systemd service** under the `wazuh` user. It periodically queries the Cortex XDR API, retrieves new alerts since the last poll, and appends them as JSON lines to a log file that Wazuh monitors natively.

Key design goals:

- **Stateful polling** — a `state.json` file tracks the timestamp of the last fetched alert, avoiding duplicates across restarts.
- **Minimal footprint** — only one external Python library (`requests`) is required.
- **Wazuh-native ingestion** — alerts are written directly to a path within `/var/ossec/logs/`, which Wazuh can be configured to read via its `localfile` block.

---

## Architecture

```
┌─────────────────────┐        HTTPS / REST        ┌──────────────────────┐
│   Cortex XDR SaaS   │ ◄──────────────────────── │   collector.py       │
│   (Palo Alto API)   │ ──────────── alerts ──────► │   (Python service)   │
└─────────────────────┘                             └──────────┬───────────┘
                                                               │
                                                    writes JSON lines
                                                               │
                                                               ▼
                                              /var/ossec/logs/cortex_xdr/alerts.log
                                                               │
                                                    Wazuh localfile ingestion
                                                               │
                                                               ▼
                                                    ┌──────────────────────┐
                                                    │   Wazuh Manager      │
                                                    │   (SIEM / Alerts)    │
                                                    └──────────────────────┘
```

---

## Prerequisites

Before installing, make sure the environment provides:

| Requirement | Details |
|---|---|
| **Python 3** | Version 3.8 or higher recommended |
| **Network access** | Outbound HTTPS to your Cortex XDR API FQDN |
| **Admin privileges** | Required to create directories, set permissions, and manage systemd |
| **Wazuh installed** | A functional Wazuh Manager or Agent that will ingest the log output |

---

## Project Structure

```
/opt/cortex_collector/
├── collector.py       # Main polling loop — fetches alerts from Cortex XDR API
├── config.py          # All user-defined settings (API keys, paths, intervals)
└── requirements.txt   # Python dependencies (only: requests)
```

Runtime directories created during installation:

```
/var/log/cortex_xdr/          # Collector operational logs
│   ├── alerts.log             # Raw alerts as received (local backup)
│   └── collector.log          # Service runtime logs
│
/var/lib/cortex_xdr/          # Persistent state
│   └── state.json             # Stores last poll timestamp
│
/var/ossec/logs/cortex_xdr/   # Wazuh ingestion path
    └── alerts.log             # Alerts forwarded to Wazuh
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/cortex-wazuh-integration.git
cd cortex-wazuh-integration
```

### 2. Create directories and files

```bash
# Application and runtime directories
mkdir -p /opt/cortex_collector
mkdir -p /var/log/cortex_xdr
mkdir -p /var/ossec/logs/cortex_xdr
mkdir -p /var/lib/cortex_xdr

# Log and state files (must exist before the service starts)
touch /var/log/cortex_xdr/alerts.log
touch /var/log/cortex_xdr/collector.log
touch /var/lib/cortex_xdr/state.json
touch /var/ossec/logs/cortex_xdr/alerts.log
```

### 3. Set ownership and permissions

The service runs as the `wazuh` user. All relevant paths must be owned and accessible by it:

```bash
# Ownership
chown -R wazuh:wazuh /var/log/cortex_xdr
chown -R wazuh:wazuh /var/lib/cortex_xdr
chown -R wazuh:wazuh /var/ossec/logs/cortex_xdr

# Directory permissions (owner: rwx, group: r-x, others: none)
chmod 750 /var/log/cortex_xdr
chmod 750 /var/lib/cortex_xdr
chmod 750 /var/ossec/logs/cortex_xdr

# File permissions (owner: rw, group: r, others: none)
chmod 640 /var/log/cortex_xdr/alerts.log
chmod 640 /var/log/cortex_xdr/collector.log
chmod 640 /var/lib/cortex_xdr/state.json
chmod 640 /var/ossec/logs/cortex_xdr/alerts.log
```

### 4. Install Python dependencies

Only one external library is required:

```bash
python3 -m pip install requests
```

Or using pip3 directly:

```bash
pip3 install requests
```

Alternatively, install from `requirements.txt`:

```bash
pip3 install -r /opt/cortex_collector/requirements.txt
```

### 5. Configure the collector

Edit `config.py` inside `/opt/cortex_collector/` and fill in your environment values:

```python
# /opt/cortex_collector/config.py

API_KEY_ID    = "your_api_key_id"
API_KEY       = "your_api_key_secret"
FQDN          = "api-your-tenant.xdr.us.paloaltonetworks.com"

LOG_FILE      = "/var/ossec/logs/cortex_xdr/alerts.log"
POLL_INTERVAL = 60          # seconds between each poll
PAGE_SIZE     = 100         # alerts per API request
STATE_FILE    = "/var/lib/cortex_xdr/state.json"
```

> ⚠️ **Never commit `config.py` with real credentials to a public repository.** Add it to `.gitignore` and use environment variables or a secrets manager in production environments.

### 6. Deploy the systemd service

Create the service unit file:

```bash
nano /etc/systemd/system/cortex-collector.service
```

Paste the following content:

```ini
[Unit]
Description=Cortex XDR Collector for Wazuh
After=network.target

[Service]
Type=simple
User=wazuh
Group=wazuh
WorkingDirectory=/opt/cortex_collector
ExecStart=/usr/bin/python3 /opt/cortex_collector/collector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable --now cortex-collector
systemctl status cortex-collector
```

---

## Configuration Reference

| Variable | Description | Example |
|---|---|---|
| `API_KEY_ID` | Cortex XDR API Key ID | `"12"` |
| `API_KEY` | Cortex XDR API Key secret | `"abc123..."` |
| `FQDN` | Cortex XDR tenant API hostname | `"api-tenant.xdr.us.paloaltonetworks.com"` |
| `LOG_FILE` | Path where alerts are written for Wazuh ingestion | `"/var/ossec/logs/cortex_xdr/alerts.log"` |
| `POLL_INTERVAL` | Polling frequency in seconds | `60` |
| `PAGE_SIZE` | Number of alerts fetched per API call | `100` |
| `STATE_FILE` | Path to the JSON file that persists the last poll timestamp | `"/var/lib/cortex_xdr/state.json"` |

---

## Running and Monitoring

Check service status:

```bash
systemctl status cortex-collector
```

Follow real-time service logs:

```bash
journalctl -u cortex-collector -f
```

Inspect the alert output destined for Wazuh:

```bash
tail -f /var/ossec/logs/cortex_xdr/alerts.log
```

Restart after a configuration change:

```bash
systemctl restart cortex-collector
```

---

## Dependencies

| Library | Source | Purpose |
|---|---|---|
| `requests` | PyPI (`pip install requests`) | HTTP calls to the Cortex XDR API |
| `hashlib` | Python standard library | API authentication (HMAC / hashing) |
| `secrets` | Python standard library | Cryptographically secure nonce generation |
| `string` | Python standard library | String utilities |
| `datetime` | Python standard library | Timestamp handling |
| `json` | Python standard library | Parsing API responses and state file |
| `logging` | Python standard library | Structured service logging |
| `time` | Python standard library | Poll interval sleep |
| `pathlib` | Python standard library | Cross-platform path manipulation |
| `config` | Local project file | User-defined settings — **not a PyPI package** |

---

## License

This project is licensed under the [MIT License](LICENSE).

---

*Contributions, issues, and pull requests are welcome.*

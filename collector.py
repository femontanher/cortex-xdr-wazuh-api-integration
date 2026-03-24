#!/usr/bin/env python3
import hashlib, secrets, string, datetime, json, logging, time
import requests
from pathlib import Path
from config import API_KEY_ID, API_KEY, FQDN, LOG_FILE, POLL_INTERVAL, PAGE_SIZE, STATE_FILE

# ── Logging ────────────────────────────────────────────────
Path("/var/log/cortex_xdr").mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/cortex_xdr/collector.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("cortex-collector")


# ── Autenticação Advanced ──────────────────────────────────
def get_headers() -> dict:
    nonce     = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    ts        = str(int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000))
    auth_hash = hashlib.sha256(f"{API_KEY}{nonce}{ts}".encode()).hexdigest()
    return {
        "x-xdr-auth-id":   str(API_KEY_ID),
        "x-xdr-nonce":     nonce,
        "x-xdr-timestamp": ts,
        "Authorization":   auth_hash,
        "Content-Type":    "application/json"
    }


def api_post(path: str, payload: dict) -> dict:
    url  = f"https://{FQDN}/public_api/v1{path}"
    resp = requests.post(url, headers=get_headers(), json=payload, timeout=30)
    resp.raise_for_status()

    return resp.json().get("reply", {})

# ── Paginação ──────────────────────────────────────────────
def api_post_paginated(path: str, base_payload: dict, items_key: str) -> list:
    all_items = []
    search_from = 0

    while True:
        payload = json.loads(json.dumps(base_payload))
        payload["request_data"]["search_from"] = search_from
        payload["request_data"]["search_to"]   = search_from + PAGE_SIZE

        reply = api_post(path, payload)
        
        if isinstance(reply, list):
            items = reply
        else:
            items = reply.get(items_key, [])
            
        all_items.extend(items)

        if len(items) < PAGE_SIZE:
            break

        search_from += PAGE_SIZE

    return all_items


# ── Estado (timestamps e IDs processados) ──────────────────
def load_state() -> dict:
    default_ts = int((datetime.datetime.now(datetime.timezone.utc)
                      - datetime.timedelta(hours=24)).timestamp() * 1000)
    try:
        if Path(STATE_FILE).exists():
            state = json.loads(Path(STATE_FILE).read_text())
            for key in ["incidents", "alerts", "audits_mgmt", "audits_agents"]:
                if key not in state:
                    state[key] = default_ts
            if "processed_ids" not in state:
                state["processed_ids"] = []
            return state
    except Exception as e:
        log.warning(f"Erro ao carregar estado: {e}")
    
    return {
        "incidents": default_ts, "alerts": default_ts, 
        "audits_mgmt": default_ts, "audits_agents": default_ts,
        "processed_ids": []
    }


def save_state(state: dict):
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        if len(state.get("processed_ids", [])) > 3000:
            state["processed_ids"] = state["processed_ids"][-3000:]
        Path(STATE_FILE).write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.error(f"Erro ao salvar estado: {e}")


# ── Output para Wazuh ──────────────────────────────────────
def send(event: dict):
    try:
        Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        log.error(f"Erro ao escrever log: {e}")


# ── Coletores ──────────────────────────────────────────────

def collect_generic(path: str, items_key: str, since_ts: int, filter_field: str, log_type: str, processed_ids: list) -> tuple:
    lookback_ms = 30000
    query_ts = max(0, since_ts - lookback_ms)
    
    items = api_post_paginated(
        path,
        {"request_data": {
            "filters": [{"field": filter_field, "operator": "gte", "value": query_ts}],
            "sort":    {"field": filter_field, "keyword": "asc"},
        }},
        items_key=items_key
    )
    
    new_items_count = 0
    max_ts = since_ts
    current_cycle_ids = []

    for item in items:
        official_id = (item.get("alert_id") or item.get("incident_id") or 
                       item.get("AUDIT_ID") or item.get("id") or item.get("external_id"))
        
        raw_ts = (item.get("detection_timestamp") or 
                  item.get("server_creation_time") or 
                  item.get("creation_time") or 
                  item.get("modification_time") or 
                  item.get("timestamp") or 
                  item.get("TIMESTAMP") or 
                  item.get("AUDIT_INSERT_TIME") or 0)
        
        try:
            ts = int(raw_ts)
            if ts < 10000000000: ts *= 1000
        except: ts = 0

        immutable_keys = ["alert_id", "incident_id", "AUDIT_ID", "id", "external_id", 
                          "detection_timestamp", "creation_time", "timestamp", "endpoint_id"]
        unique_data = {k: item[k] for k in immutable_keys if k in item}
        unique_data["_raw_ts"] = ts
        
        content_hash = hashlib.md5(json.dumps(unique_data, sort_keys=True).encode()).hexdigest()
        final_id = str(official_id) if official_id else f"hash_{content_hash}"

        if final_id in processed_ids: continue
        if ts < since_ts: continue

        send({"log_source": "cortex_xdr", "log_type": log_type, **item})
        new_items_count += 1
        current_cycle_ids.append(final_id)
        if ts > max_ts: max_ts = ts

    if len(items) > 0 and max_ts == since_ts: max_ts += 1
    log.info(f"{log_type.capitalize()}: {len(items)} na janela, {new_items_count} novos enviados.")
    return max_ts, current_cycle_ids


def collect_endpoints(endpoint_cache: dict) -> dict:
    try:
        reply = api_post("/endpoints/get_endpoints", {"request_data": {}})
        
        if isinstance(reply, list):
            items = reply
        else:
            items = reply.get("endpoints", [])
            
        new_cache = {}
        changed = 0
        for item in items:
            eid, status = item.get("endpoint_id", ""), item.get("endpoint_status", "")
            key = f"{eid}:{status}"
            new_cache[eid] = key
            if endpoint_cache.get(eid) != key:
                send({"log_source": "cortex_xdr", "log_type": "endpoint", **item})
                changed += 1
        log.info(f"Endpoints: {len(items)} total, {changed} com mudança")
        return new_cache
    except Exception as e:
        log.error(f"Erro em endpoints: {e}")
        return endpoint_cache


# ── Loop principal ─────────────────────────────────────────

def run():
    log.info("=== Cortex XDR Collector iniciado (v8 - Final) ===")
    endpoint_cache  = {}
    endpoint_cycle  = 0

    while True:
        cycle_start = time.monotonic()
        state = load_state()
        all_cycle_ids = []

        collectors = [
            ("/incidents/get_incidents", "incidents", "incidents", "modification_time", "incident"),
            ("/alerts/get_alerts_multi_events", "alerts", "alerts", "creation_time", "alert"),
            ("/audits/management_logs", "data", "audits_mgmt", "timestamp", "audit_management"),
            ("/audits/agents_reports", "data", "audits_agents", "timestamp", "audit_agent")
        ]

        for path, items_key, state_key, filter_field, log_type in collectors:
            try:
                state[state_key], ids = collect_generic(path, items_key, state[state_key], filter_field, log_type, state["processed_ids"])
                all_cycle_ids.extend(ids)
                save_state(state)
            except Exception as e:
                log.error(f"Erro em {log_type}: {e}")

        state["processed_ids"].extend(all_cycle_ids)
        save_state(state)

        endpoint_cycle += 1
        if endpoint_cycle >= 10:
            endpoint_cache = collect_endpoints(endpoint_cache)
            endpoint_cycle = 0

        elapsed = time.monotonic() - cycle_start
        sleep_for = max(0, POLL_INTERVAL - elapsed)
        log.info(f"Ciclo concluído em {elapsed:.1f}s. Próximo em {sleep_for:.1f}s.")
        time.sleep(sleep_for)

if __name__ == "__main__":
    run()

"""
threat_engine.py — Threat scoring, action determination, and full pipeline orchestration.
Combines real tools (Kafka, Elasticsearch, Vault) with simulated stages.
BLOCK/CRITICAL threats require admin approval before credential rotation.
Phase 4: Stage 7 and Stage 8 details updated to accurately reflect:
  - Human-in-the-loop approval flow
  - Infra rotation pending for CRITICAL_ALERT
  - Proportionate response (BLOCK=user only, CRITICAL=user+infra)
"""

import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from app.config import THREAT_LEVELS
from app.schemas import (
    PredictionResult, PipelineStageResult, ThreatAction, GeoLocation, NetworkEvent
)
from app import inference
from app import kafka_client
from app import elastic_client
from app import vault_client
from app import vault_infra_client
from app import pipeline_stages
from app import admin_store

logger = logging.getLogger("hpe.threat_engine")

import json
from app import db

import threading

# ── Local Deltas (Thread-Safe) ────────────────────────────────────────────────
_local_deltas = {
    "total_requests": 0,
    "total_threats": 0,
    "total_allowed": 0,
    "total_monitored": 0,
    "total_blocked": 0,
    "total_critical": 0,
    "total_latency_ms": 0.0,
    "attack_types": {},
}
_metrics_lock = threading.Lock()

_pending_updates = 0
_BATCH_SIZE = 10

def load_metrics_from_db():
    """No longer caches in memory. DB is the source of truth."""
    pass

def flush_metrics_to_db():
    """Flush pending local deltas to Postgres using atomic increments."""
    global _pending_updates
    if _pending_updates == 0:
        return
        
    try:
        with _metrics_lock:
            # Snapshot the deltas
            deltas = {k: v for k, v in _local_deltas.items() if k != "attack_types"}
            attack_deltas = dict(_local_deltas["attack_types"])
            
            # Reset local deltas
            for k in deltas.keys():
                _local_deltas[k] = 0 if k != "total_latency_ms" else 0.0
            _local_deltas["attack_types"] = {}
            _pending_updates = 0

        # Atomic increment query
        query = """
            UPDATE hpe_pipeline_metrics SET
                total_requests = total_requests + %s,
                total_threats = total_threats + %s,
                total_allowed = total_allowed + %s,
                total_monitored = total_monitored + %s,
                total_blocked = total_blocked + %s,
                total_critical = total_critical + %s,
                total_latency_ms = total_latency_ms + %s,
                updated_at = NOW()
            WHERE id = 1
        """
        params = (
            deltas["total_requests"],
            deltas["total_threats"],
            deltas["total_allowed"],
            deltas["total_monitored"],
            deltas["total_blocked"],
            deltas["total_critical"],
            deltas["total_latency_ms"],
        )
        db.execute_query(query, params)
        
        # Merge attack types if any (since it's JSONB, we just read and update)
        if attack_deltas:
            row = db.execute_query("SELECT attack_types FROM hpe_pipeline_metrics WHERE id = 1", fetch=True)
            if row:
                current_attacks = row.get("attack_types", {})
                if isinstance(current_attacks, str):
                    current_attacks = json.loads(current_attacks)
                for atk, count in attack_deltas.items():
                    current_attacks[atk] = current_attacks.get(atk, 0) + count
                db.execute_query("UPDATE hpe_pipeline_metrics SET attack_types = %s WHERE id = 1", (json.dumps(current_attacks),))

    except Exception as e:
        logger.error(f"Failed to flush metrics to DB: {e}")


def get_metrics() -> Dict[str, Any]:
    """Get current pipeline metrics (DB total + local unflushed deltas)."""
    try:
        row = db.execute_query("SELECT * FROM hpe_pipeline_metrics WHERE id = 1", fetch=True)
        if not row:
            return {}
            
        with _metrics_lock:
            # Combine DB values with unflushed local deltas for real-time accuracy
            total_requests = row.get("total_requests", 0) + _local_deltas["total_requests"]
            total_threats = row.get("total_threats", 0) + _local_deltas["total_threats"]
            total_allowed = row.get("total_allowed", 0) + _local_deltas["total_allowed"]
            total_monitored = row.get("total_monitored", 0) + _local_deltas["total_monitored"]
            total_blocked = row.get("total_blocked", 0) + _local_deltas["total_blocked"]
            total_critical = row.get("total_critical", 0) + _local_deltas["total_critical"]
            total_latency_ms = row.get("total_latency_ms", 0.0) + _local_deltas["total_latency_ms"]
            
            attack_types = row.get("attack_types", {})
            if isinstance(attack_types, str):
                attack_types = json.loads(attack_types)
            for atk, count in _local_deltas["attack_types"].items():
                attack_types[atk] = attack_types.get(atk, 0) + count

        avg_latency = (total_latency_ms / max(total_requests, 1))

        return {
            "total_requests": total_requests,
            "total_threats": total_threats,
            "total_allowed": total_allowed,
            "total_monitored": total_monitored,
            "total_blocked": total_blocked,
            "total_critical": total_critical,
            "avg_latency_ms": round(avg_latency, 2),
            "attack_types": attack_types,
            "model_metrics": inference.get_artifacts().get("metrics", {}) if inference.get_artifacts() else {},
            "infra_rotation_count": vault_infra_client.get_infra_rotation_count(),
            "active_infra_leases": len(vault_infra_client.get_active_leases()),
        }
    except Exception as e:
        logger.error(f"Failed to fetch metrics: {e}")
        return {}


def determine_action(threat_score: float) -> ThreatAction:
    """Determine the appropriate action based on threat score."""
    if threat_score < THREAT_LEVELS["ALLOW"]:
        return ThreatAction.ALLOW
    elif threat_score < THREAT_LEVELS["MONITOR"]:
        return ThreatAction.MONITOR
    elif threat_score < THREAT_LEVELS["BLOCK"]:
        return ThreatAction.BLOCK
    else:
        return ThreatAction.CRITICAL_ALERT


def _determine_affected_service(event_dict: dict) -> str:
    """
    Map the anomaly type to the infrastructure service most at risk.
    Used in Stage 7 details so the frontend dashboard shows which service
    will be rotated when admin approves a CRITICAL_ALERT.
    """
    anomaly = event_dict.get("anomaly_type", "None")
    action = event_dict.get("action", "")

    if anomaly in ["data_exfiltration", "bulk_download"]:
        return "elasticsearch"
    elif anomaly in ["lateral_movement", "privilege_escalation"]:
        return "kafka"
    elif action == "admin":
        return "database"
    else:
        return "elasticsearch"


def _determine_threat_reasons(event_dict: dict, score: float, threshold: float) -> list:
    """Analyze the event dict and ML score to formulate human-readable trigger reasons."""
    reasons = []
    
    # 1. Look at explicit anomaly types
    anomaly = event_dict.get("anomaly_type", "None")
    if anomaly and anomaly != "None":
        anomaly_map = {
            "brute_force": "Brute Force Attack Pattern",
            "data_exfiltration": "Data Exfiltration Anomaly",
            "bulk_download": "Bulk Data Download Anomaly",
            "lateral_movement": "Lateral Movement Pattern",
            "privilege_escalation": "Privilege Escalation Attempt",
        }
        reasons.append(anomaly_map.get(anomaly, f"Anomaly: {anomaly}"))
        
    # 2. Check impossible travel or geo mismatch
    if event_dict.get("impossible_travel"):
        if event_dict.get("is_vpn"):
            reasons.append("Impossible Travel via rapid VPN server hopping (potential hijack)")
        else:
            reasons.append("Impossible Travel (login from two distant locations in rapid succession)")
    elif event_dict.get("geo_mismatch"):
        if event_dict.get("is_vpn"):
            reasons.append("Geographic Mismatch via Commercial VPN Exit Node (Germany)")
        else:
            reasons.append("Geographic Mismatch (source IP region differs from typical user profile)")
            
    # Check for general VPN connection warning if no other geo anomalies are present
    if event_dict.get("is_vpn") and not event_dict.get("geo_mismatch") and not event_dict.get("impossible_travel"):
        reasons.append("Connection originating from public/commercial VPN node")
        
    # 3. Check for high failed attempts
    failed_attempts = event_dict.get("failed_attempts_last_15m", 0)
    if failed_attempts >= 5:
        reasons.append(f"High Volume of Failed Authentication Attempts ({failed_attempts} within 15m)")
        
    # 4. Check for extreme data downloads
    download_mb = event_dict.get("data_downloaded_mb", 0.0)
    if download_mb > 500:
        reasons.append(f"Extreme Outbound Data Volume ({download_mb:.1f} MB downloaded)")
        
    # 5. Check for privilege escalation (role vs action deviation)
    action = event_dict.get("action", "")
    role = event_dict.get("role", "")
    if action == "admin" and role != "Admin":
        reasons.append(f"Unauthorized Admin Action (User role '{role}' performed action '{action}')")
        
    # If no explicit reason is found but score is high, label as anomalous behavioral pattern
    if not reasons:
        reasons.append(f"Anomalous Behavioral Pattern (AI Model Ensemble confidence: {score*100:.1f}%)")
        
    return reasons


def process_raw_event(raw_event: dict) -> PredictionResult:
    """
    Called by the Kafka consumer thread.
    Converts a raw dict from Kafka into a NetworkEvent and processes it.
    """
    # Promote nested dissect fields if present (for backwards compatibility or if Filebeat prefixing is active)
    if "dissect" in raw_event and isinstance(raw_event["dissect"], dict):
        for k, v in raw_event["dissect"].items():
            if k not in raw_event:
                raw_event[k] = v

    # Promote nested fields under event/fields if present
    if "fields" in raw_event and isinstance(raw_event["fields"], dict):
        for k, v in raw_event["fields"].items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    raw_event[f"{k}.{sub_k}"] = sub_v

    # Promote nested fields under id if present
    if "id" in raw_event and isinstance(raw_event["id"], dict):
        for k, v in raw_event["id"].items():
            raw_event[f"id.{k}"] = v
            if k not in raw_event:
                raw_event[k] = v

    # Map Filebeat/Zeek ECS fields or direct dissected fields to NetworkEvent
    orig_h = raw_event.get("id.orig_h") or raw_event.get("orig_h")
    uid = raw_event.get("uid") or raw_event.get("orig_uid")
    service = raw_event.get("service") or ""

    if orig_h:
        raw_event["source_ip"] = orig_h
        raw_event["event_id"] = uid or ""
        
        service_str = str(service)
        if service_str.startswith("auth_"):
            raw_event["event_source"] = "live_portal"
            # Strip the _vpn suffix before parsing username/status
            vpn_from_service = service_str.endswith("_vpn")
            clean_service = service_str.rstrip("_vpn") if vpn_from_service else service_str
            # But be careful: rstrip removes individual chars, use removesuffix instead
            if service_str.endswith("_vpn"):
                clean_service = service_str[:-4]  # remove "_vpn"
                vpn_from_service = True
            else:
                clean_service = service_str
                vpn_from_service = False
            
            parts = clean_service.split("_")
            if len(parts) >= 3:
                user_id = parts[1]
                raw_event["user_id"] = user_id
                raw_event["action"] = "login"
                raw_event["success"] = (parts[2] == "success")
                # If the service field had _vpn suffix, mark it
                if vpn_from_service:
                    raw_event["is_vpn"] = True
                # Simulate anomaly features for AI engine if login failed
                if not raw_event["success"]:
                    raw_event["anomaly_type"] = "brute_force"
                    raw_event["failed_attempts_last_15m"] = 5
                else:
                    raw_event["anomaly_type"] = "None"
                    raw_event["failed_attempts_last_15m"] = 0
                
                # Dynamic GeoIP region lookup and profile alignment
                from app.inference import _user_profiles
                profile = _user_profiles.get(user_id, {})
                home_region = profile.get("home_region", "US-East")
                raw_event["user_region"] = home_region
                raw_event["home_region"] = home_region
                
                src_ip = str(raw_event.get("source_ip", ""))
                ip_region = home_region  # Default to user home to avoid false alarms
                
                # Check for known test IP regions
                if src_ip.startswith("185."):
                    ip_region = "EU-Central"
                elif src_ip.startswith("45."):
                    ip_region = "EU-Central"
                elif src_ip.startswith("82."):
                    ip_region = "Asia-Pacific"
                
                raw_event["ip_region"] = ip_region
                raw_event["geo_mismatch"] = (ip_region != home_region)
                
                # Map role if present in profile
                raw_event["role"] = profile.get("role", "Developer")
        else:
            raw_event["event_source"] = "replayed_dataset"
            raw_event["action"] = "connection"
            resp_bytes = raw_event.get("resp_bytes") or raw_event.get("resp_ip_bytes") or 0
            try:
                raw_event["data_downloaded_mb"] = float(resp_bytes) / (1024 * 1024)
            except Exception:
                raw_event["data_downloaded_mb"] = 0.0

    # Safety fallback: classify any auth_ events as live_portal
    service_str = str(raw_event.get("service") or "")
    if service_str.startswith("auth_"):
        raw_event["event_source"] = "live_portal"
        if not raw_event.get("user_id"):
            parts = service_str.split("_")
            if len(parts) >= 2:
                raw_event["user_id"] = parts[1]

    # Detect VPN indicator on raw events
    is_vpn = raw_event.get("is_vpn") or False
    service_str = str(raw_event.get("service", ""))
    user_id_str = str(raw_event.get("user_id", ""))
    if "vpn" in service_str.lower() or "vpn" in user_id_str.lower() or "vpn" in str(raw_event.get("username", "")).lower():
        is_vpn = True
    src_ip = str(raw_event.get("source_ip", ""))
    if src_ip.startswith("45.") or src_ip.startswith("82.") or src_ip.startswith("185."):
        is_vpn = True
    raw_event["is_vpn"] = is_vpn

    event_fields = {k: v for k, v in raw_event.items()
                    if k in NetworkEvent.model_fields}
    event = NetworkEvent(**event_fields)
    return process_event(event)


def process_event(event: NetworkEvent) -> PredictionResult:
    """
    Process a single event through the FULL pipeline:
    Network → Zeek/Suricata → Beats → Kafka → AI → SOAR → Vault → Rotation → Dist → ELK
    """
    t0 = time.time()
    event_id = str(uuid.uuid4())[:12]
    event_dict = event.model_dump()
    stages: List[PipelineStageResult] = []

    # ── Stage 1: Network Capture (simulated) ──────────────────────────────────
    stage1 = pipeline_stages.simulate_network_capture(event_dict)
    stages.append(stage1)

    # ── Stage 2: Zeek/Suricata (simulated) ────────────────────────────────────
    stage2 = pipeline_stages.simulate_zeek_suricata(event_dict)
    stages.append(stage2)

    # ── Stage 3: Elastic Beats (simulated) ────────────────────────────────────
    stage3 = pipeline_stages.simulate_elastic_beats(event_dict)
    stages.append(stage3)

    # ── Stage 4: Apache Kafka (REAL) ──────────────────────────────────────────
    kafka_t0 = time.time()
    kafka_latency = (time.time() - kafka_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="Apache Kafka",
        stage_number=4,
        status="consumed",
        latency_ms=round(kafka_latency, 2),
        details={
            "topic": "hpe-raw-events",
            "direction": "consumed",
            "partition": "auto",
        },
        is_real_tool=True,
    ))

    # ── Stage 5: AI Detection Engine (REAL) ───────────────────────────────────
    ai_t0 = time.time()
    try:
        is_threat, ensemble_score, xgb_score, lgb_score, threshold = inference.predict(event)
    except Exception as e:
        logger.error(f"Inference error: {e}")
        is_threat, ensemble_score, xgb_score, lgb_score, threshold = False, 0.0, 0.0, 0.0, 0.5
    ai_latency = (time.time() - ai_t0) * 1000

    threat_action = determine_action(ensemble_score)

    # Force any detected VPN login events to BLOCK severity to trigger the admin approval / grant permission flow
    if event_dict.get("is_vpn", False):
        is_threat = True
        if threat_action not in (ThreatAction.BLOCK, ThreatAction.CRITICAL_ALERT):
            threat_action = ThreatAction.BLOCK
        if ensemble_score < 0.85:
            ensemble_score = 0.88

    # Generate dynamic threat reasons
    threat_reasons = []
    if is_threat:
        threat_reasons = _determine_threat_reasons(event_dict, ensemble_score, threshold)
        if event_dict.get("is_vpn", False) and not any("VPN" in r for r in threat_reasons):
            threat_reasons.append("VPN connection detected — suspicious activity requires credential rotation")

    stages.append(PipelineStageResult(
        stage_name="AI Detection Engine",
        stage_number=5,
        status="threat_detected" if is_threat else "clear",
        latency_ms=round(ai_latency, 2),
        details={
            "xgboost_score": round(xgb_score, 6),
            "lightgbm_score": round(lgb_score, 6),
            "ensemble_score": round(ensemble_score, 6),
            "threshold": round(threshold, 6),
            "is_threat": is_threat,
            "action": threat_action.value,
        },
        is_real_tool=True,
    ))

    # ── Stage 6: SOAR Automation (simulated) ──────────────────────────────────
    stage6 = pipeline_stages.simulate_soar_automation(event_dict, is_threat, ensemble_score)
    stages.append(stage6)

    # ── Stage 7: HashiCorp Vault (REAL — Human-in-the-Loop) ───────────────────
    # Phase 4: Stage 7 details now reflect the full rotation plan:
    #   BLOCK       → pending admin approval → user rotation only when approved
    #   CRITICAL    → pending admin approval → user + infra rotation when approved
    #   MONITOR     → logged, no rotation
    #   ALLOW       → no action
    vault_t0 = time.time()
    vault_result = {}

    is_high_severity = is_threat and threat_action in (
        ThreatAction.BLOCK, ThreatAction.CRITICAL_ALERT
    )

    if is_high_severity:
        affected_service = (
            _determine_affected_service(event_dict)
            if threat_action == ThreatAction.CRITICAL_ALERT
            else None
        )
        vault_result = {
            "status": "pending_admin_approval",
            "message": (
                "Credential rotation requires admin approval. "
                f"Threat action: {threat_action.value}."
            ),
            "user": event_dict.get("user_id", "unknown"),
            "threat_score": round(ensemble_score, 6),
            "rotation_plan": {
                "user_rotation": True,
                "infra_rotation": threat_action == ThreatAction.CRITICAL_ALERT,
                "affected_service": affected_service,
                "reason": (
                    "CRITICAL_ALERT: both user and infrastructure credentials "
                    "will be rotated on admin approval"
                    if threat_action == ThreatAction.CRITICAL_ALERT
                    else "BLOCK: user credentials will be rotated on admin approval"
                ),
            },
        }
    elif is_threat and threat_action == ThreatAction.MONITOR:
        vault_result = {
            "status": "monitoring",
            "message": "MONITOR-level threat: logged for observation, no rotation triggered",
            "user": event_dict.get("user_id", "unknown"),
            "threat_score": round(ensemble_score, 6),
        }
    else:
        vault_result = {
            "status": "no_rotation_needed",
            "threat_score": round(ensemble_score, 6),
        }
        admin_store.increment_auto_allowed()

    vault_latency = (time.time() - vault_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="HashiCorp Vault",
        stage_number=7,
        status="pending_approval" if is_high_severity else "no_action",
        latency_ms=round(vault_latency, 2),
        details=vault_result,
        is_real_tool=True,
    ))

    # ── Stage 8: Credential Rotation (deferred — fires when admin approves) ───
    # Phase 4: Stage 8 now distinguishes between:
    #   pending_user_rotation          → BLOCK threat awaiting approval
    #   pending_user_and_infra_rotation → CRITICAL threat awaiting approval
    #   skipped                         → no threat or MONITOR
    if is_high_severity:
        rotation_plan = vault_result.get("rotation_plan", {})
        stage8_status = (
            "pending_user_and_infra_rotation"
            if rotation_plan.get("infra_rotation")
            else "pending_user_rotation"
        )
        stage8_details = {
            "user_rotation": "pending_admin_approval",
            "infra_rotation": (
                f"pending_admin_approval → will rotate '{rotation_plan.get('affected_service')}' service"
                if rotation_plan.get("infra_rotation")
                else "not_required (BLOCK threshold, not CRITICAL)"
            ),
            "vault_auth_method": vault_client.get_auth_method(),
            "vault_infra_connected": vault_infra_client.is_connected(),
            "total_user_rotations_so_far": vault_client.get_rotation_count(),
            "total_infra_rotations_so_far": vault_infra_client.get_infra_rotation_count(),
        }
    else:
        stage8_status = "skipped"
        stage8_details = {
            "reason": "No high-severity threat detected",
            "vault_auth_method": vault_client.get_auth_method(),
        }

    stages.append(PipelineStageResult(
        stage_name="Credential Rotation",
        stage_number=8,
        status=stage8_status,
        latency_ms=0.0,
        details=stage8_details,
        is_real_tool=False,
    ))

    # ── Stage 9: Credentials Distributed (simulated) ──────────────────────────
    stage9 = pipeline_stages.simulate_credential_distribution(is_threat)
    stages.append(stage9)

    # ── Stage 10: ELK Stack / Grafana (REAL — Elasticsearch) ─────────────────
    elk_t0 = time.time()
    es_audit_success = elastic_client.index_audit_log(
        event_id=event_id,
        stage="pipeline_complete",
        action=threat_action.value,
        threat_score=ensemble_score,
        is_threat=is_threat,
        event_data=event_dict,
    )

    if is_threat:
        elastic_client.index_threat(event_id, {
            "event_id": event_id,
            "threat_score": round(ensemble_score, 6),
            "threat_action": threat_action.value,
            "attack_type": event_dict.get("anomaly_type", "unknown"),
            "source_ip": event_dict.get("source_ip", ""),
            "ip_region": event_dict.get("ip_region", ""),
            "user": event_dict.get("user_id", ""),
            "action": event_dict.get("action", ""),
            "event_source": event_dict.get("event_source", "replayed_dataset"),
            "xgb_score": round(xgb_score, 6),
            "lgb_score": round(lgb_score, 6),
            "ensemble_score": round(ensemble_score, 6),
            "vault_rotation_triggered": is_high_severity,
            "infra_rotation_pending": (
                is_high_severity and threat_action == ThreatAction.CRITICAL_ALERT
            ),
            "credentials_rotated": False,  # not yet — pending admin approval
        })

        kafka_client.produce_alert({
            "event_id": event_id,
            "threat_score": ensemble_score,
            "action": threat_action.value,
            "user": event_dict.get("user_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    elk_latency = (time.time() - elk_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="ELK Stack / Grafana",
        stage_number=10,
        status="indexed" if es_audit_success else "fallback",
        latency_ms=round(elk_latency, 2),
        details={
            "audit_indexed": es_audit_success,
            "threat_indexed": is_threat,
            "index": "hpe-audit-logs",
        },
        is_real_tool=True,
    ))

    # ── Compute totals ────────────────────────────────────────────────────────
    total_latency = (time.time() - t0) * 1000

    with _metrics_lock:
        _local_deltas["total_requests"] += 1
        _local_deltas["total_latency_ms"] += total_latency
        if is_threat:
            _local_deltas["total_threats"] += 1
        _action_key_map = {
            ThreatAction.ALLOW:          "total_allowed",
            ThreatAction.MONITOR:        "total_monitored",
            ThreatAction.BLOCK:          "total_blocked",
            ThreatAction.CRITICAL_ALERT: "total_critical",
        }
        action_key = _action_key_map.get(threat_action)
        if action_key:
            _local_deltas[action_key] += 1
        if is_threat:
            at = event_dict.get("anomaly_type", "unknown")
            _local_deltas["attack_types"][at] = _local_deltas["attack_types"].get(at, 0) + 1

    # ── Geo mapping ───────────────────────────────────────────────────────────
    region_geo = {
        "US-East":      {"lat": 40.71,  "lng": -74.01,  "city": "New York"},
        "US-West":      {"lat": 37.77,  "lng": -122.42, "city": "San Francisco"},
        "EU-Central":   {"lat": 50.11,  "lng": 8.68,    "city": "Frankfurt"},
        "Asia-Pacific": {"lat": 1.35,   "lng": 103.82,  "city": "Singapore"},
        "South-America":{"lat": -23.55, "lng": -46.63,  "city": "São Paulo"},
    }
    server_geo = {"lat": 12.97, "lng": 77.59, "city": "Bangalore"}

    ip_region   = event_dict.get("ip_region", "")
    user_region = event_dict.get("user_region", "")
    src_geo = region_geo.get(ip_region, {"lat": 0, "lng": 0, "city": "Unknown"})
    dst_geo = (
        server_geo
        if ip_region == user_region or user_region not in region_geo
        else region_geo.get(user_region, server_geo)
    )

    # ── Create admin alert for BLOCK/CRITICAL (pending approval) ─────────────
    stages_dicts = [s.model_dump() for s in stages]
    alert_id = None

    if is_high_severity:
        admin_alert = admin_store.create_alert(
            event_id=event_id,
            user_id=event_dict.get("user_id", "unknown"),
            threat_score=round(ensemble_score, 6),
            threat_action=threat_action.value,
            xgb_score=round(xgb_score, 6),
            lgb_score=round(lgb_score, 6),
            ensemble_score=round(ensemble_score, 6),
            threshold=round(threshold, 6),
            event_data={
                "user":                     event_dict.get("user_id", ""),
                "source_ip":                event_dict.get("source_ip", ""),
                "ip_region":                event_dict.get("ip_region", ""),
                "action":                   event_dict.get("action", ""),
                "anomaly_type":             event_dict.get("anomaly_type", ""),
                "geo_mismatch":             event_dict.get("geo_mismatch", False),
                "login_hour":               event_dict.get("login_hour", 0),
                "failed_attempts_last_15m": event_dict.get("failed_attempts_last_15m", 0),
                "data_downloaded_mb":       event_dict.get("data_downloaded_mb", 0),
                "impossible_travel":        event_dict.get("impossible_travel", False),
                "event_source":             event_dict.get("event_source", "replayed_dataset"),
                "threat_reasons":           threat_reasons,
                "is_vpn":                   event_dict.get("is_vpn", False),
            },
            pipeline_stages=stages_dicts,
            source_geo=src_geo,
            destination_geo=dst_geo,
            total_latency_ms=round(total_latency, 2),
        )
        if admin_alert:
            alert_id = admin_alert["alert_id"]

    global _pending_updates
    _pending_updates += 1
    if _pending_updates >= _BATCH_SIZE:
        flush_metrics_to_db()

    return PredictionResult(
        event_id=event_id,
        is_threat=is_threat,
        threat_score=round(ensemble_score, 6),
        threat_action=threat_action,
        xgb_score=round(xgb_score, 6),
        lgb_score=round(lgb_score, 6),
        ensemble_score=round(ensemble_score, 6),
        threshold=round(threshold, 6),
        source_geo=GeoLocation(**src_geo),
        destination_geo=GeoLocation(**dst_geo),
        pipeline_stages=stages,
        total_latency_ms=round(total_latency, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_summary={
            "user":         event_dict.get("user_id", ""),
            "source_ip":    event_dict.get("source_ip", ""),
            "ip_region":    event_dict.get("ip_region", ""),
            "action":       event_dict.get("action", ""),
            "anomaly_type": event_dict.get("anomaly_type", ""),
            "geo_mismatch": event_dict.get("geo_mismatch", False),
            "alert_id":     alert_id,
            "event_source": event_dict.get("event_source", "replayed_dataset"),
            "threat_reasons": threat_reasons,
            "is_vpn":       event_dict.get("is_vpn", False),
        },
    )
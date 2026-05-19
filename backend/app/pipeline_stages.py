"""
pipeline_stages.py — Simulated pipeline stages for Zeek/Suricata, Elastic Beats, and SOAR.
Also provides the full pipeline orchestration that combines real + simulated stages.
"""

import time
import uuid
import logging
import random
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.schemas import PipelineStageResult

logger = logging.getLogger("hpe.pipeline")


# ── Stage definitions ──────────────────────────────────────────────────────────
PIPELINE_STAGES = [
    {"name": "Network/Applications", "number": 1, "is_real": False, "icon": "globe"},
    {"name": "Zeek/Suricata", "number": 2, "is_real": False, "icon": "shield"},
    {"name": "Elastic Beats", "number": 3, "is_real": True, "icon": "activity"},
    {"name": "Apache Kafka", "number": 4, "is_real": True, "icon": "zap"},
    {"name": "AI Detection Engine", "number": 5, "is_real": True, "icon": "brain"},
    {"name": "SOAR (StackStorm)", "number": 6, "is_real": False, "icon": "workflow"},
    {"name": "HashiCorp Vault", "number": 7, "is_real": True, "icon": "lock"},
    {"name": "Credential Rotation", "number": 8, "is_real": False, "icon": "refresh"},
    {"name": "Credentials Distributed", "number": 9, "is_real": False, "icon": "share"},
    {"name": "ELK Stack / Grafana", "number": 10, "is_real": True, "icon": "bar-chart"},
]


def get_stage_definitions() -> List[Dict[str, Any]]:
    """Return all pipeline stage definitions."""
    return PIPELINE_STAGES


# ── Simulated stage processors ────────────────────────────────────────────────

def simulate_network_capture(event: Dict[str, Any]) -> PipelineStageResult:
    """Stage 1: Simulate network/application traffic capture."""
    t0 = time.time()

    # Simulate network metadata enrichment
    enriched = {
        "capture_interface": random.choice(["eth0", "eth1", "bond0"]),
        "packet_size": random.randint(64, 1500),
        "tcp_flags": random.choice(["SYN", "SYN-ACK", "ACK", "PSH-ACK", "FIN"]),
        "vlan_id": random.randint(1, 100),
    }

    latency = (time.time() - t0) * 1000 + random.uniform(0.5, 2.0)

    return PipelineStageResult(
        stage_name="Network/Applications",
        stage_number=1,
        status="captured",
        latency_ms=round(latency, 2),
        details=enriched,
        is_real_tool=False,
    )


def simulate_zeek_suricata(event: Dict[str, Any]) -> PipelineStageResult:
    """Stage 2: Simulate Zeek/Suricata traffic analysis."""
    t0 = time.time()

    protocol = event.get("protocol", "TCP")
    process = event.get("process_name", "")

    # Simulate IDS signature matching
    suricata_alerts = []
    zeek_conn = {
        "uid": f"C{uuid.uuid4().hex[:12]}",
        "proto": protocol,
        "service": _guess_service(process),
        "duration": round(random.uniform(0.001, 30.0), 3),
        "orig_bytes": random.randint(100, 50000),
        "resp_bytes": random.randint(100, 100000),
        "conn_state": random.choice(["SF", "S0", "REJ", "RSTO"]),
    }

    # Check for suspicious patterns
    cmd = event.get("command_line", "")
    suspicious = any(k in str(cmd).lower() for k in [
        "powershell", "mimikatz", "net user", "whoami", "lateral",
        "domain_controller", "psexec", "wmic", "certutil"
    ])

    if suspicious:
        suricata_alerts.append({
            "sid": random.randint(2000000, 2999999),
            "msg": "ET POLICY Suspicious Process Activity Detected",
            "severity": random.choice([1, 2, 3]),
        })

    latency = (time.time() - t0) * 1000 + random.uniform(1.0, 5.0)

    return PipelineStageResult(
        stage_name="Zeek/Suricata",
        stage_number=2,
        status="analyzed",
        latency_ms=round(latency, 2),
        details={
            "zeek_connection": zeek_conn,
            "suricata_alerts": suricata_alerts,
            "suspicious_indicators": suspicious,
        },
        is_real_tool=False,
    )


def simulate_elastic_beats(event: Dict[str, Any]) -> PipelineStageResult:
    """Stage 3: Simulate Elastic Beats log collection and normalization."""
    t0 = time.time()

    normalized = {
        "agent_type": "filebeat",
        "agent_version": "8.15.0",
        "ecs_version": "8.0",
        "event_category": _classify_event(event.get("event_type", "")),
        "event_kind": "event",
        "event_module": event.get("log_type", "security"),
        "host_name": event.get("hostname", ""),
        "host_os": "Windows Server 2022",
        "geo_enriched": True,
    }

    latency = (time.time() - t0) * 1000 + random.uniform(0.5, 3.0)

    return PipelineStageResult(
        stage_name="Elastic Beats",
        stage_number=3,
        status="normalized",
        latency_ms=round(latency, 2),
        details=normalized,
        is_real_tool=True,
    )


def simulate_soar_automation(event: Dict[str, Any], is_threat: bool,
                             threat_score: float) -> PipelineStageResult:
    """Stage 6: Simulate SOAR/StackStorm workflow automation."""
    t0 = time.time()

    workflows_triggered = []
    if is_threat:
        workflows_triggered = [
            {"name": "threat_investigation", "status": "triggered", "priority": "high"},
            {"name": "credential_rotation", "status": "triggered", "priority": "critical"},
            {"name": "incident_notification", "status": "triggered", "priority": "high"},
            {"name": "forensic_snapshot", "status": "triggered", "priority": "medium"},
        ]
        if threat_score > 0.9:
            workflows_triggered.append(
                {"name": "network_isolation", "status": "triggered", "priority": "critical"}
            )
    else:
        workflows_triggered = [
            {"name": "baseline_update", "status": "triggered", "priority": "low"},
        ]

    latency = (time.time() - t0) * 1000 + random.uniform(2.0, 8.0)

    return PipelineStageResult(
        stage_name="SOAR (StackStorm)",
        stage_number=6,
        status="workflows_triggered" if is_threat else "passed",
        latency_ms=round(latency, 2),
        details={
            "workflows": workflows_triggered,
            "total_workflows": len(workflows_triggered),
            "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}" if is_threat else None,
        },
        is_real_tool=False,
    )


def simulate_credential_rotation(is_threat: bool, vault_result: Dict = None) -> PipelineStageResult:
    """Stage 8: Simulate credential rotation process."""
    t0 = time.time()

    if is_threat and vault_result and vault_result.get("success"):
        details = {
            "rotation_id": vault_result.get("rotation_id"),
            "services_rotated": vault_result.get("services_affected", []),
            "rotation_type": "emergency",
            "previous_creds_revoked": True,
        }
        status = "rotated"
    else:
        details = {"status": "no_rotation_needed"}
        status = "skipped"

    latency = (time.time() - t0) * 1000 + random.uniform(1.0, 5.0)

    return PipelineStageResult(
        stage_name="Credential Rotation",
        stage_number=8,
        status=status,
        latency_ms=round(latency, 2),
        details=details,
        is_real_tool=False,
    )


def simulate_credential_distribution(is_threat: bool) -> PipelineStageResult:
    """Stage 9: Simulate distributing rotated credentials to services."""
    t0 = time.time()

    if is_threat:
        details = {
            "targets": ["database-cluster", "api-gateway", "service-mesh", "load-balancer"],
            "distribution_method": "push",
            "encryption": "TLS 1.3",
            "all_targets_updated": True,
        }
        status = "distributed"
    else:
        details = {"status": "no_distribution_needed"}
        status = "skipped"

    latency = (time.time() - t0) * 1000 + random.uniform(1.0, 4.0)

    return PipelineStageResult(
        stage_name="Credentials Distributed",
        stage_number=9,
        status=status,
        latency_ms=round(latency, 2),
        details=details,
        is_real_tool=False,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _guess_service(process_name: str) -> str:
    """Guess network service from process name."""
    mapping = {
        "chrome": "http", "firefox": "http", "edge": "http",
        "outlook": "smtp", "thunderbird": "smtp",
        "powershell": "smb", "cmd": "smb",
        "ssh": "ssh", "sshd": "ssh",
        "dns": "dns", "nslookup": "dns",
    }
    for key, svc in mapping.items():
        if key in process_name.lower():
            return svc
    return "unknown"


def _classify_event(event_type: str) -> str:
    """Classify event into ECS category."""
    mapping = {
        "network_connection": "network",
        "process_start": "process",
        "file_access": "file",
        "authentication": "authentication",
        "dns_query": "network",
        "registry_change": "configuration",
    }
    return mapping.get(event_type, "host")

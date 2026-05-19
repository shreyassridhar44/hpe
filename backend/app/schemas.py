"""
schemas.py — Pydantic models for request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"
    CRITICAL_ALERT = "CRITICAL_ALERT"


class GeoLocation(BaseModel):
    lat: float = 0.0
    lng: float = 0.0
    city: str = "Unknown"


# ── Request schemas ────────────────────────────────────────────────────────────
class NetworkEvent(BaseModel):
    """A single network/security event from the log data."""
    event_id: Optional[str] = ""
    timestamp: Optional[str] = ""
    login_hour: Optional[int] = 0
    user_id: Optional[str] = ""
    workspace_id: Optional[str] = ""
    source_ip: Optional[str] = ""
    ip_region: Optional[str] = ""
    user_region: Optional[str] = ""
    geo_mismatch: Optional[bool] = False
    impossible_travel: Optional[bool] = False
    action: Optional[str] = ""
    success: Optional[bool] = True
    failed_attempts_last_15m: Optional[int] = 0
    data_downloaded_mb: Optional[float] = 0.0
    # Profile fields (merged on the fly or pre-merged)
    role: Optional[str] = ""
    remote_worker: Optional[bool] = False
    base_login_hour: Optional[float] = 9.0
    login_hour_std_dev: Optional[float] = 2.0
    avg_daily_downloads_mb: Optional[float] = 50.0
    home_region: Optional[str] = ""
    is_shift_worker: Optional[bool] = False
    clumsiness_factor: Optional[float] = 0.0
    # Attack metadata (for evaluation, not features)
    is_injected_anomaly: Optional[bool] = False
    anomaly_type: Optional[str] = "None"
    event_source: Optional[str] = "replayed_dataset"
    is_vpn: Optional[bool] = False

    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "network_connection",
                "user": "john.doe",
                "hostname": "WS-NYC-001",
                "process_name": "chrome.exe",
                "source_ip": "10.2.3.50",
                "destination_ip": "10.1.0.10",
                "timestamp": "2025-12-21 09:30:00",
            }
        }


class BatchPredictRequest(BaseModel):
    events: List[NetworkEvent]


# ── Response schemas ───────────────────────────────────────────────────────────
class PipelineStageResult(BaseModel):
    """Result from a single pipeline stage."""
    stage_name: str
    stage_number: int
    status: str = "completed"
    latency_ms: float = 0.0
    details: Dict[str, Any] = {}
    is_real_tool: bool = False


class PredictionResult(BaseModel):
    """Full prediction result with pipeline stages."""
    event_id: str
    is_threat: bool
    threat_score: float = Field(ge=0.0, le=1.0)
    threat_action: ThreatAction
    xgb_score: float = 0.0
    lgb_score: float = 0.0
    ensemble_score: float = 0.0
    threshold: float = 0.5
    source_geo: GeoLocation = GeoLocation()
    destination_geo: GeoLocation = GeoLocation()
    pipeline_stages: List[PipelineStageResult] = []
    total_latency_ms: float = 0.0
    timestamp: str = ""
    event_summary: Dict[str, Any] = {}


class HealthResponse(BaseModel):
    status: str = "healthy"
    app_name: str = "HPE"
    version: str = "1.0.0"
    uptime_seconds: float = 0.0
    model_loaded: bool = False
    kafka_connected: bool = False
    elasticsearch_connected: bool = False
    vault_connected: bool = False
    total_requests: int = 0
    total_threats_blocked: int = 0


class MetricsResponse(BaseModel):
    total_requests: int = 0
    total_threats: int = 0
    total_allowed: int = 0
    total_monitored: int = 0
    total_blocked: int = 0
    total_critical: int = 0
    avg_latency_ms: float = 0.0
    model_metrics: Dict[str, float] = {}
    pipeline_health: Dict[str, str] = {}
    attack_types: Dict[str, int] = {}


class PipelineStatusResponse(BaseModel):
    stages: List[Dict[str, Any]] = []
    total_events_processed: int = 0


class SimulationEvent(BaseModel):
    """A simulation event streamed via WebSocket."""
    event: NetworkEvent
    prediction: PredictionResult
    pipeline_stages: List[PipelineStageResult] = []


# ── Admin Dashboard schemas ───────────────────────────────────────────────────
class AdminAlert(BaseModel):
    """A pending threat alert awaiting admin approval."""
    alert_id: str
    event_id: str
    user_id: str
    threat_score: float
    threat_action: str
    xgb_score: float = 0.0
    lgb_score: float = 0.0
    ensemble_score: float = 0.0
    threshold: float = 0.5
    event_data: Dict[str, Any] = {}
    pipeline_stages: List[Dict[str, Any]] = []
    source_geo: Dict[str, Any] = {}
    destination_geo: Dict[str, Any] = {}
    total_latency_ms: float = 0.0
    status: str = "pending"  # pending | approved | rejected
    created_at: str = ""
    resolved_at: Optional[str] = None
    admin_notes: str = ""
    rotation_result: Optional[Dict[str, Any]] = None


class ApprovalRequest(BaseModel):
    """Request body for approving or rejecting an alert."""
    admin_notes: str = ""


class ApprovalResponse(BaseModel):
    """Response after an admin approval/rejection action."""
    success: bool
    alert_id: str
    action: str  # approved | rejected
    rotation_result: Optional[Dict[str, Any]] = None
    message: str = ""

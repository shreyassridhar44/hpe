"""
routes/admin.py — Security Admin Dashboard API endpoints.
Phase 4: CRITICAL_ALERT approval fires user + infrastructure rotation.
Phase 5: Kafka credential rotation via Vault KV + reconnect on CRITICAL_ALERT.
"""

import logging
import hashlib
from pydantic import BaseModel
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.schemas import ApprovalRequest, ApprovalResponse

class RegistrationApproval(BaseModel):
    password: str

from app import admin_store, vault_client, vault_infra_client

from app.ws_manager import admin_manager

logger = logging.getLogger("hpe.admin")
router = APIRouter(prefix="/api/admin", tags=["admin"])


def _determine_affected_service(event_data: dict) -> str:
    """
    Map anomaly type to the infrastructure service most at risk.

    Phase 5 routing:
      data_exfiltration / bulk_download  → elasticsearch (dynamic DB creds)
      lateral_movement / priv_escalation → kafka         (Vault KV + reconnect)
      admin action                        → database      (dynamic DB creds)
      default                             → elasticsearch
    """
    anomaly = event_data.get("anomaly_type", "None")
    action = event_data.get("action", "")

    if anomaly in ["data_exfiltration", "bulk_download"]:
        return "elasticsearch"
    elif anomaly in ["lateral_movement", "privilege_escalation"]:
        return "kafka"
    elif action == "admin":
        return "database"
    else:
        return "elasticsearch"


@router.get("/alerts")
async def get_alerts(status: str = None, severity: str = None, limit: int = 100):
    alerts = admin_store.get_all_alerts(status=status, severity=severity, limit=limit)
    pending_count = sum(1 for a in admin_store.get_all_alerts(status="pending"))
    return {
        "total": len(alerts),
        "pending_count": pending_count,
        "alerts": alerts,
    }


@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    alert = admin_store.get_alert(alert_id)
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    return alert


@router.post("/alerts/{alert_id}/approve", response_model=ApprovalResponse)
async def approve_alert(alert_id: str, request: ApprovalRequest):
    """
    Approve credential rotation for a threat alert.

    BLOCK       → user-level rotation only (vault_client)
    CRITICAL    → user-level + infrastructure rotation (vault_client + vault_infra_client)

    Phase 5: if affected_service == 'kafka', vault_infra_client rotates
    the Kafka KV secret and triggers kafka_client.reconnect_kafka().
    """
    alert = admin_store.approve_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="approve",
            message=f"Alert {alert_id} not found",
        )

    if alert["status"] != "approved":
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="approve",
            message=f"Alert already resolved as: {alert['status']}",
        )

    # ── User-level rotation (all approvals) ───────────────────────────────────
    user_rotation_result = vault_client.rotate_credentials(
        reason=f"admin_approved_{alert['threat_action'].lower()}_score_{alert['threat_score']:.4f}",
        user=alert["user_id"],
        threat_score=alert["threat_score"],
    )

    logger.info(
        f"[ADMIN] User credential rotation for {alert['user_id']} "
        f"(alert={alert_id}, success={user_rotation_result.get('success')}, "
        f"action={alert['threat_action']})"
    )

    # ── Infrastructure rotation (CRITICAL_ALERT only) ─────────────────────────
    infra_rotation_result = None
    affected_service = None

    if alert["threat_action"] == "CRITICAL_ALERT":
        if vault_infra_client.is_connected():
            affected_service = _determine_affected_service(alert.get("event_data", {}))
            infra_rotation_result = vault_infra_client.rotate_infrastructure_credentials(
                service=affected_service,
                reason=f"admin_approved_critical_score_{alert['threat_score']:.4f}",
                threat_score=alert["threat_score"],
            )

            # Phase 5 specific logging for Kafka rotation
            if affected_service == "kafka":
                kafka_reconnected = infra_rotation_result.get(
                    "new_credential", {}
                ).get("kafka_reconnected", False)
                logger.warning(
                    f"[ADMIN] Kafka credential rotation completed — "
                    f"alert={alert_id} "
                    f"vault_success={infra_rotation_result.get('success')} "
                    f"kafka_reconnected={kafka_reconnected}"
                )
            else:
                new_user = infra_rotation_result.get(
                    "new_credential", {}
                ).get("username", "n/a")
                logger.warning(
                    f"[ADMIN] Infrastructure credential rotation for "
                    f"service='{affected_service}' "
                    f"(alert={alert_id}, new_user='{new_user}', "
                    f"success={infra_rotation_result.get('success')})"
                )
        else:
            logger.warning(
                f"[ADMIN] Vault infra client not connected — "
                f"skipping infrastructure rotation for CRITICAL_ALERT {alert_id}"
            )
            infra_rotation_result = {
                "success": False,
                "error": "vault_infra_client not connected",
            }
    else:
        logger.info(
            f"[ADMIN] BLOCK threat approved — user rotation only "
            f"(score={alert['threat_score']:.4f} < 0.85 CRITICAL threshold)"
        )

    # ── Attach combined result to alert for audit trail ───────────────────────
    combined_result = {
        "user_rotation":    user_rotation_result,
        "infra_rotation":   infra_rotation_result,
        "affected_service": affected_service,
        "threat_action":    alert["threat_action"],
    }
    admin_store.set_rotation_result(alert_id, combined_result)

    # ── Broadcast to admin WebSocket clients ──────────────────────────────────
    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id":              alert_id,
            "action":                "approved",
            "user_id":               alert["user_id"],
            "threat_action":         alert["threat_action"],
            "user_rotation_success": user_rotation_result.get("success", False),
            "infra_rotation":        infra_rotation_result,
            "affected_service":      affected_service,
        },
    })

    # ── Build response message ────────────────────────────────────────────────
    message_parts = [f"User credentials rotated for {alert['user_id']}."]
    if infra_rotation_result and infra_rotation_result.get("success"):
        if affected_service == "kafka":
            kafka_reconnected = infra_rotation_result.get(
                "new_credential", {}
            ).get("kafka_reconnected", False)
            message_parts.append(
                f"Kafka credentials rotated in Vault and "
                f"{'reconnected' if kafka_reconnected else 'reconnect attempted'}."
            )
        else:
            new_user = infra_rotation_result.get("new_credential", {}).get("username", "")
            message_parts.append(
                f"Infrastructure credentials rotated for '{affected_service}' "
                f"(new DB user: {new_user[:24]}...)."
            )
    elif alert["threat_action"] == "CRITICAL_ALERT" and infra_rotation_result:
        message_parts.append(
            f"Infrastructure rotation attempted for '{affected_service}' "
            f"but failed: {infra_rotation_result.get('error', 'unknown')}."
        )

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="approved",
        rotation_result=combined_result,
        message=" ".join(message_parts),
    )


@router.post("/alerts/{alert_id}/reject", response_model=ApprovalResponse)
async def reject_alert(alert_id: str, request: ApprovalRequest):
    alert = admin_store.reject_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="reject",
            message=f"Alert {alert_id} not found",
        )

    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id": alert_id,
            "action":   "rejected",
            "user_id":  alert["user_id"],
        },
    })

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="rejected",
        message=f"Alert {alert_id} rejected as false positive.",
    )


@router.get("/stats")
async def get_admin_stats():
    stats = admin_store.get_stats()
    stats["infra_rotation_count"] = vault_infra_client.get_infra_rotation_count()
    stats["active_infra_leases"] = vault_infra_client.get_active_leases()
    return stats


@router.get("/audit-log")
async def get_audit_log(limit: int = 50):
    log = admin_store.get_audit_log(limit=limit)
    return {"total": len(log), "entries": log}


@router.get("/infra-leases")
async def get_infra_leases():
    """
    Get all active infrastructure leases including Kafka Vault KV status.
    Phase 5: Kafka section shows vault_managed_credential metadata.
    """
    return {
        "active_leases":         vault_infra_client.get_active_leases(),
        "total_infra_rotations": vault_infra_client.get_infra_rotation_count(),
        "vault_infra_connected": vault_infra_client.is_connected(),
    }


@router.get("/registrations")
async def get_registrations():
    """Fetch all users currently in 'pending' status."""
    from app import db
    query = "SELECT username, department, status FROM hpe_users WHERE status = 'pending'"
    try:
        users = db.execute_query(query, fetch=True, fetch_all=True)
        # Dynamically append VPN indicator based on signature
        for u in users:
            u["is_vpn"] = ("vpn" in str(u.get("username", "")).lower() or "vpn" in str(u.get("department", "")).lower())
        return {"total": len(users), "registrations": users}
    except Exception as e:
        logger.error(f"Failed to fetch pending registrations: {e}")
        return {"error": str(e)}


@router.post("/registrations/{username}/approve")
async def approve_registration(username: str, approval: RegistrationApproval):
    """Approve a pending user registration and set their password."""
    from app import db
    pass_hash = hashlib.sha256(approval.password.encode('utf-8')).hexdigest()
    try:
        db.execute_query(
            "UPDATE hpe_users SET status = 'active', password_hash = %s WHERE username = %s", 
            (pass_hash, username)
        )
        logger.info(f"[ADMIN] Registration approved and credentials issued for user: {username}")
        return {"success": True, "message": f"User {username} approved and credentials issued."}
    except Exception as e:
        logger.error(f"Failed to approve registration for {username}: {e}")
        return {"success": False, "message": str(e)}



@router.post("/registrations/{username}/reject")
async def reject_registration(username: str):
    """Reject and delete a pending user registration."""
    from app import db
    try:
        db.execute_query("DELETE FROM hpe_users WHERE username = %s AND status = 'pending'", (username,))
        logger.info(f"[ADMIN] Registration rejected/deleted for user: {username}")
        return {"success": True, "message": f"Registration for {username} rejected."}
    except Exception as e:
        logger.error(f"Failed to reject registration for {username}: {e}")
        return {"success": False, "message": str(e)}



@router.post("/reset")
async def reset_pipeline():
    """Wipe all pipeline state and start fresh."""
    try:
        from app import db, elastic_client, kafka_client
        import time

        # 1. Truncate all hpe_* Postgres tables and reset stats
        logger.warning("[FRESH RESTART] Wiping PostgreSQL state")
        db.execute_query("TRUNCATE TABLE hpe_admin_alerts, hpe_admin_audit_log, hpe_infra_leases, hpe_credential_rotations CASCADE")
        db.execute_query("UPDATE hpe_admin_stats SET total_alerts_created=0, total_approved=0, total_rejected=0, total_auto_allowed=0 WHERE id=1")
        db.execute_query("UPDATE hpe_pipeline_metrics SET total_requests=0, total_threats=0, total_allowed=0, total_monitored=0, total_blocked=0, total_critical=0, total_latency_ms=0, attack_types='{}' WHERE id=1")
        db.execute_query("UPDATE hpe_simulation_state SET sim_index=0 WHERE id=1")
        
        # 2. Reset in-memory caches
        from app import threat_engine
        import app.routes.simulate as simulate_route
        threat_engine._metrics = {
            "total_requests": 0, "total_threats": 0, "total_allowed": 0,
            "total_monitored": 0, "total_blocked": 0, "total_critical": 0,
            "total_latency_ms": 0.0, "attack_types": {},
        }
        threat_engine._pending_updates = 0
        simulate_route._sim_index = 0
        simulate_route._sim_batch_count = 0

        # 3. Delete Kafka topics
        logger.warning("[FRESH RESTART] Wiping Kafka topics")
        if kafka_client.is_connected() and kafka_client._admin:
            try:
                from app.config import KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC, KAFKA_AUDIT_TOPIC
                kafka_client._admin.delete_topics([KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC, KAFKA_AUDIT_TOPIC])
                time.sleep(2)  # Give Kafka time to delete
            except Exception as e:
                logger.error(f"Kafka topic deletion error: {e}")
        
        # 4. Delete ES indices
        logger.warning("[FRESH RESTART] Wiping Elasticsearch indices")
        if elastic_client.is_connected() and elastic_client._es:
            try:
                elastic_client._es.indices.delete(index='hpe-audit-logs', ignore_unavailable=True)
                elastic_client._es.indices.delete(index='hpe-threats', ignore_unavailable=True)
                time.sleep(1)
            except Exception as e:
                logger.error(f"ES index deletion error: {e}")

        return {"success": True, "message": "Pipeline reset complete"}
    except Exception as e:
        logger.error(f"[FRESH RESTART] Failed: {e}")
        return {"success": False, "message": str(e)}


@router.websocket("/ws")
async def admin_websocket(websocket: WebSocket):
    await websocket.accept()
    admin_manager.add(websocket)

    stats = admin_store.get_stats()
    stats["infra_rotation_count"] = vault_infra_client.get_infra_rotation_count()
    await websocket.send_json({
        "type": "admin_connected",
        "data": stats,
    })

    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        admin_manager.remove(websocket)
    except Exception as e:
        admin_manager.remove(websocket)
        logger.error(f"Admin WebSocket error: {e}")
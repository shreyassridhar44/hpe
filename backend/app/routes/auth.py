import hashlib
import time
import os
import uuid
import logging
import asyncio
import threading
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import db

logger = logging.getLogger("hpe.auth")
router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    department: str


# ── VPN / Proxy IP Detection ─────────────────────────────────────────────────
# Uses ip-api.com (free, 45 req/min) to detect VPN, proxy, and hosting IPs.
# Results are cached in-memory to avoid hitting the rate limit.
_vpn_cache: dict = {}
_vpn_cache_lock = threading.Lock()
_VPN_CACHE_TTL = 600  # 10 minutes

def check_vpn_ip(ip: str) -> dict:
    """
    Check if an IP address belongs to a VPN, proxy, or hosting provider.
    Returns dict with: is_vpn, isp, country, city, region.
    Uses ip-api.com free tier (45 req/min, no key needed).
    """
    # Skip private/docker IPs
    if ip.startswith(("10.", "172.", "192.168.", "127.", "0.")):
        return {"is_vpn": False, "isp": "Private Network", "country": "Local", "city": "Local", "region": "Local"}

    # Check cache first
    with _vpn_cache_lock:
        cached = _vpn_cache.get(ip)
        if cached and (time.time() - cached["_ts"]) < _VPN_CACHE_TTL:
            return cached

    try:
        import urllib.request
        import json as json_mod
        url = f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,country,city,regionName"
        req = urllib.request.Request(url, headers={"User-Agent": "HPE-ThreatPipeline/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json_mod.loads(resp.read().decode())

        if data.get("status") != "success":
            logger.warning(f"ip-api.com lookup failed for {ip}: {data}")
            return {"is_vpn": False, "isp": "Unknown", "country": "Unknown", "city": "Unknown", "region": "Unknown"}

        result = {
            "is_vpn": bool(data.get("proxy") or data.get("hosting")),
            "isp": data.get("isp", "Unknown"),
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "_ts": time.time(),
        }

        # Cache the result
        with _vpn_cache_lock:
            _vpn_cache[ip] = result
            # Prune cache if it grows too large
            if len(_vpn_cache) > 500:
                oldest = sorted(_vpn_cache.items(), key=lambda x: x[1]["_ts"])[:100]
                for k, _ in oldest:
                    del _vpn_cache[k]

        logger.info(f"VPN check for {ip}: is_vpn={result['is_vpn']}, isp={result['isp']}, country={result['country']}")
        return result

    except Exception as e:
        logger.warning(f"VPN IP check failed for {ip}: {e}")
        # Fallback: use the legacy IP-prefix heuristic
        is_vpn_fallback = ip.startswith(("45.", "82.", "185.", "104.", "198."))
        return {"is_vpn": is_vpn_fallback, "isp": "Unknown", "country": "Unknown", "city": "Unknown", "region": "Unknown"}


def _broadcast_vpn_alert(username: str, client_ip: str, vpn_info: dict, login_success: bool):
    """Immediately broadcast a VPN login alert to the dashboard via WebSocket."""
    from app.ws_manager import manager as ws_manager, admin_manager

    alert_data = {
        "type": "vpn_login_alert",
        "data": {
            "username": username,
            "source_ip": client_ip,
            "vpn_provider": vpn_info.get("isp", "Unknown VPN"),
            "country": vpn_info.get("country", "Unknown"),
            "city": vpn_info.get("city", "Unknown"),
            "region": vpn_info.get("region", "Unknown"),
            "login_success": login_success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }

    try:
        # Broadcast to BOTH simulation dashboard and admin panel using sync-safe methods
        ws_manager.broadcast_sync(alert_data)
        admin_manager.broadcast_sync(alert_data)
        logger.info(f"🛡️ VPN LOGIN ALERT broadcast: {username} from {client_ip} ({vpn_info.get('isp')})")
    except Exception as e:
        logger.warning(f"Failed to broadcast VPN login alert: {e}")


def write_zeek_log(username: str, success: bool, request_ip: str, is_vpn: bool = False):
    """Write login attempt as a Zeek TSV log line to be picked up by Filebeat."""
    log_path = os.environ.get("ZEEK_LOG_PATH", "/shared-data/zeek-live/conn.log")
    
    # Format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes
    ts = f"{time.time():.6f}"
    uid = f"C{uuid.uuid4().hex[:12]}"
    orig_h = request_ip
    orig_p = "12345"
    resp_h = "10.0.0.1"  # The server
    resp_p = "443"
    proto = "tcp"
    
    status_str = "success" if success else "failure"
    # Encode username, status, and VPN flag into service field for threat_engine mapping
    # Format: auth_{username}_{status}_vpn (if VPN detected)
    service = f"auth_{username}_{status_str}"
    if is_vpn:
        service += "_vpn"
    
    # Mock some data for the remaining fields
    duration = "1.0"
    orig_bytes = "500"
    resp_bytes = "500" if success else "100"
    conn_state = "SF" if success else "REJ"
    
    # 20 fields total to match the Filebeat config dissect tokenizer
    tsv_line = f"{ts}\t{uid}\t{orig_h}\t{orig_p}\t{resp_h}\t{resp_p}\t{proto}\t{service}\t{duration}\t{orig_bytes}\t{resp_bytes}\t{conn_state}\t-\t-\t0\tShADadFf\t10\t1000\t10\t1000\n"
    
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(tsv_line)
        logger.info(f"Wrote login event to Zeek log: {service}")
    except Exception as e:
        logger.error(f"Failed to write to Zeek log at {log_path}: {e}")

@router.post("/login")
def login(request: LoginRequest, http_req: Request):
    # Hash password using simple sha256 for demo
    pass_hash = hashlib.sha256(request.password.encode('utf-8')).hexdigest()
    
    # Attempt to get real IP from proxy headers, fallback to client host
    client_ip = http_req.headers.get("x-forwarded-for") or (http_req.client.host if http_req.client else "192.168.1.50")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # ── Real-time VPN Detection ───────────────────────────────────────────────
    vpn_info = check_vpn_ip(client_ip)
    is_vpn = vpn_info.get("is_vpn", False)
    if is_vpn:
        logger.warning(f"🛡️ VPN DETECTED: User '{request.username}' logging in from VPN IP {client_ip} ({vpn_info.get('isp')}, {vpn_info.get('country')})")
    
    try:
        query = "SELECT * FROM hpe_users WHERE username = %s"
        user = db.execute_query(query, (request.username,), fetch=True)
        
        if not user:
            write_zeek_log(request.username, False, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user.get('status') == 'pending':
            # Log as failure to Zeek to trigger pipeline visibility
            write_zeek_log(request.username, False, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
            raise HTTPException(status_code=403, detail="Account awaiting admin approval")
            
        if user['password_hash'] == pass_hash:
            # Reset failed attempts on success
            db.execute_query("UPDATE hpe_users SET failed_attempts = 0, last_login = NOW() WHERE username = %s", (request.username,))
            write_zeek_log(request.username, True, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=True)
            return {"success": True, "message": "Login successful", "department": user['department']}
        else:
            # Increment failed attempts on failure
            db.execute_query("UPDATE hpe_users SET failed_attempts = failed_attempts + 1 WHERE username = %s", (request.username,))
            write_zeek_log(request.username, False, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
            raise HTTPException(status_code=401, detail="Invalid username or password")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during login: {e}")
        # Even on DB error, write a failure Zeek log
        write_zeek_log(request.username, False, client_ip, is_vpn)
        if is_vpn:
            _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/register")
def register(request: RegisterRequest):
    try:
        # Check if user already exists
        query = "SELECT * FROM hpe_users WHERE username = %s"
        existing = db.execute_query(query, (request.username,), fetch=True)
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
            
        # Insert user with status='pending' and no password hash yet
        insert_query = "INSERT INTO hpe_users (username, department, status) VALUES (%s, %s, 'pending')"
        db.execute_query(insert_query, (request.username, request.department))
        
        # Broadcast to admin WebSocket connection
        from app.ws_manager import admin_manager
        import asyncio
        from datetime import datetime, timezone
        
        is_vpn = ("vpn" in request.username.lower() or "vpn" in request.department.lower())
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    admin_manager.broadcast({
                        "type": "new_registration",
                        "data": {
                            "username": request.username,
                            "department": request.department,
                            "status": "pending",
                            "is_vpn": is_vpn,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }),
                    loop
                )
        except Exception as e:
            logger.warning(f"Failed to broadcast live registration: {e}")

        return {"success": True, "message": "Access request submitted. Awaiting admin approval and credential issuance."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during registration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


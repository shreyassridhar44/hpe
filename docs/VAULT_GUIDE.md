# HashiCorp Vault — Credential System & Infrastructure Security

> This document explains how the HPE pipeline manages credentials for 200 enterprise users via HashiCorp Vault, and covers the full credential security architecture including dynamic database secrets, AppRole authentication, and automated Kubernetes unsealing.

---

## Architecture Overview

```
user_profiles.json (200 users)
         │
         ▼ (on backend startup)
   vault_client.py
         │
         ▼
   HashiCorp Vault (Raft persistent storage)
   ┌──────────────────────────────────────────────────┐
   │  secret/hpe/users/USR-0001  ← db_password,      │
   │  secret/hpe/users/USR-0002    api_key,           │
   │  secret/hpe/users/USR-0003    service_token      │
   │  ...                                             │
   │  secret/hpe/users/USR-0200                      │
   │                                                  │
   │  database/creds/hpe-backend-role  ← dynamic     │
   │  database/creds/hpe-readonly-role   PostgreSQL   │
   │                                                  │
   │  auth/approle/role/hpe-backend    ← AppRole      │
   │  secret/hpe/kafka                 ← Kafka creds  │
   └──────────────────────────────────────────────────┘
         │
         ▼
   vault-data PVC (/vault/data)
   ├── .unseal_key          ← read by unseal-watcher sidecar
   ├── .root_token          ← used only during vault-init Job
   ├── .approle_credentials ← read by backend at startup
   ├── .initialized         ← first-boot flag
   ├── .db_engine_configured
   └── .approle_configured
```

---

## How It Works

### 1. Startup — Credential Seeding

When the backend starts (`main.py` → `vault_client.connect_vault()`):
1. Reads all 200 user profiles from `user_profiles.json`
2. For each user, creates a Vault secret at `secret/hpe/users/{user_id}`
3. Each secret contains:
   - `db_password` — 32-char cryptographically secure password
   - `api_key` — Prefixed with `hpe_` + 48 hex chars
   - `service_token` — UUID v4
   - `role` — from profile (Developer, Admin, Finance, HR, Sales)
   - `home_region` — from profile (US-East, US-West, EU-Central, Asia-Pacific, South-America)
   - `rotation_count` — starts at 0
   - `status` — "active" initially
   - `last_rotation_reason` — "initial_provisioning"

### 2. Threat Detection — Per-User Rotation

When the AI engine detects a threat for a specific user:
1. `threat_engine.py` calls `vault_client.rotate_credentials(user=event.user_id)`
2. Only **that user's** credentials are regenerated
3. The secret at `secret/hpe/users/{user_id}` is updated with:
   - Brand new `db_password`, `api_key`, `service_token`
   - Incremented `rotation_count`
   - `status` → "rotated"
   - `last_rotation_reason` → `"threat_detected_score_0.XXXX"`

### 3. CRITICAL Alert — Dual Rotation

When an admin approves a CRITICAL alert (score > 0.85), the system performs two simultaneous rotations:
1. **User KV rotation** — the flagged user's credentials are regenerated as above
2. **Infrastructure lease revocation** — `vault_infra_client.py` immediately revokes the active PostgreSQL dynamic credential lease, forcing Vault to issue a brand-new database user

Both rotations are logged to the audit trail in PostgreSQL.

### 4. API Access — Viewing Credentials

| Endpoint | What you see |
|---|---|
| `/api/vault/users` | All 200 users, masked passwords |
| `/api/vault/users/USR-0042` | Single user detail |
| `/api/vault/credentials` | Latest rotated user (for dashboard) |
| Vault UI (`localhost:8200`) | Full unmasked values |

---

## Dynamic Database Credentials

The system uses Vault's database secrets engine to generate short-lived PostgreSQL credentials on demand. No static database password exists anywhere in the codebase.

| Role | TTL | Permissions |
|------|-----|-------------|
| `hpe-backend-role` | 1 hour | SELECT, INSERT, UPDATE on all tables |
| `hpe-readonly-role` | 30 minutes | SELECT only |

Vault automatically revokes these users when the lease expires. On a CRITICAL alert approval, `vault_infra_client.py` forcefully revokes the current lease immediately — the compromised database user ceases to exist within milliseconds.

---

## AppRole Authentication

The backend authenticates to Vault using AppRole rather than a static token. On startup, the backend reads a `role_id` and `secret_id` from the shared PVC (written by the vault-init Job) and exchanges them for a short-lived Vault token. A background thread auto-renews this token every 45 minutes. The root token is only used during the vault-init Job and is never visible to the running application.

**Credential file location** (written by vault-init, mounted read-only by backend):
```
/vault/data/.approle_credentials
```

---

## Kafka Credentials

Kafka broker credentials are stored in Vault KV at `secret/hpe/kafka` and fetched at backend startup via `vault_infra_client.py`. On a `lateral_movement` CRITICAL alert approval, `reconnect_kafka()` fetches the newly rotated credentials from Vault and rebuilds all Kafka producer/consumer clients instantly with zero downtime.

---

## Auto-Unseal on Kubernetes Restart

> **Why does Vault seal itself?**
> Vault uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) as a security mechanism. Every time Vault's container restarts (e.g., after `minikube stop` → `minikube start`), Vault deliberately seals itself. This is **by design** — if someone gains physical access to the server, they cannot read any secrets without the unseal key.

Unsealing in Kubernetes is handled automatically. The Vault StatefulSet runs an `unseal-watcher` sidecar container alongside the main Vault server. The sidecar polls Vault's seal status every 15 seconds and automatically calls the unseal API whenever it detects Vault has sealed itself — no manual intervention required.

The sidecar is secured with a minimal footprint:
- Mounts the vault-data PVC as `readOnly: true` — it can only read the unseal key, never write
- Has no Vault token and cannot read any secrets
- Only calls `/v1/sys/unseal` — it cannot access or modify secret data
- The Vault pod runs under a dedicated `vault-sa` ServiceAccount scoped with least-privilege RBAC

**Watching the sidecar:**
```bash
# Follow unseal-watcher logs in real time
kubectl logs vault-0 -c unseal-watcher -n hpe -f

# Expected output after a Minikube restart:
# [unseal-watcher] Vault is SEALED — attempting auto-unseal...
# [unseal-watcher] Vault unsealed successfully.

# Verify both containers are running in the vault pod
kubectl get pod vault-0 -n hpe -o jsonpath='{.status.containerStatuses[*].name}'
# Output: vault unseal-watcher
```

---

## Viewing in Vault UI

1. Open `http://localhost:8200`
2. Login method: **Token**
3. Token: `hpe-dev-token`
4. Navigate: **Secrets** → **secret/** → **hpe/** → **users/**
5. Click any user (e.g., `USR-0042`) to see full credentials

---

## User Roles Distribution

| Role | Count | Description |
|---|---|---|
| Developer | ~50 | High download volumes, varied hours |
| Sales | ~50 | Moderate activity, high travel probability |
| Finance | ~35 | Regular hours, low downloads |
| Admin | ~30 | High privileges, varied patterns |
| HR | ~20 | Regular hours, low volume |

*Note: Some users have `is_shift_worker: true` which gives them unusual login hours. These are NOT threats — the AI must learn to distinguish legitimate shift work from actual attacks.*

---

## Security Notes

- **Raft persistent storage:** Secrets survive container restarts. `docker-compose down -v` or `kubectl delete namespace hpe` wipes the PVC and resets Vault completely.
- **Dynamic DB credentials:** No static database password exists anywhere. Vault creates and revokes PostgreSQL users automatically on each request and on CRITICAL alert approvals.
- **AppRole authentication:** The root token is only used during `vault-init`. The running backend only ever holds a short-lived AppRole token that auto-renews every 45 minutes.
- **Auto-unseal sidecar:** The unseal-watcher uses `readOnly: true` PVC access and carries no Vault token — it can only trigger the unseal API, not read any secrets.
- **Masked API responses:** The `/api/vault/users` endpoint masks passwords (first 4 chars + `****` + last 4 chars). Full values are only visible in the Vault UI.
- **KV v2:** We use Vault's KV v2 secrets engine, which provides versioning. You can see the full history of credential rotations for each user.

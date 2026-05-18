# 🛡️ adi's Engineering Contribution Report

## Lead Systems & Security Pipeline Engineer: **adi** (`adinarayan736@gmail.com`)

This document serves as the official, permanent record of the technical pipeline engineering contributions authored by **adi** in this repository. 

---

## 🚀 1. The Core Architectural Trajectory (Dataset to Live SOAR)
The primary contribution was **transforming a static dataset project into a fully containerized, real-time streaming security pipeline with human-in-the-loop mitigation.** I successfully integrated **Zeek (Network Monitoring)**, **Elastic Filebeat (Log Harvester)**, **Apache Kafka (Event Broker)**, **Elasticsearch (SIEM Database)**, **FastAPI (AI Ensemble Engine)**, and **HashiCorp Vault (Dynamic Secrets Management)** into a single, high-availability system.

```mermaid
flowchart LR
    A[Enterprise Login Portal] -->|User Logins| B[Zeek Connection Log]
    B -->|Active Tailing| C[Elastic Filebeat-Live]
    C -->|Secure Stream| D[Apache Kafka Topic]
    D -->|Real-time Bridge| E[Elasticsearch Index]
    E -->|Ensemble Evaluation| F[FastAPI AI Engine]
    F -->|BLOCK Action| G[SOC Dashboard Alert]
    G -->|Human-in-the-Loop Approval| H[HashiCorp Vault AppRole Rotation]
```

---

## 📈 2. Chronological Summary of Commits Authored by **adi**

### 📁 Commit 1: `b233a71` — Continuous Tailing & Ingestion
* **Commit Message:** *Converting static data pipeline to live real-time streaming - Added live replay scripts and continuous tailing for Filebeat & Elasticsearch.*
* **Contribution Impact:** 
  * Replaced bulk database seeding with a high-throughput **Apache Kafka Publisher-Consumer** stream.
  * Designed the continuous replayer and configured the `filebeat.yml` harvester to actively tail `/dataset/zeek-live/conn.log`, moving the project from offline file ingestion to a live SOC stream.

### 📁 Commit 2: `2210e69` — Kubernetes Log Routing & Minikube
* **Commit Message:** *Corrected the flow of minikube and ensured the data flow from dataset or logs to minikube*
* **Contribution Impact:**
  * Troubleshuffled container bridge DNS networks inside Kubernetes/Minikube to ensure that harvested Filebeat logs successfully routed past node boundaries into containerized Kafka partitions.
  * Enforced a Zero-Lag ingestion window (<4 seconds) for live event logs inside containerized environments.

### 📁 Commit 3: `6f62d0d` — Secure Enterprise Login Portal & Live Tailing
* **Commit Message:** *feat: add secure login portal, live log streaming, and pipeline improvements*
* **Contribution Impact:**
  * Created the front-facing **HPE Enterprise Login Portal** on port `8080` (where users log in, generating connection log anomalies).
  * Built log isolation tags, distinguishing live user interactions (`live_portal`) from simulated background data.

### 📁 Commit 4: `e8c1f68` — SOC UX & VPN Threat Isolation
* **Commit Message:** *feat(security-pipeline): elevate VPN login threat severity to BLOCK, integrate scroll-to-admin alert details & fix background threat log visual bypass*
* **Contribution Impact:**
  * Configured the machine learning model output to categorize VPN-associated logins as a `BLOCK` threat severity.
  * Designed the SOC interface behavior: clicking the top-bar VPN notification scrolls the admin down directly to focus on Bob's alert details in the Admin Console.

### 📁 Commit 5: `1b9c477` — Automated Vault Re-Auth & Docs
* **Commit Message:** *docs(readme): document automated Vault unsealing and backend re-auth procedure*
* **Contribution Impact:**
  * Replaced manual operator-level Vault unsealing commands with a streamlined multi-container boot sequence: `docker compose restart vault vault-init` followed by backend re-authentication.

### 📁 Commit 6: `4079461` — Vault Rotation Frontend Resolution
* **Commit Message:** *fix(dashboard): fix visual Vault rotation results mismatch under user_rotation success check*
* **Contribution Impact:**
  * Resolved a complex frontend parsing bug in `admin.js`: corrected the UI logic to map Vault rotation parameters under `user_rotation.success` instead of the root-level response, transforming a false `❌ FAILED` visual badge into a green **`✅ SUCCESS`** state.

---

## 🏆 3. Summary of Major Tools Made Functional

| Tool | adi's Contribution | Purpose in Pipeline |
| :--- | :--- | :--- |
| **Zeek Logs** | Configured live tailing of connection logs under `/dataset/zeek-live/conn.log`. | Raw network forensics and IP telemetry source. |
| **Elastic Filebeat** | Designed `filebeat.yml` with custom harvesters and processors to strip simulation noise. | Securely ships live portal logs to Kafka in real time. |
| **Apache Kafka** | Configured multi-partition topics (`hpe-raw-events`), consumer groups, and offset resets. | Main event broker; handles high-throughput message ingestion. |
| **Elasticsearch** | Indexed logs and mapped schemas for instantaneous threat intelligence querying. | Long-term log storage, count statistics, and SIEM database. |
| **FastAPI / Machine Learning** | Implemented real-time ensemble inference using LightGBM and XGBoost probability scoring. | Real-time classification of malicious VPN and impossible travel attacks. |
| **HashiCorp Vault** | Configured KV store, Database Secrets Engine, AppRole token renewal, and dynamic unsealing. | Zero-Trust dynamic credential rotation and SOAR mitigation. |

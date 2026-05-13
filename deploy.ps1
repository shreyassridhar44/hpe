# deploy.ps1 - One-shot Minikube deployment for HPE Pipeline
# Preserves all 5 phases: Vault server mode, AppRole, database engine, dual rotation, Kafka creds

param(
    [switch]$SkipBuild,
    [switch]$DeleteFirst,
    [switch]$Fresh
)

Write-Host ""
Write-Host "=== HPE Threat Detection Pipeline - Minikube Deployment ===" -ForegroundColor Cyan
Write-Host "  2 Kafka brokers, 2 Backends, 2 Frontends" -ForegroundColor DarkCyan
Write-Host "  Vault Server Mode + AppRole + Database Engine" -ForegroundColor DarkCyan
Write-Host ""

if ($DeleteFirst) {
    Write-Host "[0/6] Cleaning up previous deployment..." -ForegroundColor Red
    kubectl delete namespace hpe --ignore-not-found=true 2>$null
    Start-Sleep -Seconds 5
}

# Point Docker to Minikube
Write-Host "[1/6] Configuring Docker to use Minikube daemon..." -ForegroundColor Yellow
minikube docker-env | Invoke-Expression

if (-not $SkipBuild) {
    Write-Host ""
    Write-Host "[2/6] Building Docker images inside Minikube..." -ForegroundColor Yellow
    docker build -t hpe-backend:latest -f backend/Dockerfile .
    docker build -t hpe-frontend:latest -f frontend/Dockerfile ./frontend
} else {
    Write-Host ""
    Write-Host "[2/6] Skipping image build" -ForegroundColor DarkYellow
}

# Apply namespace + shared resources
Write-Host ""
Write-Host "[3/6] Creating namespace and config..." -ForegroundColor Yellow
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/vault-pvc.yaml

# Deploy infrastructure
Write-Host ""
Write-Host "[4/6] Deploying infrastructure..." -ForegroundColor Yellow
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/kafka/
kubectl apply -f k8s/elasticsearch/
kubectl apply -f k8s/vault/vault-config-configmap.yaml
kubectl apply -f k8s/vault/vault-service.yaml
kubectl apply -f k8s/vault/vault-statefulset.yaml

# Wait for infra
Write-Host ""
Write-Host "Waiting for infrastructure pods..." -ForegroundColor DarkYellow
kubectl wait --for=condition=Ready pod -l app=kafka -n hpe --timeout=240s
kubectl wait --for=condition=Ready pod -l app=elasticsearch -n hpe --timeout=180s
kubectl wait --for=condition=Ready pod -l app=vault -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=postgres -n hpe --timeout=120s

# Run vault-init Job
Write-Host ""
Write-Host "[5/6] Running Vault initialization..." -ForegroundColor Yellow
kubectl apply -f k8s/vault/vault-init-configmap.yaml
kubectl apply -f k8s/vault/vault-init-job.yaml
kubectl wait --for=condition=Complete job/vault-init -n hpe --timeout=180s

Write-Host "Vault init logs:" -ForegroundColor DarkYellow
kubectl logs job/vault-init -n hpe --tail=10

# Deploy application
Write-Host ""
Write-Host "[6/6] Deploying application components..." -ForegroundColor Yellow
kubectl apply -f k8s/backend/
kubectl apply -f k8s/frontend/
kubectl apply -f k8s/live-pipeline/

# Wait for app pods
Write-Host ""
Write-Host "Waiting for application pods..." -ForegroundColor DarkYellow
kubectl wait --for=condition=Ready pod -l app=backend -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=frontend -n hpe --timeout=120s

if ($Fresh) {
    Write-Host ""
    Write-Host "[FRESH] Wiping all pipeline data..." -ForegroundColor Magenta
    # Port-forward backend and call reset API
    Start-Job -Name "PortForward" -ScriptBlock { kubectl port-forward service/backend 8000:8000 -n hpe } | Out-Null
    Start-Sleep -Seconds 3
    try {
        Invoke-RestMethod -Uri "http://localhost:8000/api/admin/reset" -Method Post
        Write-Host "[FRESH] Pipeline data wiped - starting clean" -ForegroundColor Green
    } catch {
        Write-Host "[FRESH] Failed to reset pipeline data: $_" -ForegroundColor Red
    } finally {
        Stop-Job -Name "PortForward" | Remove-Job
    }
}

# Summary
Write-Host ""
Write-Host "=== Deployment Complete ===" -ForegroundColor Green
Write-Host ""
kubectl get pods -n hpe
Write-Host ""
Write-Host "Access the dashboard:" -ForegroundColor Cyan
Write-Host "  minikube service frontend -n hpe" -ForegroundColor White
Write-Host ""

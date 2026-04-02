#!/usr/bin/env bash
# scripts/aks-setup.sh — One-time AKS cluster setup
# ─────────────────────────────────────────────────────────────────────────────
# Run once to prepare your AKS cluster for the redaction service.
# Installs: NGINX Ingress, cert-manager, Prometheus stack, ACR secret.
#
# Usage:
#   export ACR_NAME=youracr
#   export AKS_CLUSTER=your-aks
#   export RESOURCE_GROUP=your-rg
#   export ACR_USERNAME=...
#   export ACR_PASSWORD=...
#   bash scripts/aks-setup.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

ACR_NAME="${ACR_NAME:?ACR_NAME required}"
AKS_CLUSTER="${AKS_CLUSTER:?AKS_CLUSTER required}"
RESOURCE_GROUP="${RESOURCE_GROUP:?RESOURCE_GROUP required}"
NAMESPACE="${NAMESPACE:-redaction}"

echo "=== AKS Setup for PII Redaction Service ==="
echo "  Cluster:    $AKS_CLUSTER"
echo "  Namespace:  $NAMESPACE"
echo "  ACR:        $ACR_NAME"
echo ""

# ── 1. Connect to cluster ────────────────────────────────────────────────────
echo "→ Getting AKS credentials..."
az aks get-credentials \
    --resource-group "$RESOURCE_GROUP" \
    --name "$AKS_CLUSTER" \
    --overwrite-existing

# ── 2. Create namespace ───────────────────────────────────────────────────────
echo "→ Creating namespace: $NAMESPACE"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# ── 3. ACR pull secret ───────────────────────────────────────────────────────
echo "→ Creating ACR pull secret..."
kubectl create secret docker-registry acr-secret \
    --docker-server="${ACR_NAME}.azurecr.io" \
    --docker-username="${ACR_USERNAME:?ACR_USERNAME required}" \
    --docker-password="${ACR_PASSWORD:?ACR_PASSWORD required}" \
    --namespace "$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# ── 4. Add Helm repos ────────────────────────────────────────────────────────
echo "→ Adding Helm repositories..."
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add cert-manager https://charts.jetstack.io
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# ── 5. NGINX Ingress Controller ──────────────────────────────────────────────
echo "→ Installing NGINX Ingress Controller..."
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
    --namespace ingress-nginx --create-namespace \
    --set controller.replicaCount=2 \
    --set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz \
    --wait --timeout 5m

# ── 6. cert-manager (TLS) ────────────────────────────────────────────────────
echo "→ Installing cert-manager..."
helm upgrade --install cert-manager cert-manager/cert-manager \
    --namespace cert-manager --create-namespace \
    --set installCRDs=true \
    --wait --timeout 5m

# Create ClusterIssuer for Let's Encrypt
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: devops@yourorg.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
EOF

# ── 7. Prometheus + Grafana ──────────────────────────────────────────────────
echo "→ Installing Prometheus + Grafana..."
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
    --namespace monitoring --create-namespace \
    --set grafana.adminPassword=admin \
    --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
    --wait --timeout 10m

# ── 8. Create ServiceMonitor for scraping redaction service ─────────────────
cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: pii-redaction
  namespace: monitoring
  labels:
    release: monitoring
spec:
  selector:
    matchLabels:
      app: redaction-redaction
  namespaceSelector:
    matchNames:
      - $NAMESPACE
  endpoints:
    - port: http
      path: /metrics
      interval: 10s
EOF

# ── 9. Verify ────────────────────────────────────────────────────────────────
echo ""
echo "=== Setup Complete ==="
echo ""
INGRESS_IP=$(kubectl get svc ingress-nginx-controller -n ingress-nginx \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
echo "  Ingress IP:  $INGRESS_IP"
echo "  Namespace:   $NAMESPACE (ready)"
echo ""
echo "Next steps:"
echo "  1. Point your DNS → $INGRESS_IP"
echo "  2. Run: make deploy-aks ACR_NAME=$ACR_NAME"
echo "  3. Check: make aks-status"

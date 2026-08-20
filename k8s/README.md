# Kubernetes / KEDA Physical Autoscaling

## Purpose

This deployment proves that the scaling-agent's persisted desired replica target
can physically scale deception-engine pods through Prometheus, KEDA, and HPA.
All supporting services remain private `ClusterIP` resources in the isolated
`capstone-deception` namespace.

```text
synthetic MITRE event
  -> Redpanda
  -> scaling-agent desired replicas
  -> metrics-bridge
  -> Prometheus
  -> KEDA external metric
  -> HPA
  -> deception-engine pod replicas
```

The manifests use only synthetic validation events and disposable local state.
They do not connect to a real database, expose an Ingress, or publish a control
API outside the cluster.

## Replica Metric Contract

The authoritative KEDA metric is:

```text
capstone_scaling_current_replicas
```

It represents the desired total number of deception-engine replicas. The
ScaledObject therefore uses `metricType: AverageValue` with a threshold of `1`.
For `N` running pods and desired total `R`, the external metric becomes `R/N`;
the HPA calculation converges to exactly `R`.

Do not change this trigger to `metricType: Value`. A total desired-replica
metric with `Value` creates positive feedback because HPA multiplies the value
by the current replica count.

The scaling-agent continues to own decision safeguards:

- scale-up threshold `0.6`
- scale-down threshold `0.3`
- scale-up cooldown `30s`
- maximum scale-up step `+2`
- scale-down stabilization `120s`
- safe mode, manual target, rollback, autoscaling toggle, and replica budget

## Resources

| Manifest | Purpose |
|---|---|
| `namespace.yaml` | Isolated `capstone-deception` namespace |
| `redis.yaml` | Private state stores for deception and scaling state |
| `redpanda.yaml` | Private event broker and topic initialization job |
| `deception-engine-deployment.yaml` | Physically scaled workload |
| `deception-engine-service.yaml` | Internal deception-engine service |
| `scaling-agent-deployment.yaml` | Deterministic replica decision service |
| `scaling-agent-service.yaml` | Internal metrics and control service |
| `metrics-bridge-deployment.yaml` | Converts scaling metrics to Prometheus format |
| `prometheus.yaml` | Private Prometheus server and scrape configuration |
| `keda-scaledobject-prometheus.yaml` | KEDA/HPA desired-replica bridge |

`keda-scaledobject-proxy.yaml` is a legacy pressure-metric alternative and is
not part of this validated deployment path.

## Local Image Preparation

The validated Docker Desktop cluster uses locally built images with
`imagePullPolicy: Never`:

```powershell
docker compose -f docker-compose.yml build deception-engine scaling-agent metrics-bridge

$images = @(
  "capstone-main-deception-engine:latest",
  "capstone-main-scaling-agent:latest",
  "capstone-main-metrics-bridge:latest",
  "redis:7-alpine",
  "redpandadata/redpanda:v24.1.9",
  "prom/prometheus:v2.48.0"
)

foreach ($image in $images) {
  docker save $image | docker exec -i desktop-control-plane ctr -n k8s.io images import -
}
```

For another cluster, tag and push these images to an approved private registry,
then update the manifest image references and pull policy.

## Apply Order

Install KEDA first, then apply the project resources:

```powershell
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/redpanda.yaml
kubectl wait --for=condition=complete job/redpanda-init -n capstone-deception --timeout=180s
kubectl apply -f k8s/deception-engine-deployment.yaml
kubectl apply -f k8s/deception-engine-service.yaml
kubectl apply -f k8s/scaling-agent-deployment.yaml
kubectl apply -f k8s/scaling-agent-service.yaml
kubectl apply -f k8s/metrics-bridge-deployment.yaml
kubectl apply -f k8s/prometheus.yaml
kubectl apply -f k8s/keda-scaledobject-prometheus.yaml
```

## Validation

```powershell
kubectl get pods,deployments,services -n capstone-deception
kubectl get scaledobject,hpa -n capstone-deception
kubectl describe scaledobject deception-engine-prometheus-scaler -n capstone-deception
kubectl describe hpa keda-hpa-deception-engine-prometheus-scaler -n capstone-deception

kubectl get --raw "/apis/external.metrics.k8s.io/v1beta1/namespaces/capstone-deception/s0-prometheus?labelSelector=scaledobject.keda.sh%2Fname%3Ddeception-engine-prometheus-scaler"
```

Acceptance requires all application pods to be ready, Prometheus to report the
metrics bridge as `up=1`, the ScaledObject to be `Ready=True`, the external
metric to be readable, and a unique high-risk event to change physical pods
from `1` to `3`. Returning the scaler to one replica must keep three physical
pods during the 120-second stabilization window and then reduce them to one.

## Validated Local Result

On 2026-08-20, Docker Desktop Kubernetes v1.34.3 with KEDA v2.19.0 passed the
complete physical test:

```text
automatic baseline: 1 pod
unique high-risk event: logical target 1 -> 3
HPA/deployment: 1 -> 3 ready pods
stable target: 3 pods remained stable
rollback target: 3 -> 1
stabilization: held 3 pods for 120 seconds
physical scale-down: 3 -> 1 ready pod
```

Safe mode held physical replicas despite a high-risk event, a manual target of
four converged to four pods, a maximum budget of three clamped the target, and
a scaling-agent restart restored the persisted control and replica state.

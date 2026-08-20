# Kubernetes / KEDA Autoscaling Plan

## Purpose

The Docker Compose deployment validates adaptive scaling decisions by updating the scaling-agent desired replica target.

The Kubernetes deployment path connects the validated scaling pressure metric to KEDA/HPA so pod replicas can be physically scaled.

## Validated in Docker Compose

- Intent-based scaling from MITRE/trap signals.
- Metric-based scaling from Prometheus metrics.
- Scale-up threshold: 0.6.
- Scale-down threshold: 0.3.
- Scale-down hysteresis window: 120 seconds.
- Scale-up cooldown: 30 seconds.
- Maximum scale-up step: +2 replicas.
- Maximum replicas: 10.

## Kubernetes Physical Scaling Design

Prometheus scrapes metrics-bridge.

metrics-bridge exposes:

- capstone_scaling_scale_pressure
- capstone_scaling_current_replicas
- capstone_pgproxy_total_connections
- capstone_mysqlproxy_total_connections
- capstone_mitre_trap_triggers_total

KEDA Prometheus scaler queries:

    capstone_scaling_scale_pressure

KEDA then creates/manages an HPA for the deception-engine Deployment.

## Expected Kubernetes Behavior

| Condition | Metric | Expected Behavior |
|---|---:|---|
| Low pressure | < 0.3 | Scale down after cooldown/hysteresis |
| Medium pressure | 0.3 to 0.6 | Hold |
| High pressure | >= 0.6 | Scale up |
| Repeated high pressure | >= 0.6 | Scale up gradually, max +2 pods per 30s |
| Sustained low pressure | < 0.3 for 120s | Scale down gradually, -1 pod per 120s |

## Apply Order

    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/deception-engine-deployment.yaml
    kubectl apply -f k8s/deception-engine-service.yaml
    kubectl apply -f k8s/scaling-agent-deployment.yaml
    kubectl apply -f k8s/scaling-agent-service.yaml
    kubectl apply -f k8s/keda-scaledobject-prometheus.yaml

## Validation Commands

    kubectl get pods -n capstone-deception
    kubectl get deploy -n capstone-deception
    kubectl get scaledobject -n capstone-deception
    kubectl get hpa -n capstone-deception
    kubectl describe scaledobject deception-engine-prometheus-scaler -n capstone-deception
    kubectl describe hpa -n capstone-deception

## Review Note

These manifests define the physical autoscaling path. A Kubernetes cluster with KEDA installed and Prometheus reachable as http://prometheus:9090 is required to execute physical pod autoscaling.

Docker Compose validates the scaler decision logic; Kubernetes/KEDA performs real pod replica changes.

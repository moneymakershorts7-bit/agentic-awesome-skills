# OpenTelemetry Collector Kubernetes & Helm Deployment Runbook
## Architecture Overview
The OpenTelemetry Collector is a powerful solution for collecting telemetry data from various sources. When deployed in a Kubernetes environment, it can be managed using Helm charts, which simplify the deployment process and provide a flexible way to configure the Collector.

## Concrete Configs / Code Recipes
### values.yaml Configuration
```yaml
mode: daemonset
resources:
  limits:
    cpu: 1
    memory: 1Gi
  requests:
    cpu: 200m
    memory: 400Mi
image:
  tag: "0.81.0"
presets:
  kubernetesAttributes:
    enabled: true
config:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317
        http:
          endpoint: 0.0.0.0:4318
          cors:
            allowed_origins:
              - http://*
              - https://*
  processors:
    batch:
      send_batch_size: 8192
      timeout: 5s
      memory_limiter:
        check_interval: 5s
        limit_mib: 800
        spike_limit_mib: 150
  exporters:
    otlp:
      endpoint: observability.example.com:443
      headers:
        api-key: ${OBSERVABILITY_API_KEY}
    otlp/metrics:
      endpoint: metrics.example.com:443
      headers:
        api-key: ${METRICS_API_KEY}
  service:
    pipelines:
      traces:
        receivers: [otlp]
        processors: [memory_limiter, batch, k8sattributes]
        exporters: [otlp]
      metrics:
        receivers: [otlp]
        processors: [memory_limiter, batch, k8sattributes]
        exporters: [otlp/metrics]
```

### Helm Install Command
```bash
helm install my-otel-collector open-telemetry/opentelemetry-collector \
  --values collector-values.yaml \
  --set extraEnvs[0].name=<observability_api_key> \
  --set extraEnvs[0].value=<secret-key-123> \
  --set extraEnvs[1].name=<metrics_api_key> \
  --set extraEnvs[1].value=<metrics-key-456> \
  --dry-run
```

### Prometheus Service Monitor
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: otel-collector
spec:
  selector:
    matchLabels:
      app: opentelemetry-collector
  endpoints:
  - port: 55678
    interval: 10s
  namespaceSelector:
    matchLabels:
      name: default
```

### RBAC Roles
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: otel-collector
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - services
  verbs:
  - get
  - list
  - watch
```

### ServiceAccount Config
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: otel-collector
```

## Operational Runbook / Failure Modes
### Deployment Failure
* Check the deployment logs for errors
* Verify that the `values.yaml` file is correctly configured
* Check the Helm chart version and update if necessary
* Try redeploying the Collector

### Collector Crash
* Check the Collector logs for errors
* Verify that the `values.yaml` file is correctly configured
* Check the resource allocations and adjust if necessary
* Try restarting the Collector

### Prometheus Service Monitor Failure
* Check the Prometheus logs for errors
* Verify that the ServiceMonitor is correctly configured
* Check the Collector logs for errors
* Try restarting the Prometheus service

### RBAC Role Failure
* Check the RBAC logs for errors
* Verify that the Role is correctly configured
* Check the ServiceAccount logs for errors
* Try updating the Role and ServiceAccount configurations

# Freebird Logging Configuration Guide

Comprehensive guide for configuring structured logging, log aggregation, and analysis for Freebird deployments.

---

## Quick Start

### Enable Structured Logging

In `.env`:

```bash
# Plain text logs (default, human-readable)
LOG_FORMAT=plain

# JSON logs (machine-readable, for aggregation systems)
LOG_FORMAT=json

# Log level
RUST_LOG=info,freebird=debug
```

### View Logs

```bash
# Docker Compose
docker-compose logs -f issuer
docker-compose logs -f verifier

# Kubernetes
kubectl logs -f deployment/issuer -n freebird
kubectl logs -f deployment/verifier -n freebird
```

---

## Structured Logging (JSON Format)

When `LOG_FORMAT=json`, logs are emitted as JSON for easy parsing and aggregation.

### Example Log Entry

```json
{
  "timestamp": "2024-01-15T10:30:45.123456Z",
  "level": "info",
  "target": "freebird::issuer::core",
  "fields": {
    "message": "Token issued successfully",
    "user_id": "user:12345",
    "token_hash": "sha256:abc123...",
    "processing_time_ms": 45
  }
}
```

### JSON Fields

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp with microseconds |
| `level` | Log level: trace, debug, info, warn, error |
| `target` | Module path that emitted the log |
| `fields` | Structured data relevant to the event |
| `message` | Human-readable message |

### Key Log Patterns

#### Token Issuance

```json
{
  "timestamp": "...",
  "level": "info",
  "fields": {
    "message": "Token issued",
    "user_id": "...",
    "token_hash": "...",
    "sybil_mode": "invitation",
    "duration_ms": 50
  }
}
```

#### Token Verification

```json
{
  "timestamp": "...",
  "level": "info",
  "fields": {
    "message": "Token verified",
    "token_hash": "...",
    "issuer_id": "issuer:prod:v4",
    "result": "accepted",
    "duration_ms": 25
  }
}
```

#### Key Rotation

```json
{
  "timestamp": "...",
  "level": "info",
  "fields": {
    "message": "Key rotated",
    "old_kid": "...",
    "new_kid": "...",
    "grace_period_secs": 86400
  }
}
```

#### Error Conditions

```json
{
  "timestamp": "...",
  "level": "error",
  "fields": {
    "message": "Verification failed",
    "error": "clock_skew",
    "details": "client_time is 500ms ahead",
    "token_hash": "..."
  }
}
```

---

## Log Aggregation Systems

### ELK Stack (Elasticsearch, Logstash, Kibana)

#### 1. Configure Filebeat

```yaml
# filebeat.yml
filebeat.inputs:
  - type: container
    paths:
      - '/var/lib/docker/containers/*/*.log'
    multiline.pattern: '^\{'
    multiline.negate: true
    multiline.match: after
    json.message_key: message
    json.keys_under_root: true

processors:
  - add_kubernetes_metadata:
      in_cluster: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "freebird-%{+yyyy.MM.dd}"
```

#### 2. Create Elasticsearch Mapping

```bash
curl -X PUT "elasticsearch:9200/_index_template/freebird" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["freebird-*"],
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "timestamp": { "type": "date" },
        "level": { "type": "keyword" },
        "target": { "type": "keyword" },
        "message": { "type": "text" },
        "fields": { "type": "object", "enabled": true }
      }
    }
  }'
```

#### 3. Query in Kibana

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "fields.message": "Token verified" } },
        { "range": { "timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "results": {
      "terms": {
        "field": "fields.result",
        "size": 10
      }
    }
  }
}
```

### Datadog

#### 1. Install Datadog Agent

```bash
DD_AGENT_MAJOR_VERSION=7 DD_API_KEY=YOUR_API_KEY \
  DD_SITE="datadoghq.com" bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_script.sh)"
```

#### 2. Configure Log Collection

```yaml
# /etc/datadog-agent/conf.d/freebird.yaml
logs:
  - type: docker
    service: freebird-issuer
    source: rust
    tags:
      - component:issuer

  - type: docker
    service: freebird-verifier
    source: rust
    tags:
      - component:verifier
```

#### 3. Query Logs

```
service:freebird-issuer "Token issued" @level:info
```

### Cloudwatch (AWS)

#### 1. Configure Log Driver

In `docker-compose.yaml`:

```yaml
services:
  issuer:
    logging:
      driver: awslogs
      options:
        awslogs-group: /freebird/issuer
        awslogs-region: us-east-1
        awslogs-stream-prefix: ec2
```

#### 2. Create Log Group

```bash
aws logs create-log-group --log-group-name /freebird/issuer
aws logs create-log-group --log-group-name /freebird/verifier
```

#### 3. Query with CloudWatch Insights

```
fields @timestamp, level, message
| filter message like /Token/
| stats count() by level
```

### Google Cloud Logging

#### 1. Configure Logging

```yaml
# docker-compose.yaml
services:
  issuer:
    logging:
      driver: gcplogs
      options:
        gcp-project: my-project
        labels: component=issuer
```

#### 2. Query Logs

```
resource.type="cloud_run_revision"
resource.labels.service_name="freebird-issuer"
jsonPayload.message="Token issued"
```

---

## Docker Compose Logging

### Configure Logging in docker-compose.yaml

```yaml
services:
  issuer:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"
        labels: "component=issuer"
        env: "RUST_LOG,LOG_FORMAT"

    environment:
      - RUST_LOG=info,freebird=debug
      - LOG_FORMAT=json

  verifier:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"
        labels: "component=verifier"
        env: "RUST_LOG,LOG_FORMAT"
```

### Access Logs

```bash
# View logs
docker logs freebird-issuer | jq '.'

# Follow logs
docker logs -f freebird-issuer

# Get last 100 lines
docker logs --tail 100 freebird-issuer

# Get logs since timestamp
docker logs --since 2024-01-15T10:00:00 freebird-issuer
```

---

## Kubernetes Logging

### Configure Pod Logging

The Kubernetes manifests in `k8s/` include proper logging configuration:

```yaml
containers:
  - name: issuer
    env:
      - name: RUST_LOG
        value: "info,freebird=debug"
      - name: LOG_FORMAT
        value: "json"
```

### View Logs

```bash
# View live logs
kubectl logs -f deployment/issuer -n freebird

# View verifier logs (all replicas)
kubectl logs -f -l app=freebird,component=verifier -n freebird

# View logs with timestamps
kubectl logs deployment/issuer -n freebird --timestamps=true

# Get previous logs (if pod crashed)
kubectl logs deployment/issuer -n freebird --previous

# Export logs for analysis
kubectl logs deployment/issuer -n freebird > issuer-logs.txt
```

### Configure Centralized Logging

#### Option 1: Fluent Bit

```yaml
# k8s/fluent-bit-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: freebird
data:
  fluent-bit.conf: |
    [SERVICE]
        Daemon Off
        Flush 1
        Log_Level info

    [INPUT]
        Name tail
        Path /var/log/containers/*freebird*.log
        Parser docker
        Tag kube.*
        Refresh_Interval 5

    [OUTPUT]
        Name es
        Match *
        Host elasticsearch
        Port 9200
        Index freebird
        Type _doc
```

#### Option 2: Loki (Grafana)

```bash
# Deploy Loki Helm chart
helm repo add grafana https://grafana.github.io/helm-charts
helm install loki grafana/loki -n freebird

# Configure Promtail to ship logs
helm install promtail grafana/promtail -n freebird
```

---

## Log Analysis

### Common Queries

#### Find Verification Failures

```bash
# JSON format
docker logs freebird-verifier | \
  jq 'select(.fields.message == "Verification failed")'

# Elasticsearch
GET freebird-*/_search
{
  "query": {
    "match": { "fields.message": "Verification failed" }
  }
}
```

#### Count Tokens by User

```bash
# Count unique users
docker logs freebird-issuer | \
  jq -s 'group_by(.fields.user_id) | map({user: .[0].fields.user_id, count: length})'
```

#### Find Slow Operations

```bash
# Operations taking > 100ms
docker logs freebird-issuer | \
  jq 'select(.fields.duration_ms > 100)'
```

#### Error Rate Over Time

```bash
# Count errors by hour
docker logs freebird-issuer | \
  jq 'select(.level == "error") | .timestamp' | \
  cut -d: -f1 | sort | uniq -c
```

### Grafana Dashboards

Create a Grafana dashboard with:

1. **Token Issuance Rate** (per second)
2. **Token Verification Rate** (per second)
3. **Verification Success Rate** (%)
4. **API Latency** (p50, p95, p99)
5. **Error Rate** (%)
6. **Active Users** (24h)
7. **Key Rotation Events**
8. **Sybil Resistance Activity**

---

## Best Practices

### Log Levels

- **ERROR**: System failures, security issues, crypto errors
- **WARN**: Unusual conditions, replay attempts, expired keys
- **INFO**: Normal operations, token issuance/verification
- **DEBUG**: Detailed flow information (verbose)
- **TRACE**: Every operation (very verbose)

### In Production

```bash
# Recommended production settings
RUST_LOG=info,freebird=info  # Only important events
LOG_FORMAT=json              # Machine-readable
```

### In Development

```bash
# Recommended development settings
RUST_LOG=debug,freebird=debug  # More details
LOG_FORMAT=plain               # Human-readable
```

### Retention

```yaml
# Docker: Keep 10 files, max 100MB each
logging:
  options:
    max-size: "100m"
    max-file: "10"
    # = 1GB total storage per service

# Kubernetes: Logs are ephemeral
# Configure persistent log aggregation (ELK, Datadog, etc.)
```

---

## Troubleshooting Log Issues

### Logs Not Appearing

```bash
# Check container is running
docker ps | grep freebird

# Check log driver
docker inspect freebird-issuer | grep -A 5 LogDriver

# Check log output
docker logs freebird-issuer --raw

# Check Docker daemon logs
sudo journalctl -u docker.service -n 50
```

### High Log Volume

```bash
# Reduce verbosity
RUST_LOG=info,freebird=warn

# Check for infinite loops or repeated errors
docker logs freebird-issuer | sort | uniq -c | sort -rn | head -20
```

### JSON Parsing Errors

```bash
# Validate JSON structure
docker logs freebird-issuer | jq empty

# Extract only valid JSON
docker logs freebird-issuer | jq -s 'map(select(. != null))'
```

---

## References

- [tracing-rs Documentation](https://docs.rs/tracing/)
- [ELK Stack Setup](https://www.elastic.co/guide/index.html)
- [Datadog Logging](https://docs.datadoghq.com/logs/)
- [CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [Grafana Loki](https://grafana.com/oss/loki/)

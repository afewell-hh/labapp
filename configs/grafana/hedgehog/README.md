# Hedgehog Grafana Dashboards

This directory contains the official Hedgehog Grafana dashboard JSON files for the lab environment.

## Official Dashboards

According to the [Hedgehog documentation](https://docs.hedgehog.cloud/latest/user-guide/grafana/), the following dashboards are provided:

1. **Switch Critical Resources** (`grafana_crm.json`) - ASIC resource usage (ACLs, routes, nexthops, neighbors, IPMC, FDB)
2. **Fabric** (`grafana_fabric.json`) - BGP underlay and external peering metrics
3. **Interfaces** (`grafana_interfaces.json`) - Switch port monitoring and counters
4. **Logs** (`grafana_logs.json`) - System, kernel, and BGP log visualization
5. **Platform** (`grafana_platform.json`) - PSU, temperature, and fan monitoring
6. **Node Exporter** (`grafana_node_exporter.json`) - Linux system metrics (memory, CPU, disk)

## Dashboard Sources

The official dashboard JSON files can be obtained from:

- **Hedgehog Documentation**: https://docs.hedgehog.cloud/latest/user-guide/grafana/
- **Hedgehog GitHub**: https://github.com/githedgehog (check fabricator or docs repo)

## Importing Dashboards

Dashboards are automatically imported during the k3d cluster initialization by the `20-k3d-observability-init.sh` script.

### Manual Import (if needed)

If you need to manually import or update dashboards:

```bash
# Using kubectl and ConfigMaps (automated approach)
kubectl create configmap hedgehog-dashboard-crm \
  --from-file=grafana_crm.json \
  -n monitoring \
  --dry-run=client -o yaml | \
  kubectl label --local -f - grafana_dashboard=1 -o yaml | \
  kubectl apply -f -

# Using Grafana API
GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASSWORD="admin"

curl -X POST \
  -H "Content-Type: application/json" \
  -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
  "${GRAFANA_URL}/api/dashboards/db" \
  -d @grafana_crm.json
```

## Datasource Configuration

The dashboards require the following Prometheus datasource configuration:

- **Datasource Name**: `Prometheus`
- **Datasource Type**: `prometheus`
- **URL**: `http://kube-prometheus-stack-prometheus.monitoring:9090`

### Fabric Metrics Endpoint

For VLAB environments, Prometheus must scrape metrics from the Hedgehog controller's fabric-proxy service:

- **Target**: `https://<hedgehog-controller-ip>:31028/metrics`
- **Job Name**: `hedgehog-fabric`
- **Scrape Interval**: `15s`
- **TLS**: Insecure (self-signed certs in lab environment)

The controller IP is typically `172.19.0.1` (Docker bridge network gateway from k3d containers).

## Dashboard Variables

Common dashboard variables used across Hedgehog dashboards:

- **env** - Environment selection (usually `vlab` for lab environments)
- **node** - Switch name filtering (e.g., `spine-01`, `leaf-01`)
- **vrf** - VRF selection (multi-value)
- **neighbor** - BGP neighbor IP (multi-value)
- **interface** - Port selection (multi-value, e.g., `Ethernet1`, `Ethernet2`)
- **file** - Log file selection (for Loki-based log dashboard)

## Placeholder Status

**Note**: This directory currently contains placeholder/documentation only. The actual dashboard JSON files will be populated from the official Hedgehog source in a future update.

To populate the dashboards:

1. Download the official JSON files from Hedgehog documentation or GitHub
2. Place them in this directory with the filenames listed above
3. Re-run the k3d initialization or manually import using the commands above

## Testing

The test harness at `tests/e2e/scripts/validate-observability.sh` verifies that dashboards are present and accessible in Grafana.

# Observability: Alloy → Prometheus Remote Write (Issue #96)

This documents the working recipe used on the GCP validation VM to get Hedgehog switch telemetry into the EMC Prometheus stack.

## What changed
- Prometheus is now exposed via the k3d load-balancer on host port `9090` (see `packer/scripts/20-k3d-observability-init.sh`).
- `hhfab` launch scripts patch `fab.yaml` **before** `vlab up`, injecting:
  - relaxed `tlsSAN` entries so EMC services can reach the controller.
  - `defaultAlloyConfig` with a Prometheus remote_write target pointing at the host’s **internal** bridges (`http://192.168.122.1:9090/api/v1/write`, falling back to k3d/docker bridges). No telemetry egresses the VM; override via `ALLOY_PROM_REMOTE_WRITE_URL` only if you relocate Prometheus.
- The Prometheus validation module (`packer/scripts/60-prometheus-hedgehog-scrape.sh`) now checks for Alloy metrics instead of scraping `fabric-proxy /metrics` (which never exposed Prom data).

## Automation steps (hh-lab)
1. **k3d bring-up** – run `20-k3d-observability-init.sh`; it maps host `9090` to the Prometheus service and sets the service type to `LoadBalancer`.
2. **fab.yaml patch** – `hhfab-vlab-runner` and `30-vlab-init.sh` call `apply_fab_overrides` right after `hhfab init` to merge TLS SANs and Alloy telemetry:
   ```yaml
   fabric:
     defaultAlloyConfig:
       agentScrapeIntervalSeconds: 120
       unixScrapeIntervalSeconds: 120
       unixExporterEnabled: true
       collectSyslogEnabled: true
       prometheusTargets:
         emc:
           url: http://192.168.122.1:9090/api/v1/write
           labels: { env: vlab, cluster: emc }
           sendIntervalSeconds: 120
           useControlProxy: true
       unixExporterCollectors: [cpu, filesystem, loadavg, meminfo, netdev, diskstats]
   ```
   The host IP is auto-detected (first non-loopback). Override with `ALLOY_PROM_REMOTE_WRITE_URL` if needed.
3. **Run VLAB** – `hhfab vlab up --controls-restricted=false --ready wait` (systemd tmux). Certificates now include host IPs, docker/k3d gateways, and EMC service DNS names.
4. **Validate telemetry** – run `packer/scripts/60-prometheus-hedgehog-scrape.sh` or manually:
   ```bash
   kubectl config use-context k3d-k3d-observability
   kubectl -n monitoring port-forward svc/kube-prometheus-stack-prometheus 9090:9090
   curl -G --data-urlencode 'query=up{env="vlab",cluster="emc"}' http://localhost:9090/api/v1/query
   ```
   Expect one or more results once Alloy pushes samples.

## Notes & gaps
- If the validation script times out, check control-proxy egress and that `fab.yaml` contains `prometheusTargets`.
- Host firewall does not need to expose 9090 externally; telemetry is internal to the VM.
- Old `additionalScrapeConfigs` against `fabric-proxy` were removed because `/metrics` isn’t a Prom endpoint. Remote write is the supported path.

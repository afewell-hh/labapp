# Hedgehog Lab System Requirements (BYO VM)

## Minimum (will work for smoke testing)
- 16 vCPUs with nested virtualization enabled
- 96 GB RAM
- 320 GB free disk (SSD)
- Ubuntu 24.04 Server

## Recommended (for smooth student experience)
- 32 vCPUs
- 128–160 GB RAM
- 400+ GB SSD, high IOPS
- Consistent internet egress to `ghcr.io`, `github.com`, apt mirrors

## Networking
- Outbound HTTPS required; inbound only for the ports you expose (Grafana 3000, ArgoCD 8080, Gitea 3001, Prometheus 9090 by default).
- No special load balancer required; services bind to host ports via k3d mappings.

## Notes
- The installer will warn if CPU/RAM/disk are below recommended thresholds but will proceed.
- Ensure VT-x/AMD-V nesting is enabled on the hypervisor; the preflight check will fail fast if not detected.
- Allocate extra 50–80 GB headroom for log growth and future curriculum content.*** End Patch

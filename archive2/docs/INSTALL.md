# Hedgehog Lab – BYO Ubuntu 24.04 Installer (Issue #97)

This guide walks you through turning a fresh Ubuntu 24.04 Server VM into a fully functional Hedgehog Lab with VLAB + EMC using the new `hh-lab-installer`.

## System Requirements
- **OS:** Ubuntu 24.04 LTS (Server)
- **Compute:** ≥32 vCPUs (nested virtualization enabled)
- **Memory:** ≥128 GB RAM
- **Disk:** ≥400 GB free on `/` (SSD strongly recommended)
- **Network:** Public internet egress to ghcr.io, GitHub, and apt mirrors

> The installer will warn (not fail) if CPU/RAM/disk fall below the recommendations.

## Quick Install (One-Liner)
```bash
curl -fsSL https://raw.githubusercontent.com/afewell-hh/labapp/main/scripts/install.sh \
  | sudo bash -s -- --ghcr-user <github_user> --ghcr-token <read:packages_pat>
```
Use `--interactive` to be prompted for credentials instead of passing them on the command line.

## Step-by-Step
1. **Provision a VM** on your platform (GCP, AWS, local) that meets the requirements above. Ensure nested virtualization is enabled.
2. **SSH in as root (or a sudo user)** and clone or download this repository (optional when using the one-liner).
3. **Run the installer:**
   ```bash
   sudo ./scripts/hh-lab-installer --ghcr-user <user> --ghcr-token <token>
   ```
   - The installer stages the proven packer modules, installs dependencies, performs GHCR auth, and launches the orchestrator service.
4. **Monitor progress:**
   - `hh-lab status`
   - `hh-lab logs -f`
   - `tmux attach -t hhfab-vlab` (view the VLAB tmux session)
5. **Access the lab (after completion):**
   - Grafana: `http://<host-ip>:3000` (admin / prom-operator)
   - Prometheus: `http://<host-ip>:9090`
   - ArgoCD: `http://<host-ip>:8080` (password from `argocd-initial-admin-secret`)
   - Gitea: `http://<host-ip>:3001` (gitea_admin / admin123)

## Idempotency & Re-Runs
- The installer is safe to re-run; it reuses the staged payload, preserves systemd units, and respects the `/var/lib/hedgehog-lab/initialized` stamp.
- If GHCR auth fails, re-run with `--interactive` or reset Docker creds in `/root/.docker/config.json`.

## Troubleshooting
- **Service still running:** `journalctl -u hedgehog-lab-init.service -f`
- **VLAB tmux session:** `tmux ls` then `tmux attach -t hhfab-vlab`
- **Disk space warnings:** expand the root volume, then re-run the installer.
- **Network blocks:** ensure egress to `ghcr.io` and `i.hhdev.io` (for hhfab download) is allowed.

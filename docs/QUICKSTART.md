# Hedgehog Lab Appliance - Quick Start Guide

Get up and running with the Hedgehog Lab Appliance in minutes.

## Table of Contents

- [First Login](#first-login)
- [Verify Services](#verify-services)
- [Accessing Services](#accessing-services)
- [Exploring the VLAB](#exploring-the-vlab)
- [Using the CLI](#using-the-cli)
- [Common Tasks](#common-tasks)
- [Next Steps](#next-steps)

## First Login

After the VM boots, you'll see the Ubuntu login prompt or desktop.

**Default Credentials:**
- **Username:** `hhlab`
- **Password:** `hhlab`

**Access Methods:**

**Console/SSH:**
```bash
# SSH to VM
ssh hhlab@<vm-ip>
Password: hhlab
```

**RDP (Recommended for Desktop):**
- Connect to: `<vm-ip>:3389`
- Username: `hhlab`
- Password: `hhlab`

**VNC:**
- Connect to: `<vm-ip>:5901`
- Password: `hhlab`

> **Security Note:** For production or shared environments, change the default password immediately:
> ```bash
> passwd
> ```

## IMPORTANT: First-Time Setup Required

**The lab does NOT initialize automatically.** You must configure GHCR credentials first.

### Run the Setup Wizard

```bash
hh-lab setup
```

This interactive wizard will:
1. Prompt for your GitHub username
2. Prompt for your GitHub Personal Access Token (PAT)
3. Authenticate with ghcr.io
4. Optionally start lab initialization

**Creating a GitHub PAT:**
1. Go to https://github.com/settings/tokens
2. Click "Generate new token" (classic)
3. Give it a name: "Hedgehog Lab"
4. Select scope: `read:packages`
5. Click "Generate token" and copy it

**Security:** The token is used only for `docker login` and immediately wiped from memory. It's NEVER stored to disk.

## Verify Services

After running `hh-lab setup` and allowing initialization to complete (15-20 minutes), verify everything is working.

### Quick Status Check

```bash
# View overall lab status
hh-lab status
```

**Expected output after initialization:**
```
Hedgehog Lab Status

✓ Lab is initialized and ready
  Build Type: standard
  Initialized: 2025-11-11T00:13:45Z

GHCR Authentication: ✓ Configured
  Username: your-github-username
  Authenticated: 2025-11-11T00:00:00Z

Services Status:
  k3d cluster (hedgehog-lab): [OK]
  Kubernetes API: [OK]
  hhfab CLI: [OK]
  VLAB: [OK] (7 switches running)
  ArgoCD: [OK]
  Gitea: [OK]
  Grafana: [OK]
```

**Before setup:**
```
Hedgehog Lab Status

⚠ Lab is not yet initialized
ℹ GHCR credentials not configured

GHCR Authentication: ✗ Not configured
  Run 'hh-lab setup' to configure credentials
```

### Monitor Initialization Progress

```bash
# Follow initialization logs in real-time
hh-lab logs -f

# Or use the monitor command for a cleaner view
hh-lab monitor

# Or use systemd directly
sudo journalctl -u hedgehog-lab-init.service -f
```

### Detailed Status

```bash
# Check k3d cluster
k3d cluster list
kubectl cluster-info
kubectl get nodes

# Check all pods across namespaces
kubectl get pods -A

# Check specific services
kubectl get pods -n grafana
kubectl get pods -n argocd
kubectl get pods -n gitea

# Inspect VLAB tmux session
tmux attach -t hhfab-vlab
# Press Ctrl+B then D to detach
```

**All pods should show `Running` status** (initialization takes 15-20 minutes)

## Accessing Services

The appliance includes several web-based services for managing and observing your lab environment.

### Service URLs and Credentials

| Service | URL | Username | Password | Purpose |
|---------|-----|----------|----------|---------|
| **Grafana** | http://localhost:3000 | `admin` | `admin` (change on first login) | Observability dashboards, metrics visualization |
| **ArgoCD** | http://localhost:8080 | `admin` | See below* | GitOps continuous delivery |
| **Gitea** | http://localhost:3001 | `hedgehog` | `hedgehog` | Git repository hosting |
| **Prometheus** | http://localhost:9090 | N/A | N/A | Metrics collection (direct access) |

> **Note:** If using **VirtualBox with NAT**, ensure port forwarding is configured (see [Installation Guide](INSTALL.md#installation-on-virtualbox)).
>
> If using **Bridged networking**, replace `localhost` with the VM's IP address.
>
> If using **GCP**, replace `localhost` with the instance's external IP address.

### Getting the ArgoCD Password

ArgoCD's initial admin password is stored in a file:

```bash
# Get ArgoCD admin password
cat /var/lib/hedgehog-lab/argocd-admin-password

# Or use kubectl
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 -d; echo
```

**Change the password after first login** for security.

### Accessing from Host Browser

1. **Open your browser** on the host machine (not inside the VM)

2. **Navigate to a service:**
   ```
   http://localhost:3000
   ```

3. **Login** with credentials from the table above

4. **Change default passwords** (recommended):
   - Grafana: User menu → Profile → Change Password
   - ArgoCD: User menu → User Info → Update Password
   - Gitea: User menu → Settings → Password

### Accessing from Other Machines (Bridged Mode Only)

If you configured bridged networking:

1. **Find the VM's IP address:**
   ```bash
   # Inside the VM
   ip addr show | grep "inet " | grep -v 127.0.0.1
   ```
   Example output: `inet 192.168.1.100/24`

2. **Access from another machine:**
   ```
   http://192.168.1.100:3000    # Grafana
   http://192.168.1.100:8080    # ArgoCD
   http://192.168.1.100:3001    # Gitea
   ```

## Exploring the VLAB

The Hedgehog Virtual Lab (VLAB) provides a simulated 7-switch Hedgehog Fabric topology running in containers.

### View VLAB Status

```bash
# Use hhfab CLI to inspect VLAB
cd /opt/hedgehog/vlab
hhfab vlab inspect
hhfab vlab status

# Check VLAB directory
ls -la /opt/hedgehog/vlab/

# View wiring diagram
cat /opt/hedgehog/vlab/wiring.yaml

# Check VLAB containers
docker ps
```

### Attach to VLAB tmux Session

The VLAB runs in a persistent tmux session that you can view:

```bash
# List tmux sessions
tmux ls

# Attach to VLAB session
tmux attach -t hhfab-vlab

# Press Ctrl+B then D to detach without stopping
```

### Access Switch Consoles

VLAB switches run in Docker containers with Hedgehog SONiC-based network OS.

```bash
# Use hhfab to list switches
cd /opt/hedgehog/vlab
hhfab vlab switch list

# Connect to a switch console via hhfab
hhfab vlab switch console <switch-name>

# Or use docker directly
docker ps --format "table {{.Names}}\t{{.Status}}"
docker exec -it <container-name> bash
```

**Available switches in default topology:**
- Spine switches (2)
- Leaf switches (4-5 depending on config)
- Control node (1)

### View VLAB Networking

```bash
# Show Docker networks created for VLAB
docker network ls

# Inspect VLAB working directory
ls -la /opt/hedgehog/vlab/
```

## Using the CLI

The `hh-lab` CLI tool provides convenient commands for managing the lab appliance.

### Available Commands

```bash
# Show help
hh-lab help

# Configure GHCR credentials (REQUIRED first time)
hh-lab setup

# View lab status
hh-lab status

# View initialization logs
hh-lab logs

# Follow logs in real-time
hh-lab logs -f

# Monitor initialization progress
hh-lab monitor

# View system information
hh-lab info
```

### Command Examples

**First-Time Setup:**
```bash
# Run setup wizard (required before first use)
hh-lab setup
```

**Checking Status:**
```bash
# Check overall status
hh-lab status

# Check if GHCR credentials are configured
hh-lab status | grep "GHCR Authentication"

# Check if initialization is complete
hh-lab status | grep initialized
```

**Viewing Logs:**
```bash
# View all logs
hh-lab logs

# Follow logs in real-time
hh-lab logs -f

# View module-specific logs
tail -f /var/log/hedgehog-lab/modules/vlab.log
tail -f /var/log/hedgehog-lab/modules/k3d.log
tail -f /var/log/hedgehog-lab/modules/gitops.log
```

**Troubleshooting:**
```bash
# View detailed system info
hh-lab info

# Check VLAB tmux session
tmux attach -t hhfab-vlab

# Manually restart initialization (if needed)
sudo systemctl restart hedgehog-lab-init.service
```

### CLI Auto-completion

Bash completion is enabled by default:

```bash
# Type 'hh-lab' and press TAB twice to see available commands
hh-lab <TAB><TAB>

# Partial completion works too
hh-lab st<TAB>    # completes to 'hh-lab status'
```

## Common Tasks

### Restart a Service

```bash
# Restart all pods in a namespace
kubectl rollout restart deployment -n monitoring

# Restart specific deployment
kubectl rollout restart deployment -n monitoring kube-prometheus-stack-grafana

# Check rollout status
kubectl rollout status deployment -n monitoring kube-prometheus-stack-grafana
```

### View Service Logs

```bash
# Grafana logs
kubectl logs -n monitoring deployment/kube-prometheus-stack-grafana

# ArgoCD logs
kubectl logs -n argocd deployment/argocd-server

# Follow logs in real-time
kubectl logs -n monitoring deployment/kube-prometheus-stack-grafana -f
```

### Check Resource Usage

```bash
# Node resource usage
kubectl top nodes

# Pod resource usage (all namespaces)
kubectl top pods -A

# Specific namespace
kubectl top pods -n monitoring
```

### Access Kubernetes Dashboard (Optional)

If you want a web-based Kubernetes dashboard:

```bash
# Install Kubernetes Dashboard
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

# Create admin user (for development only)
kubectl create serviceaccount dashboard-admin -n kubernetes-dashboard
kubectl create clusterrolebinding dashboard-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kubernetes-dashboard:dashboard-admin

# Get access token
kubectl -n kubernetes-dashboard create token dashboard-admin

# Start proxy
kubectl proxy

# Access at: http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
```

### Reset the Lab

If you need to start fresh:

```bash
# WARNING: This will destroy all lab data and reset to initial state

# Delete k3d cluster
k3d cluster delete k3d-observability

# Remove VLAB containers
docker stop $(docker ps -q --filter "name=vlab-")
docker rm $(docker ps -aq --filter "name=vlab-")

# Remove initialization marker
sudo rm /var/lib/hedgehog-lab/initialized

# Restart initialization
sudo systemctl restart hedgehog-lab-init

# Monitor progress
hh-lab logs --follow
```

## Next Steps

Now that you're up and running:

1. **Learn Hedgehog Fabric:**
   - Explore the VLAB topology
   - Practice SONiC CLI commands
   - Review Grafana dashboards for network metrics

2. **Experiment with GitOps:**
   - Create Git repositories in Gitea
   - Deploy applications with ArgoCD
   - Practice GitOps workflows

3. **Explore Observability:**
   - View metrics in Prometheus
   - Create custom Grafana dashboards
   - Query logs in Loki

4. **Advanced Topics:**
   - Scenario management (future feature)
   - Checkpointing lab state (future feature)
   - Custom VLAB topologies

5. **Get Help:**
   - [Troubleshooting Guide](TROUBLESHOOTING.md)
   - [FAQ](FAQ.md)
   - [GitHub Issues](https://github.com/afewell-hh/labapp/issues)

## Tips and Best Practices

### Performance

- **Allocate sufficient resources:** 8 vCPUs and 16 GB RAM recommended
- **Use SSD storage:** Much faster than HDD for container operations
- **Close unnecessary apps:** Free up host resources for the VM

### Persistence

- **Data persists across reboots:** Your configurations, Git repos, and dashboards are saved
- **Snapshots recommended:** Take VM snapshots before major changes
- **Backup important data:** Export configurations from Grafana, Gitea before experiments

### Security

- **Change default passwords:** Especially for shared/workshop environments
- **Firewall rules:** If using bridged mode, ensure proper network security
- **Keep updated:** Watch for appliance updates with security fixes

### Development Workflow

```bash
# Typical workflow for lab exercises:

# 1. Check status
hh-lab status

# 2. Access a switch
docker exec -it vlab-leaf-1 sonic-cli

# 3. Make configuration changes
# (configure your switch)

# 4. View metrics in Grafana
# (open browser to localhost:3000)

# 5. Check logs if needed
hh-lab logs

# 6. Take snapshot (in VMware/VirtualBox)
# (before major experiments)
```

## Support

Need help?

- **Documentation:** Check [INSTALL.md](INSTALL.md), [TROUBLESHOOTING.md](TROUBLESHOOTING.md), [FAQ.md](FAQ.md)
- **Command help:** `hh-lab --help`, `kubectl --help`
- **Logs:** `hh-lab logs`, `journalctl -u hedgehog-lab-init`
- **GitHub Issues:** https://github.com/afewell-hh/labapp/issues
- **Discussions:** https://github.com/afewell-hh/labapp/discussions

Happy learning with Hedgehog Fabric!

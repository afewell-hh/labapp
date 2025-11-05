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

After the VM boots, you'll see the Ubuntu login prompt.

**Default Credentials:**
- **Username:** `hhlab`
- **Password:** `hhlab`

```bash
# Login at the console or via SSH
Ubuntu 22.04.5 LTS hedgehog-lab tty1

hedgehog-lab login: hhlab
Password: hhlab
```

> **Security Note:** For production or shared environments, change the default password immediately:
> ```bash
> passwd
> ```

## Verify Services

Check that initialization completed successfully and all services are running.

### Quick Status Check

```bash
# View overall lab status
hh-lab status
```

**Expected output:**
```
Hedgehog Lab Status

✓ Lab is initialized and ready
  Build Type: standard
  Version: 0.1.0
  Initialized: 2025-11-05T10:23:45Z

Services:
  k3d Cluster: [OK] (k3d-observability)
  VLAB: [OK] (7 switches, 0 VPCs)
  GitOps: [PENDING] (deployment in future sprint)
  Observability: [OK] (Prometheus, Grafana, Loki)

Current Scenario: default
```

### Detailed Status

```bash
# Check k3d cluster
kubectl cluster-info
kubectl get nodes

# Check all pods across namespaces
kubectl get pods -A

# Check specific services
kubectl get pods -n monitoring
kubectl get pods -n argocd
kubectl get pods -n gitea
```

**All pods should show `Running` status** (may take a few minutes after first boot)

## Accessing Services

The appliance includes several web-based services for managing and observing your lab environment.

### Service URLs and Credentials

| Service | URL | Username | Password | Purpose |
|---------|-----|----------|----------|---------|
| **Grafana** | http://localhost:3000 | `admin` | `admin` | Observability dashboards, metrics visualization |
| **ArgoCD** | http://localhost:8080 | `admin` | See below* | GitOps continuous delivery |
| **Gitea** | http://localhost:3001 | `gitea_admin` | `admin123` | Git repository hosting |
| **Prometheus** | http://localhost:9090 | N/A | N/A | Metrics collection (direct access) |

> **Note:** If using **VirtualBox with NAT**, ensure port forwarding is configured (see [Installation Guide](INSTALL.md#installation-on-virtualbox)).
>
> If using **Bridged networking**, replace `localhost` with the VM's IP address.

### Getting the ArgoCD Password

ArgoCD generates a random initial admin password. Retrieve it with:

```bash
# Get ArgoCD admin password
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
# Check VLAB directory
ls -la /opt/hedgehog/vlab/

# View wiring diagram
cat /opt/hedgehog/vlab/wiring.yaml

# Check VLAB containers
docker ps | grep vlab
```

### Access Switch Consoles

VLAB switches run in Docker containers with SONiC network OS.

```bash
# List VLAB containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Connect to a switch console (example)
docker exec -it vlab-leaf-1 bash

# Inside the switch container
sonic-cli
show version
show interfaces status
exit
```

**Available switches in default topology:**
- `vlab-spine-1`, `vlab-spine-2` (Spine switches)
- `vlab-leaf-1`, `vlab-leaf-2`, `vlab-leaf-3`, `vlab-leaf-4` (Leaf switches)
- `vlab-control-1` (Control node)

### View VLAB Networking

```bash
# Show Docker networks created for VLAB
docker network ls | grep vlab

# Inspect a VLAB network
docker network inspect vlab-fabric
```

## Using the CLI

The `hh-lab` CLI tool provides convenient commands for managing the lab appliance.

### Available Commands

```bash
# Show help
hh-lab --help

# View lab status
hh-lab status

# View initialization logs
hh-lab logs

# Follow logs in real-time
hh-lab logs --follow

# View system information
hh-lab info

# View service details
hh-lab services
```

### Command Examples

```bash
# Check if initialization is complete
hh-lab status | grep initialized

# View only errors from logs
hh-lab logs | grep ERROR

# View k3d-specific logs
sudo cat /var/log/hedgehog-lab/modules/k3d.log

# View VLAB-specific logs
sudo cat /var/log/hedgehog-lab/modules/vlab.log
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

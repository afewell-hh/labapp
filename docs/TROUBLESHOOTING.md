# Hedgehog Lab Appliance - Troubleshooting Guide

Solutions to common issues you might encounter with the Hedgehog Lab Appliance.

## Table of Contents

- [Installation Issues](#installation-issues)
- [First Boot Issues](#first-boot-issues)
- [Service Issues](#service-issues)
- [Network Issues](#network-issues)
- [Performance Issues](#performance-issues)
- [VLAB Issues](#vlab-issues)
- [Kubernetes Issues](#kubernetes-issues)
- [Getting Help](#getting-help)

## Installation Issues

### Issue: OVA Import Fails in VMware

**Symptoms:**
- Import fails with "Invalid OVF descriptor" error
- Import hangs or times out

**Solutions:**

1. **Verify OVA file integrity:**
   ```bash
   sha256sum hedgehog-lab-standard-0.1.0.ova
   # Compare with published checksum
   ```

2. **Check disk space:**
   - Ensure at least 120 GB free on destination storage
   - Use different datastore/drive if needed

3. **Try alternative import method:**
   ```bash
   # Extract OVA to OVF + VMDK
   tar -xvf hedgehog-lab-standard-0.1.0.ova
   # Import the OVF instead
   ```

4. **Update VMware:**
   - Ensure VMware Workstation/Fusion is up to date
   - OVA format requires VMware 12+ or Fusion 8+

### Issue: VirtualBox Import Fails

**Symptoms:**
- "NS_ERROR_INVALID_ARG" during import
- Import completes but VM won't start

**Solutions:**

1. **Check VirtualBox version:**
   ```bash
   VBoxManage --version
   # Minimum: VirtualBox 6.1 or later
   ```

2. **Enable virtualization in BIOS:**
   - Restart host computer
   - Enter BIOS/UEFI settings (usually F2, F10, or Del during boot)
   - Enable Intel VT-x or AMD-V
   - Save and reboot

3. **Import as VDI:**
   - During import, check "Import hard drives as VDI"
   - VDI format has better VirtualBox compatibility

4. **Manual VM creation (last resort):**
   ```bash
   # Extract VMDK from OVA
   tar -xvf hedgehog-lab-standard-0.1.0.ova

   # Create VM manually in VirtualBox
   # - Attach extracted VMDK as hard drive
   # - Configure: Ubuntu 64-bit, 8 CPUs, 16 GB RAM
   ```

### Issue: Insufficient Resources Error

**Symptoms:**
- "Not enough memory" during import
- VM won't start due to resource constraints

**Solutions:**

1. **Close other VMs and applications**
2. **Reduce VM resources temporarily:**
   - Minimum viable: 4 CPUs, 8 GB RAM
   - Edit VM settings before first boot
   - Performance will be reduced

3. **Check available host resources:**
   ```bash
   # Linux
   free -h
   nproc

   # macOS
   sysctl hw.memsize
   sysctl hw.ncpu

   # Windows (PowerShell)
   Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory
   Get-CimInstance Win32_Processor | Select-Object NumberOfLogicalProcessors
   ```

## First Boot Issues

### Issue: Initialization Takes Too Long

**Symptoms:**
- Initialization exceeds 30 minutes
- Appears stuck on a step

**Solutions:**

1. **Check initialization status:**
   ```bash
   # Login to VM (hhlab/hhlab)
   hh-lab status

   # View real-time logs
   hh-lab logs --follow
   ```

2. **View detailed progress:**
   ```bash
   sudo journalctl -u hedgehog-lab-init -f
   ```

3. **Check which step is running:**
   ```bash
   sudo cat /var/lib/hedgehog-lab/state.json
   ```

4. **Network-related delays:**
   - k3d cluster creation requires internet for container images
   - Slow networks can add 10-15 minutes
   - Check: `ping -c 3 8.8.8.8`

5. **Be patient:**
   - First boot initialization: 15-20 minutes is normal
   - VLAB initialization is the longest step (5-10 minutes)

### Issue: Initialization Fails

**Symptoms:**
- Initialization exits with error
- `hh-lab status` shows "Failed" state

**Solutions:**

1. **Check error logs:**
   ```bash
   hh-lab logs | grep ERROR

   # View full initialization log
   sudo cat /var/log/hedgehog-lab-init.log
   ```

2. **Check module-specific logs:**
   ```bash
   sudo cat /var/log/hedgehog-lab/modules/k3d.log
   sudo cat /var/log/hedgehog-lab/modules/vlab.log
   sudo cat /var/log/hedgehog-lab/modules/network.log
   ```

3. **Common failure causes:**
   - **No network:** Verify VM has internet access
   - **Insufficient disk space:** Check with `df -h`
   - **Docker issues:** Check with `docker ps`

4. **Retry initialization:**
   ```bash
   # Remove failure marker
   sudo rm /var/lib/hedgehog-lab/initialized

   # Restart initialization service
   sudo systemctl restart hedgehog-lab-init

   # Monitor progress
   hh-lab logs --follow
   ```

### Issue: VM Boots to Login but Services Not Ready

**Symptoms:**
- Can login but `hh-lab status` shows not initialized
- Services unreachable

**Solutions:**

1. **Check if initialization is still running:**
   ```bash
   sudo systemctl status hedgehog-lab-init
   ```

2. **If not running, start it:**
   ```bash
   sudo systemctl start hedgehog-lab-init
   ```

3. **Check for startup failures:**
   ```bash
   sudo systemctl list-units --failed
   ```

## Service Issues

### Issue: Cannot Access Web Services

**Symptoms:**
- Browser shows "Connection refused" or "Unable to connect"
- URLs not loading (Grafana, ArgoCD, Gitea)

**Solutions:**

1. **Verify services are running:**
   ```bash
   kubectl get pods -A
   # All pods should show "Running" status
   ```

2. **Check service endpoints:**
   ```bash
   kubectl get svc -A
   ```

3. **VirtualBox + NAT: Check port forwarding:**
   - VM Settings → Network → Port Forwarding
   - Ensure rules exist for ports 3000, 8080, 3001
   - Add missing rules if needed

4. **Test from inside VM first:**
   ```bash
   # Inside the VM
   curl http://localhost:3000
   curl http://localhost:8080
   curl http://localhost:3001
   ```

5. **Check firewall (if using bridged mode):**
   ```bash
   sudo ufw status
   # If active, allow ports:
   sudo ufw allow 3000/tcp
   sudo ufw allow 8080/tcp
   sudo ufw allow 3001/tcp
   ```

6. **Restart port forwarding (VirtualBox):**
   - Power off VM
   - Edit network settings
   - Remove and re-add port forwarding rules
   - Power on VM

### Issue: Grafana Login Fails

**Symptoms:**
- "Invalid username or password"
- Default credentials don't work

**Solutions:**

1. **Use correct default credentials:**
   - Username: `admin`
   - Password: `admin`

2. **Check Grafana pod status:**
   ```bash
   kubectl get pods -n monitoring | grep grafana
   kubectl logs -n monitoring deployment/kube-prometheus-stack-grafana
   ```

3. **Reset Grafana admin password:**
   ```bash
   # Get Grafana pod name
   GRAFANA_POD=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].metadata.name}')

   # Reset password inside pod
   kubectl exec -n monitoring $GRAFANA_POD -- grafana-cli admin reset-admin-password newpassword
   ```

### Issue: Cannot Get ArgoCD Password

**Symptoms:**
- `kubectl get secret` command fails
- Secret not found

**Solutions:**

1. **Check ArgoCD namespace exists:**
   ```bash
   kubectl get namespace argocd
   ```

2. **Check if secret exists:**
   ```bash
   kubectl get secrets -n argocd
   ```

3. **If ArgoCD not deployed yet:**
   - GitOps stack deployment is in future sprint
   - ArgoCD may not be available in current MVP

4. **Alternative: Reset ArgoCD password:**
   ```bash
   # Get current password
   kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

   # Or reset via CLI
   kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d | argocd login localhost:8080 --username admin --password-stdin
   argocd account update-password
   ```

### Issue: Pod Stuck in Pending or CrashLoopBackOff

**Symptoms:**
- `kubectl get pods -A` shows pods not Running
- Services unavailable

**Solutions:**

1. **Check pod details:**
   ```bash
   kubectl describe pod <pod-name> -n <namespace>
   ```

2. **View pod logs:**
   ```bash
   kubectl logs <pod-name> -n <namespace>
   kubectl logs <pod-name> -n <namespace> --previous  # if crashed
   ```

3. **Common causes:**
   - **Pending:** Insufficient resources
     ```bash
     kubectl top nodes
     # Increase VM RAM/CPU if needed
     ```
   - **ImagePullBackOff:** Network issue or image not available
     ```bash
     kubectl describe pod <pod-name> -n <namespace> | grep -A 5 Events
     ```
   - **CrashLoopBackOff:** Application error
     ```bash
     kubectl logs <pod-name> -n <namespace>
     ```

4. **Restart pod:**
   ```bash
   kubectl delete pod <pod-name> -n <namespace>
   # Kubernetes will recreate it automatically
   ```

## Network Issues

### Issue: No Internet Access from VM

**Symptoms:**
- `ping 8.8.8.8` fails
- Cannot download container images
- Initialization fails at "Wait for network" step

**Solutions:**

1. **Check VM network adapter:**
   - VMware/VirtualBox: Ensure network adapter is connected
   - Settings → Network → "Connect" checkbox enabled

2. **Check network mode:**
   - NAT mode should work out of the box
   - Bridged mode requires DHCP on local network

3. **Verify IP address assigned:**
   ```bash
   ip addr show
   # Should show IP address on enp0s3 or similar
   ```

4. **Check DNS:**
   ```bash
   cat /etc/resolv.conf
   # Should show nameserver entries

   # Test DNS
   nslookup google.com
   ```

5. **Restart networking:**
   ```bash
   sudo systemctl restart systemd-networkd
   sudo systemctl restart systemd-resolved
   ```

6. **Check host network:**
   - Ensure host computer has internet access
   - Temporarily disable host firewall/VPN to test

### Issue: Cannot Access VM from Host (Bridged Mode)

**Symptoms:**
- Can't connect to VM's IP address from host
- Other machines can't access services

**Solutions:**

1. **Verify VM has IP address:**
   ```bash
   ip addr show | grep "inet "
   ```

2. **Check if host can ping VM:**
   ```bash
   # On host
   ping <VM_IP>
   ```

3. **Check VM firewall:**
   ```bash
   sudo ufw status
   sudo ufw allow from <HOST_IP>
   ```

4. **Verify network mode:**
   - VirtualBox: Settings → Network → Attached to: Bridged Adapter
   - Select correct physical adapter (Wi-Fi or Ethernet)

5. **Check local network:**
   - Ensure host and VM on same subnet
   - Some networks block VM bridged mode (corporate, public Wi-Fi)

## Performance Issues

### Issue: VM Running Very Slowly

**Symptoms:**
- High CPU usage on host
- Sluggish VM response
- Services timing out

**Solutions:**

1. **Check resource allocation:**
   ```bash
   # Inside VM
   nproc  # Should show 8 CPUs
   free -h  # Should show ~16 GB
   ```

2. **Check host resources:**
   - Close other VMs and resource-intensive apps
   - Monitor host CPU/RAM usage

3. **Enable hardware virtualization:**
   - VirtualBox: VM Settings → System → Acceleration → VT-x/AMD-V enabled
   - VMware: Usually enabled by default

4. **Reduce VM resources if host limited:**
   - Power off VM
   - Reduce to 4 CPUs, 8 GB RAM (minimum)
   - Expect reduced performance

5. **Check for CPU-intensive processes:**
   ```bash
   top
   # Look for processes using high CPU
   ```

6. **SSD vs HDD:**
   - Move VM to SSD if currently on HDD
   - Significant performance improvement for container operations

### Issue: Disk Space Running Low

**Symptoms:**
- "No space left on device" errors
- Services failing
- Cannot pull container images

**Solutions:**

1. **Check disk usage:**
   ```bash
   df -h
   sudo du -sh /var/lib/docker
   sudo du -sh /opt/hedgehog
   ```

2. **Clean up Docker:**
   ```bash
   # Remove unused images and containers
   docker system prune -a

   # Remove unused volumes
   docker volume prune
   ```

3. **Clean up logs:**
   ```bash
   sudo journalctl --vacuum-time=7d
   ```

4. **Check VM disk size:**
   - Power off VM
   - Expand virtual disk in VMware/VirtualBox
   - Boot and resize partition

## VLAB Issues

### Issue: VLAB Containers Not Running

**Symptoms:**
- `docker ps` shows no VLAB containers
- Cannot access switches

**Solutions:**

1. **Check VLAB initialization:**
   ```bash
   sudo cat /var/log/hedgehog-lab/modules/vlab.log
   ```

2. **Verify VLAB directory:**
   ```bash
   ls -la /opt/hedgehog/vlab/
   ```

3. **Check Docker service:**
   ```bash
   sudo systemctl status docker
   sudo systemctl start docker  # if not running
   ```

4. **Manually start VLAB (if implemented):**
   ```bash
   # Future: hh-lab vlab start
   # Currently: Check init script
   sudo /usr/local/bin/hedgehog-vlab-init
   ```

### Issue: Cannot Connect to Switch Console

**Symptoms:**
- `docker exec` fails
- Container not found

**Solutions:**

1. **List VLAB containers:**
   ```bash
   docker ps --filter "name=vlab"
   ```

2. **Check container is running:**
   ```bash
   docker inspect vlab-leaf-1 | grep Status
   ```

3. **View container logs:**
   ```bash
   docker logs vlab-leaf-1
   ```

4. **Restart container:**
   ```bash
   docker restart vlab-leaf-1
   ```

## Kubernetes Issues

### Issue: kubectl Commands Fail

**Symptoms:**
- "The connection to the server localhost:8080 was refused"
- kubectl cannot connect to cluster

**Solutions:**

1. **Check k3d cluster exists:**
   ```bash
   k3d cluster list
   ```

2. **Verify kubeconfig:**
   ```bash
   echo $KUBECONFIG
   ls -la ~/.kube/config

   # Set context
   kubectl config use-context k3d-k3d-observability
   ```

3. **Check k3d cluster status:**
   ```bash
   k3d cluster list
   docker ps | grep k3d
   ```

4. **Restart k3d cluster:**
   ```bash
   k3d cluster stop k3d-observability
   k3d cluster start k3d-observability
   ```

### Issue: Helm Commands Fail

**Symptoms:**
- Helm charts won't install
- Repository errors

**Solutions:**

1. **Update Helm repos:**
   ```bash
   helm repo update
   ```

2. **Check Helm version:**
   ```bash
   helm version
   ```

3. **Verify Kubernetes connection:**
   ```bash
   kubectl cluster-info
   ```

## Getting Help

If you're still experiencing issues:

### Collect Diagnostic Information

```bash
# System info
hh-lab info > diagnostics.txt

# Status
hh-lab status >> diagnostics.txt

# Logs
hh-lab logs >> diagnostics.txt

# Kubernetes state
kubectl get pods -A >> diagnostics.txt
kubectl get nodes >> diagnostics.txt
kubectl top nodes >> diagnostics.txt

# Docker state
docker ps >> diagnostics.txt
docker images >> diagnostics.txt
```

### Where to Get Help

1. **Documentation:**
   - [Installation Guide](INSTALL.md)
   - [Quick Start Guide](QUICKSTART.md)
   - [FAQ](FAQ.md)

2. **GitHub Issues:**
   - Search existing issues: https://github.com/afewell-hh/labapp/issues
   - Create new issue with diagnostics info

3. **GitHub Discussions:**
   - Q&A and community help: https://github.com/afewell-hh/labapp/discussions

4. **Include in Bug Reports:**
   - Output of `hh-lab info`
   - Output of `hh-lab status`
   - Relevant log excerpts
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - VM configuration (CPUs, RAM, disk)
   - Host OS and virtualization platform

### Emergency Reset

As a last resort, completely reset the lab:

```bash
# WARNING: This destroys all lab data

# Stop everything
sudo systemctl stop hedgehog-lab-init
k3d cluster delete k3d-observability
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

# Clean up
sudo rm -rf /var/lib/hedgehog-lab
sudo rm -rf /opt/hedgehog/vlab
sudo rm -f /var/log/hedgehog-lab-init.log

# Reboot VM
sudo reboot

# After reboot, initialization will run automatically
```

For issues not covered here, please open a GitHub issue with detailed diagnostics.

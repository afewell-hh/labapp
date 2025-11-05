# Hedgehog Lab Appliance - E2E Test Plan

**Version:** 1.0
**Date:** 2025-11-05
**Target Release:** v0.1.0 MVP
**Issue:** #21

## Table of Contents

- [Overview](#overview)
- [Test Objectives](#test-objectives)
- [Test Scope](#test-scope)
- [Test Environment](#test-environment)
- [Test Procedures](#test-procedures)
  - [1. Build Testing](#1-build-testing)
  - [2. VMware Testing](#2-vmware-testing)
  - [3. VirtualBox Testing](#3-virtualbox-testing)
  - [4. Service Validation](#4-service-validation)
  - [5. VLAB Testing](#5-vlab-testing)
  - [6. GitOps Workflow Testing](#6-gitops-workflow-testing)
  - [7. Observability Testing](#7-observability-testing)
- [Pass/Fail Criteria](#passfail-criteria)
- [Test Results Template](#test-results-template)

---

## Overview

This test plan provides comprehensive procedures for validating the Hedgehog Lab Appliance v0.1.0 MVP release. It covers the complete user workflow from build to deployment to usage across multiple virtualization platforms.

## Test Objectives

1. **Verify build pipeline** produces valid OVA artifacts
2. **Validate deployment** on VMware Workstation, Fusion, and VirtualBox
3. **Confirm initialization** completes successfully on first boot
4. **Test all services** are accessible and functional
5. **Validate VLAB** environment is operational
6. **Verify GitOps workflow** functions end-to-end
7. **Confirm observability** stack provides metrics and logs

## Test Scope

### In Scope

- ✅ Standard build OVA creation
- ✅ VMware Workstation 17.x (Windows/Linux)
- ✅ VMware Fusion 13.x (macOS)
- ✅ VirtualBox 7.x (All platforms)
- ✅ First boot initialization (standard build)
- ✅ Service availability and health
- ✅ VLAB 7-switch topology
- ✅ Basic GitOps workflow (when implemented)
- ✅ Observability dashboards and metrics

### Out of Scope

- ❌ Pre-warmed build testing (v0.2.0)
- ❌ VMware ESXi/vSphere testing (future)
- ❌ Hyper-V testing (not supported)
- ❌ Performance benchmarking (separate effort)
- ❌ Security testing (separate effort)
- ❌ Upgrade testing (future releases)

## Test Environment

### Build Environment

**OS:** Ubuntu 22.04 LTS
**Packer:** 1.11.2+
**QEMU:** Latest from Ubuntu repos
**Resources:** 8+ CPU cores, 32 GB RAM, 200 GB disk
**Network:** High-speed internet connection

### Test Environments

#### VMware Workstation (Windows)

- **Host OS:** Windows 10/11 Pro
- **VMware Version:** Workstation 17.x
- **Host CPU:** Intel Core i7/i9 with VT-x
- **Host RAM:** 32 GB
- **Host Disk:** 150 GB free (SSD)

#### VMware Workstation (Linux)

- **Host OS:** Ubuntu 22.04 LTS
- **VMware Version:** Workstation 17.x Pro
- **Host CPU:** AMD Ryzen/Intel Core with virtualization
- **Host RAM:** 32 GB
- **Host Disk:** 150 GB free (SSD)

#### VMware Fusion (macOS)

- **Host OS:** macOS 13.x+ (Ventura/Sonoma)
- **VMware Version:** Fusion 13.x
- **Host CPU:** Intel or Apple Silicon (with Rosetta)
- **Host RAM:** 32 GB
- **Host Disk:** 150 GB free

#### VirtualBox

- **Host OS:** Windows 10/11, macOS 13+, or Ubuntu 22.04
- **VirtualBox Version:** 7.0.x
- **Extension Pack:** Installed
- **Host CPU:** VT-x/AMD-V enabled
- **Host RAM:** 32 GB
- **Host Disk:** 150 GB free

---

## Test Procedures

### 1. Build Testing

**Objective:** Verify Packer build produces valid artifacts

**Tester:** Build engineer
**Duration:** 60-90 minutes
**Automation:** `scripts/validate-build.sh`

#### 1.1 Local Build Test

```bash
# Step 1: Clone repository
git clone https://github.com/afewell-hh/labapp.git
cd labapp

# Step 2: Initialize Packer
packer init packer/standard-build.pkr.hcl

# Step 3: Validate template
packer validate packer/standard-build.pkr.hcl

# Step 4: Build (full resources)
packer build \
  -var "version=0.1.0-test" \
  packer/standard-build.pkr.hcl

# Step 5: Validate build output
cd tests/e2e
./scripts/validate-build.sh ../../output-hedgehog-lab-standard
```

**Expected Results:**
- ✅ Packer build completes without errors
- ✅ OVA file created in output directory
- ✅ OVA size between 15-25 GB
- ✅ SHA256 checksum file present
- ✅ Checksum verification passes
- ✅ VMDK file present and valid
- ✅ OVF file present and well-formed

**Pass Criteria:** All checks pass, `validate-build.sh` exits with code 0

---

### 2. VMware Testing

**Objective:** Validate appliance deployment and operation on VMware platforms

#### 2.1 VMware Workstation (Windows)

**Tester:** QA engineer
**Duration:** 45 minutes
**Platform:** Windows 10/11 + VMware Workstation 17.x

##### Setup

1. **Download OVA**
   ```powershell
   # Download from release or use local build
   cd C:\VMs
   # Copy hedgehog-lab-standard-0.1.0.ova to this directory
   ```

2. **Verify Checksum** (PowerShell)
   ```powershell
   Get-FileHash .\hedgehog-lab-standard-0.1.0.ova -Algorithm SHA256
   # Compare with .sha256 file
   ```

3. **Import OVA**
   - Open VMware Workstation
   - File → Open
   - Select `hedgehog-lab-standard-0.1.0.ova`
   - Name: `HedgehogLab-Test`
   - Storage: Default location
   - Click Import
   - Wait for import (5-10 minutes)

4. **Configure Network**
   - Right-click VM → Settings
   - Network Adapter → NAT
   - Click OK

5. **Power On**
   - Click "Power On"
   - Watch console for boot messages

##### Validation

6. **Monitor First Boot Initialization**
   - Login at console: `hhlab` / `hhlab`
   - Run: `hh-lab logs --follow`
   - Watch for completion (15-20 minutes)
   - **Expected:** "Initialization Complete!" message

7. **Run Service Tests**
   ```bash
   cd /tmp
   git clone https://github.com/afewell-hh/labapp.git
   cd labapp/tests/e2e
   ./scripts/validate-services.sh
   ```
   - **Expected:** All service checks pass

8. **Test Web Access** (from Windows host)
   - Open browser: `http://localhost:3000`
   - **Expected:** Grafana login page
   - Login: `admin` / `admin`
   - **Expected:** Grafana home dashboard

9. **Run Full Test Suite**
   ```bash
   cd /tmp/labapp/tests/e2e
   ./scripts/run-all-tests.sh
   ```
   - **Expected:** All tests pass

**Pass Criteria:**
- ✅ OVA imports successfully
- ✅ VM boots without errors
- ✅ Initialization completes in < 25 minutes
- ✅ All services running and accessible
- ✅ Test suite passes 100%

**Screenshot Requirements:**
- [ ] VMware import dialog
- [ ] First boot console
- [ ] `hh-lab status` output
- [ ] Grafana dashboard
- [ ] Test results summary

#### 2.2 VMware Fusion (macOS)

**Tester:** QA engineer
**Duration:** 45 minutes
**Platform:** macOS 13+ + VMware Fusion 13.x

##### Setup

1. **Download OVA**
   ```bash
   cd ~/VMs
   # Download or copy OVA here
   ```

2. **Import OVA**
   - Open VMware Fusion
   - File → Import
   - Select OVA file
   - Name: `HedgehogLab-Test`
   - Click Continue
   - Wait for import

3. **Network Configuration**
   - Virtual Machine → Settings
   - Network Adapter → Share with my Mac (NAT)
   - Close settings

4. **Start VM**
   - Click Play button

##### Validation

5. **Follow validation steps 6-9 from VMware Workstation test**
   - Same procedures apply
   - Use Safari/Chrome on macOS for web access

**Pass Criteria:** Same as VMware Workstation

---

### 3. VirtualBox Testing

**Objective:** Validate appliance deployment on VirtualBox

**Tester:** QA engineer
**Duration:** 45 minutes
**Platform:** Ubuntu 22.04 + VirtualBox 7.0.x

#### Setup

1. **Install VirtualBox Extension Pack** (if not installed)
   ```bash
   # Download from virtualbox.org
   sudo VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-*.vbox-extpack
   ```

2. **Import OVA**
   - Open VirtualBox
   - File → Import Appliance
   - Select OVA file
   - Appliance Settings:
     - Name: `HedgehogLab-Test`
     - CPUs: 8
     - RAM: 16384 MB
     - Check "Import hard drives as VDI"
   - Click Import
   - Accept license
   - Wait for import (5-15 minutes)

3. **Configure Port Forwarding**
   - Select VM → Settings → Network
   - Adapter 1 → NAT
   - Advanced → Port Forwarding
   - Add rules:
     | Name | Protocol | Host Port | Guest Port |
     |------|----------|-----------|------------|
     | Grafana | TCP | 3000 | 3000 |
     | ArgoCD | TCP | 8080 | 8080 |
     | Gitea | TCP | 3001 | 3001 |
   - Click OK

4. **Start VM**
   - Click Start

#### Validation

5. **Monitor Initialization**
   - Login: `hhlab` / `hhlab`
   - Run: `hh-lab logs --follow`
   - **Expected:** Completes successfully in 15-20 minutes

6. **Run Tests**
   ```bash
   cd /tmp
   git clone https://github.com/afewell-hh/labapp.git
   cd labapp/tests/e2e
   ./scripts/run-all-tests.sh
   ```

7. **Test Web Access**
   - From host browser: `http://localhost:3000`
   - **Expected:** Grafana accessible

**Pass Criteria:**
- ✅ OVA imports successfully
- ✅ Port forwarding works
- ✅ VM boots and initializes
- ✅ All services accessible via localhost
- ✅ Test suite passes

---

### 4. Service Validation

**Objective:** Verify all services are running and healthy

**Tester:** Any
**Duration:** 10 minutes
**Automation:** `scripts/validate-services.sh`

#### Manual Validation

```bash
# 1. Check lab status
hh-lab status

# Expected output:
# ✓ Lab is initialized and ready
# Services:
#   k3d Cluster: [OK]
#   VLAB: [OK]
#   GitOps: [PENDING] or [OK]
#   Observability: [OK]

# 2. Check k3d cluster
kubectl cluster-info
kubectl get nodes
kubectl get pods -A

# Expected:
# - Cluster info shows API server running
# - Node(s) in Ready state
# - All pods Running or Completed

# 3. Check specific namespaces
kubectl get pods -n monitoring
kubectl get pods -n argocd
kubectl get pods -n gitea

# Expected: All pods in Running state

# 4. Test service endpoints
curl -s http://localhost:3000/api/health | jq .  # Grafana
curl -s http://localhost:8080/healthz             # ArgoCD
curl -s http://localhost:3001/                    # Gitea

# Expected: All return successful responses

# 5. Check VLAB containers
docker ps --filter "name=vlab-" --format "table {{.Names}}\t{{.Status}}"

# Expected: 7 containers running (2 spines, 4 leaves, 1 control)
```

**Automated Validation**

```bash
./scripts/validate-services.sh
```

**Pass Criteria:**
- ✅ `hh-lab status` shows all services OK
- ✅ k3d cluster healthy
- ✅ All Kubernetes pods running
- ✅ Service endpoints respond
- ✅ VLAB containers running
- ✅ Automation script passes

---

### 5. VLAB Testing

**Objective:** Validate VLAB environment functionality

**Tester:** Network engineer or QA
**Duration:** 15 minutes
**Automation:** `scripts/validate-vlab.sh`

#### Manual Validation

```bash
# 1. Check VLAB status
hh-lab status | grep VLAB

# Expected: VLAB: [OK] (7 switches, 0 VPCs)

# 2. List VLAB containers
docker ps --filter "name=vlab-" --format "{{.Names}}"

# Expected output:
# vlab-spine-1
# vlab-spine-2
# vlab-leaf-1
# vlab-leaf-2
# vlab-leaf-3
# vlab-leaf-4
# vlab-control-1

# 3. Check VLAB directory
ls -la /opt/hedgehog/vlab/
cat /opt/hedgehog/vlab/wiring.yaml

# Expected: Configuration files present

# 4. Test switch console access
docker exec -it vlab-leaf-1 bash

# Inside container:
hostname  # Should show leaf-1
# If SONiC CLI available:
# sonic-cli
# show version
# exit
exit

# 5. Check VLAB networks
docker network ls | grep vlab

# Expected: VLAB-related networks present

# 6. Verify switch connectivity
docker exec vlab-leaf-1 ping -c 2 vlab-spine-1

# Expected: Ping succeeds (if connectivity configured)
```

**Automated Validation**

```bash
./scripts/validate-vlab.sh
```

**Pass Criteria:**
- ✅ All 7 switch containers running
- ✅ Switch console access works
- ✅ VLAB configuration files present
- ✅ Networks configured correctly
- ✅ Automation script passes

---

### 6. GitOps Workflow Testing

**Objective:** Validate GitOps stack (ArgoCD + Gitea) functionality

**Tester:** DevOps engineer or QA
**Duration:** 20 minutes
**Automation:** `scripts/validate-gitops.sh`

#### Manual Validation

**Note:** GitOps deployment is marked for future sprint. If services not deployed, skip this section.

```bash
# 1. Check GitOps services
kubectl get pods -n argocd
kubectl get pods -n gitea

# Expected: All pods Running

# 2. Get ArgoCD password
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 -d; echo

# 3. Access Gitea (from host browser)
# URL: http://localhost:3001
# Username: gitea_admin
# Password: admin123

# 4. Create test repository in Gitea
# - Click "+" → New Repository
# - Name: test-app
# - Initialize with README
# - Create Repository

# 5. Access ArgoCD (from host browser)
# URL: http://localhost:8080
# Username: admin
# Password: <from step 2>

# 6. Create ArgoCD application
# - Click "New App"
# - Application Name: test-app
# - Project: default
# - Sync Policy: Manual
# - Repository URL: http://gitea-http.gitea.svc:3000/gitea_admin/test-app
# - Path: .
# - Destination: https://kubernetes.default.svc
# - Namespace: default
# - Click Create

# 7. Sync application
# - Click Sync
# - Expected: Sync succeeds (or shows "no manifests" if empty repo)
```

**Automated Validation**

```bash
./scripts/validate-gitops.sh
```

**Pass Criteria:**
- ✅ Gitea accessible and functional
- ✅ Can create repositories
- ✅ ArgoCD accessible
- ✅ Can create applications
- ✅ GitOps sync works (if manifests present)
- ✅ Automation script passes

---

### 7. Observability Testing

**Objective:** Validate observability stack (Prometheus, Grafana, Loki)

**Tester:** SRE or QA
**Duration:** 15 minutes
**Automation:** `scripts/validate-observability.sh`

#### Manual Validation

```bash
# 1. Check observability pods
kubectl get pods -n monitoring

# Expected: All pods Running
# - Prometheus
# - Grafana
# - Loki
# - Node exporter
# - kube-state-metrics

# 2. Access Grafana (from host browser)
# URL: http://localhost:3000
# Username: admin
# Password: admin

# 3. Verify data sources
# - Navigate to Configuration → Data Sources
# - Expected: Prometheus and Loki configured

# 4. Check dashboards
# - Click Dashboards
# - Expected: Pre-installed dashboards present
# - Open "Kubernetes / Compute Resources / Cluster"
# - Expected: Metrics displayed

# 5. Test Prometheus (from host browser)
# URL: http://localhost:9090
# Query: up
# Expected: Shows all targets

# 6. Test Loki queries in Grafana
# - Explore → Loki
# - Query: {namespace="monitoring"}
# - Expected: Logs displayed

# 7. Check metrics collection
kubectl top nodes
kubectl top pods -A

# Expected: Resource usage displayed
```

**Automated Validation**

```bash
./scripts/validate-observability.sh
```

**Pass Criteria:**
- ✅ All observability pods running
- ✅ Grafana accessible with dashboards
- ✅ Prometheus collecting metrics
- ✅ Loki ingesting logs
- ✅ Data sources configured correctly
- ✅ Can query metrics and logs
- ✅ Automation script passes

---

## Pass/Fail Criteria

### Overall Test Pass Criteria

For v0.1.0 MVP release, **ALL** of the following must pass:

#### Build Tests
- [x] Standard build completes successfully
- [x] OVA artifacts created and valid
- [x] Checksums verify correctly
- [x] Build validation script passes

#### Platform Tests
- [x] VMware Workstation deployment successful
- [x] VMware Fusion deployment successful (if macOS available)
- [x] VirtualBox deployment successful
- [x] First boot initialization completes on all platforms

#### Service Tests
- [x] k3d cluster operational
- [x] All Kubernetes pods running
- [x] Service endpoints accessible
- [x] Service validation script passes

#### VLAB Tests
- [x] All 7 switch containers running
- [x] Switch console access functional
- [x] VLAB validation script passes

#### GitOps Tests
- [x] Gitea accessible and functional (if deployed)
- [x] ArgoCD accessible and functional (if deployed)
- [x] GitOps validation script passes (or SKIP if not deployed)

#### Observability Tests
- [x] Grafana accessible with dashboards
- [x] Prometheus collecting metrics
- [x] Loki ingesting logs
- [x] Observability validation script passes

### Failure Escalation

If any test fails:

1. **Document the failure** in test results
2. **Capture evidence** (logs, screenshots, error messages)
3. **Create GitHub issue** with details
4. **Assign to appropriate team member**
5. **Retest after fix**
6. **Update test results**

---

## Test Results Template

### Test Execution Summary

**Test Date:** YYYY-MM-DD
**Tester:** [Name]
**Build Version:** v0.1.0
**Build Artifact:** hedgehog-lab-standard-0.1.0.ova

### Results by Category

| Test Category | Status | Duration | Notes |
|---------------|--------|----------|-------|
| Build Validation | ✅ PASS | 75 min | All artifacts valid |
| VMware Workstation (Windows) | ✅ PASS | 40 min | No issues |
| VMware Workstation (Linux) | ⏭️ SKIP | - | No Linux host available |
| VMware Fusion (macOS) | ✅ PASS | 42 min | No issues |
| VirtualBox (Ubuntu) | ✅ PASS | 38 min | Port forwarding required |
| Service Validation | ✅ PASS | 8 min | All services OK |
| VLAB Validation | ✅ PASS | 12 min | All switches operational |
| GitOps Validation | ⏭️ SKIP | - | Not deployed in v0.1.0 |
| Observability Validation | ✅ PASS | 14 min | Dashboards functional |

### Overall Result

**Status:** ✅ PASS / ❌ FAIL / ⚠️ PARTIAL

**Total Duration:** [Total time]

**Pass Rate:** X/Y tests passed (Z%)

### Issues Found

| Issue # | Severity | Description | Status |
|---------|----------|-------------|--------|
| #XX | Critical | [Description] | Open/Fixed |
| #YY | Minor | [Description] | Fixed |

### Recommendations

- [Any recommendations for improvements]
- [Suggestions for future testing]

### Artifacts

- [ ] Test result JSON files
- [ ] Screenshots
- [ ] Logs (if failures occurred)
- [ ] Screen recordings (optional)

### Sign-off

**Tested by:** [Name]
**Date:** [Date]
**Approved by:** [Project Lead]
**Date:** [Date]

---

**End of Test Plan**

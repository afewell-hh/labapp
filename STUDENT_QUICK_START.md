# Hedgehog Virtual AI Data Center (vAIDC) - Student Quick Start

Get your lab environment running in under 5 minutes!

## Prerequisites

1. **Google Cloud Account** - Sign up at https://cloud.google.com (free tier available)
2. **GCP Project with Billing** - Create a project and enable billing
3. **gcloud CLI** - Install from https://cloud.google.com/sdk/docs/install (or use Cloud Shell)

---

## Quick Start: Use the Scripts (Easiest)

We provide simple scripts to manage your lab environment:

| Script | Purpose |
|--------|---------|
| `deploy-lab.sh` | Create your lab environment |
| `stop-lab.sh` | Pause lab to save costs (data preserved) |
| `start-lab.sh` | Resume a paused lab |
| `cleanup-lab.sh` | Delete everything when you're done |

### Deploy Your Lab

```bash
# Clone the repository
git clone https://github.com/afewell-hh/labapp.git
cd labapp

# Deploy (replace YOUR_PROJECT_ID with your actual GCP project ID)
./deploy-lab.sh YOUR_PROJECT_ID
```

The script will:
1. Set up your GCP project
2. Enable required APIs
3. Create the VM with all required settings
4. Configure firewall rules
5. Display access URLs when complete

### Manage Your Lab

```bash
# Pause your lab (saves ~$1.10/hour, keeps your data)
./stop-lab.sh YOUR_PROJECT_ID

# Resume your lab
./start-lab.sh YOUR_PROJECT_ID

# Delete everything when you're completely done
./cleanup-lab.sh YOUR_PROJECT_ID
```

---

## Alternative: Cloud Shell One-Click Deploy

Click to open Google Cloud Shell:

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/afewell-hh/labapp&cloudshell_open_in_editor=STUDENT_QUICK_START.md)

Then run:
```bash
./deploy-lab.sh YOUR_PROJECT_ID
```

---

## Alternative: Manual Deployment

If you prefer to run commands individually:

### Step 1: Set Your Project

```bash
gcloud config set project YOUR_PROJECT_ID
```

### Step 2: Enable Required APIs

```bash
gcloud services enable compute.googleapis.com
```

### Step 3: Create the VM

```bash
gcloud compute instances create hedgehog-lab \
  --zone=us-west1-c \
  --machine-type=n1-standard-32 \
  --image=hedgehog-vaidc-v20260114 \
  --image-project=teched-473722 \
  --boot-disk-size=300GB \
  --boot-disk-type=pd-balanced \
  --enable-nested-virtualization \
  --min-cpu-platform="Intel Cascade Lake" \
  --tags=http-server,https-server
```

### Step 4: Create Firewall Rules

```bash
gcloud compute firewall-rules create allow-vaidc-services \
  --allow=tcp:80,tcp:443,tcp:3000,tcp:3001,tcp:8080,tcp:9090 \
  --target-tags=http-server,https-server \
  --description="Allow access to Hedgehog vAIDC services"
```

### Step 5: Get Your VM's IP Address

```bash
gcloud compute instances describe hedgehog-lab \
  --zone=us-west1-c \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

---

## Accessing Your Lab Environment

After deployment (allow 5-10 minutes for services to initialize):

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://YOUR_VM_IP:3000 | admin / admin |
| **Gitea** | http://YOUR_VM_IP:3001 | student01 / hedgehog123 |
| **ArgoCD** | http://YOUR_VM_IP:8080 | admin / (see below) |
| **Prometheus** | http://YOUR_VM_IP:9090 | No login required |

### Get ArgoCD Password

```bash
gcloud compute ssh hedgehog-lab --zone=us-west1-c --command="kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d && echo"
```

### SSH to Your VM

```bash
gcloud compute ssh hedgehog-lab --zone=us-west1-c
```

### RDP Access (Desktop)

If you prefer a graphical desktop:
- **Address:** YOUR_VM_IP:3389
- **Username:** ubuntu
- **Password:** HHLab.Admin!

---

## Check Lab Status

Once connected via SSH:

```bash
# Check VLAB status
cd ~/hhfab && hhfab vlab inspect

# View running containers
docker ps

# Check Kubernetes pods
kubectl get pods -A
```

---

## Cost Management

### Estimated Costs

| Resource | Cost |
|----------|------|
| VM running (n1-standard-32) | ~$1.10/hour |
| VM stopped (disk only) | ~$51/month |
| VM deleted | $0 |

### Save Money: Stop When Not Using

```bash
# Stop your lab (you'll only pay for disk storage)
./stop-lab.sh YOUR_PROJECT_ID

# Start again when needed
./start-lab.sh YOUR_PROJECT_ID
```

### Complete Cleanup

When you're completely done with the course:

```bash
./cleanup-lab.sh YOUR_PROJECT_ID
```

This removes:
- The VM instance
- The firewall rules
- All associated costs

---

## Troubleshooting

### VM Won't Start
- Ensure your project has billing enabled
- Check you have sufficient quota for n1-standard-32 machines
- Try a different zone: `./deploy-lab.sh YOUR_PROJECT_ID us-central1-a`

### Can't Access Services
- Wait 5-10 minutes after VM creation for services to start
- Verify firewall rules exist: `gcloud compute firewall-rules list`
- Check VM has an external IP: `gcloud compute instances list`

### SSH Connection Issues
- Ensure you're authenticated: `gcloud auth login`
- Try Cloud Console SSH: Console > Compute Engine > VM instances > SSH button

### Script Permission Denied
```bash
chmod +x deploy-lab.sh stop-lab.sh start-lab.sh cleanup-lab.sh
```

---

## Need Help?

- **Documentation:** https://docs.hedgehog.cloud/vaidc
- **Course Materials:** https://hedgehog.cloud/learn
- **Community:** https://hedgehog.cloud/community

---

**Happy Learning!**

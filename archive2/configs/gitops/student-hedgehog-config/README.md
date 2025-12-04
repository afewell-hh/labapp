# Student Hedgehog Config Repository Seed

This directory contains the initial seed content for the `student/hedgehog-config` GitOps repository in Gitea.

## Purpose

The `student/hedgehog-config` repository serves as the GitOps source of truth for Hedgehog fabric configuration. Students learn to manage VPCs and VPC Attachments by editing YAML files in this repository, which ArgoCD automatically syncs to the Hedgehog controller.

## Repository Structure

```
student/hedgehog-config/
├── README.md                          # Repository introduction and instructions
├── examples/
│   ├── vpc-simple.yaml               # Basic VPC with single subnet
│   ├── vpc-multi-subnet.yaml         # VPC with IPv4 and DHCPv4 subnets
│   └── vpcattachment-example.yaml    # VPC attachment to server connections
└── active/
    └── .gitkeep                       # Placeholder for student work
```

## Workflow

1. **Students explore examples/** - Learn VPC/VPCAttachment syntax and patterns
2. **Students create YAML in active/** - Apply their learning to hands-on exercises
3. **Git commit triggers ArgoCD** - Automated sync to Hedgehog controller
4. **Observe in Grafana** - View fabric changes in real-time dashboards

## Automated Seeding

The `40-gitops-init.sh` script automatically:

1. Creates the `student` organization in Gitea
2. Creates the `hedgehog-config` repository
3. Seeds it with the files from this directory
4. Configures ArgoCD to watch this repository
5. Sets up automated sync with self-heal enabled

## Manual Setup (if needed)

If you need to manually recreate this repository:

```bash
# Create organization
curl -X POST "http://localhost:3001/api/v1/orgs" \
  -H "Content-Type: application/json" \
  -u "gitea_admin:admin123" \
  -d '{"username":"student"}'

# Create repository
curl -X POST "http://localhost:3001/api/v1/orgs/student/repos" \
  -H "Content-Type: application/json" \
  -u "gitea_admin:admin123" \
  -d '{
    "name":"hedgehog-config",
    "description":"Hedgehog Fabric GitOps Configuration",
    "private":false,
    "default_branch":"main"
  }'

# Clone and seed
git clone http://localhost:3001/student/hedgehog-config.git
cd hedgehog-config
cp -r /path/to/this/directory/* .
git add .
git commit -m "Initial seed from curriculum"
git push origin main
```

## ArgoCD Application

The ArgoCD Application manifest that syncs this repository:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hedgehog-fabric
  namespace: argocd
spec:
  project: default
  source:
    repoURL: http://gitea-http.gitea:3000/student/hedgehog-config.git
    targetRevision: main
    path: active
  destination:
    server: https://172.19.0.1:6443  # Hedgehog controller API
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

## Testing

The test harness at `tests/e2e/scripts/validate-gitops.sh` verifies:

- Gitea repository exists and is accessible
- Repository contains expected files
- ArgoCD Application is created and healthy
- Sync status shows successful reconciliation

## References

- [Hedgehog VPC Documentation](https://docs.hedgehog.cloud/latest/)
- [ArgoCD Documentation](https://argo-cd.readthedocs.io/)
- [Course 2 Curriculum](/home/ubuntu/afewell-hh/labapp/reference/learn_content_scratchpad/network-like-hyperscaler/course-2-provisioning/)

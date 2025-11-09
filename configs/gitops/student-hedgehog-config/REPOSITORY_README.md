# Hedgehog Fabric GitOps Configuration

Welcome to your Hedgehog Fabric GitOps repository! This repository is the source of truth for all VPC and network configuration in your Hedgehog lab environment.

## What is This Repository?

This repository uses **GitOps** principles to manage your Hedgehog fabric:

- **Declare** your desired network state in YAML files
- **Commit** changes to Git
- **ArgoCD automatically syncs** your changes to the Hedgehog controller
- **Observe** the fabric reconcile in real-time via Grafana dashboards

## Repository Structure

```
hedgehog-config/
├── README.md           # This file
├── examples/           # Reference examples (DO NOT EDIT)
│   ├── vpc-simple.yaml
│   ├── vpc-multi-subnet.yaml
│   └── vpcattachment-example.yaml
└── active/             # YOUR WORK GOES HERE
    └── your-config.yaml
```

## Getting Started

### 1. Explore Examples

The `examples/` directory contains reference implementations:

- **vpc-simple.yaml** - Basic VPC with a single subnet
- **vpc-multi-subnet.yaml** - VPC with multiple subnets (IPv4 + DHCPv4)
- **vpcattachment-example.yaml** - How to attach VPCs to server connections

### 2. Create Your Configuration

Create YAML files in the `active/` directory:

```bash
# Option 1: Copy an example
cp examples/vpc-simple.yaml active/my-vpc.yaml

# Option 2: Create from scratch
cat > active/my-vpc.yaml <<'EOF'
apiVersion: vpc.githedgehog.com/v1beta1
kind: VPC
metadata:
  name: demo-vpc
  namespace: default
spec:
  ipv4Namespace: default
  vlanNamespace: default
  subnets:
    demo-subnet:
      subnet: 10.99.1.0/24
      gateway: 10.99.1.1
      vlan: 1099
EOF
```

### 3. Commit and Push

```bash
git add active/my-vpc.yaml
git commit -m "Add demo VPC"
git push origin main
```

### 4. Observe Sync

ArgoCD will automatically detect your commit and sync it to the Hedgehog controller within seconds:

- **ArgoCD UI**: http://localhost:8080 (admin / <see docs for password>)
- **Grafana Dashboards**: http://localhost:3000 (admin / admin)
- **kubectl**: `kubectl get vpcs` (if you have kubeconfig access)

## Hedgehog Resource Reference

### VPC (Virtual Private Cloud)

```yaml
apiVersion: vpc.githedgehog.com/v1beta1
kind: VPC
metadata:
  name: my-vpc
  namespace: default
spec:
  ipv4Namespace: default        # IP allocation group
  vlanNamespace: default         # VLAN allocation group
  subnets:
    subnet-name:                 # Subnet identifier
      subnet: 10.0.1.0/24        # CIDR block
      gateway: 10.0.1.1          # Gateway IP (usually .1)
      vlan: 1001                 # VLAN ID (unique per namespace)
      dhcp:                      # Optional: Enable DHCP
        enable: true
        range:
          start: 10.0.1.10       # DHCP range start
          end: 10.0.1.250        # DHCP range end
```

### VPCAttachment

```yaml
apiVersion: vpc.githedgehog.com/v1beta1
kind: VPCAttachment
metadata:
  name: my-attachment
  namespace: default
spec:
  vpc: my-vpc                    # Reference to VPC name
  subnet: subnet-name            # Subnet within the VPC
  connection: server-01--leaf-01 # Server connection (see wiring diagram)
```

## Lab Workflows

### Course 2: VPC Provisioning

1. Create a VPC with IPv4 and DHCPv4 subnets
2. Attach the VPC to server connections
3. Validate connectivity using `kubectl fabric` CLI
4. Decommission and clean up resources

### Course 3: Observability

1. Make configuration changes via Git
2. Watch reconciliation in Grafana Fabric dashboard
3. Monitor BGP peering and interface statistics
4. Query logs for configuration events

### Course 4: Troubleshooting

1. Introduce a misconfiguration (invalid CIDR, conflicting VLAN)
2. Diagnose using ArgoCD sync status and Kubernetes events
3. Roll back using Git revert
4. Validate recovery in Grafana

## Useful Commands

### Check VPC Status

```bash
kubectl get vpcs
kubectl describe vpc my-vpc
```

### Check VPC Attachments

```bash
kubectl get vpcattachments
kubectl describe vpcattachment my-attachment
```

### View Kubernetes Events

```bash
kubectl get events --sort-by='.lastTimestamp'
```

### Force ArgoCD Sync (if auto-sync disabled)

```bash
argocd app sync hedgehog-fabric
```

## Best Practices

1. **One resource per file** - Makes Git history cleaner
2. **Descriptive commit messages** - Helps track changes over time
3. **Test in stages** - Create VPC first, then attachments
4. **Use examples as templates** - Copy and modify rather than write from scratch
5. **Check ArgoCD before debugging** - Sync errors show up there first

## Troubleshooting

### My commit didn't sync

1. Check ArgoCD app status: http://localhost:8080
2. Look for sync errors in the Application details
3. Verify YAML syntax: `kubectl apply --dry-run=client -f active/my-file.yaml`

### VPC shows "Reconciling" state

This is normal! The controller is configuring the fabric. Check:

- Grafana Fabric dashboard for BGP convergence
- `kubectl describe vpc <name>` for progress events
- Typically takes 30-60 seconds for full reconciliation

### VLAN conflict error

- VLANs must be unique within a `vlanNamespace`
- Check existing VPCs: `kubectl get vpcs -o yaml | grep vlan:`
- Choose a different VLAN ID (e.g., 1000-2000 range)

## Learn More

- [Hedgehog Documentation](https://docs.hedgehog.cloud/latest/)
- [kubectl-fabric CLI Guide](https://docs.hedgehog.cloud/latest/user-guide/kubectl-plugin/)
- [VPC CRD Reference](/home/ubuntu/afewell-hh/labapp/reference/learn_content_scratchpad/network-like-hyperscaler/research/CRD_REFERENCE.md)
- [Course Materials](/home/ubuntu/afewell-hh/labapp/reference/learn_content_scratchpad/network-like-hyperscaler/)

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review ArgoCD and Grafana for clues
3. Consult the course materials and documentation
4. Ask your instructor or lab administrator

Happy GitOps-ing! 🚀

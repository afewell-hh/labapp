# Test variables file for Terraform module verification
# Usage: terraform plan -var-file=marketplace_test.tfvars

project_id              = "teched-473722"
zone                    = "us-west1-c"
machine_type            = "n1-standard-32"
network                 = "default"
subnetwork              = ""
boot_disk_size_gb       = 300
boot_disk_type          = "pd-balanced"
source_image            = "projects/teched-473722/global/images/hedgehog-vaidc-v20260114"
firewall_source_ranges  = ["0.0.0.0/0"]
goog_cm_deployment_name = "test-vaidc"

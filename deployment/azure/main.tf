locals {
  tags = { project = "deterministic-hr-v1", deployment_id = var.deployment_id, experiment_id = var.experiment_id }
  infrastructure = {
    schema_version         = 1
    deployment_id          = var.deployment_id
    run_id                 = var.run_id
    experiment_id          = var.experiment_id
    experiment_version     = 1
    data_volume_id         = azurerm_managed_disk.data.id
    data_device            = "/dev/disk/azure/scsi1/lun0"
    format_blank_data_disk = var.format_blank_data_disk
    admin_source_cidr      = var.admin_source_cidr
    # Bootstrap stays private. The NSG kill switch must not change immutable
    # custom_data and thereby replace the VM when ingress is disabled.
    enable_public_honeypot = false
  }
}
resource "azurerm_resource_group" "honeypot" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.tags
}

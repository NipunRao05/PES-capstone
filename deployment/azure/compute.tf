resource "azurerm_linux_virtual_machine" "honeypot" {
  name                            = "${var.name_prefix}-vm"
  location                        = azurerm_resource_group.honeypot.location
  resource_group_name             = azurerm_resource_group.honeypot.name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.honeypot.id]
  admin_ssh_key {
    username   = var.admin_username
    public_key = trimspace(var.ssh_public_key)
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = var.image_version
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = var.disk_storage_type
    disk_size_gb         = var.os_disk_size_gb
  }
  # No identity block, password, provisioner, remote-exec or application secret.
  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
    infrastructure = jsonencode(local.infrastructure)
    bootstrap      = file("${path.module}/bootstrap.sh")
    disk_prepare   = file("${path.module}/prepare_disk.py")
    firewall       = file("${path.module}/host_firewall.py")
  }))
  tags       = local.tags
  depends_on = [azurerm_network_interface_security_group_association.honeypot]
  lifecycle {
    precondition {
      condition     = var.vm_memory_mb >= 18176 && var.vm_vcpus >= 4
      error_message = "Reviewed SKU declaration requires >=18176MiB and >=4vCPUs. Verify actual regional SKU/quota separately; host guard checks real memory."
    }
  }
}

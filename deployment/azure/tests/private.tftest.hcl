mock_provider "azurerm" {}

variables {
  subscription_id     = "11111111-1111-1111-1111-111111111111"
  tenant_id           = "22222222-2222-2222-2222-222222222222"
  resource_group_name = "test-private-rg"
  location            = "eastus"
  name_prefix         = "test-private"
  public_ip_name      = "test-private-ip"
  vm_size             = "Standard_E4as_v5"
  vm_memory_mb        = 32768
  vm_vcpus            = 4
  admin_username      = "testadmin"
  admin_source_cidr   = "203.0.113.10/32"
  ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKbM7WhcNW1lLVHjWYH39U3zR8r5lXfvJaPzRgCgXYzL fixture"
  image_version       = "24.04.202610010"
  deployment_id       = "test-deployment"
  run_id              = "test-run"
}

run "default_private" {
  command = plan
  assert {
    condition     = var.enable_public_honeypot == false && length(azurerm_network_security_group.honeypot.security_rule) == 2
    error_message = "Only SSH plus explicit deny should exist in default private mode."
  }
  assert {
    condition     = alltrue([for rule in azurerm_network_security_group.honeypot.security_rule : rule.access != "Allow" || (rule.destination_port_range == "22" && rule.source_address_prefix == var.admin_source_cidr)])
    error_message = "Unexpected public management/database ingress."
  }
  assert {
    condition     = azurerm_linux_virtual_machine.honeypot.disable_password_authentication && length(azurerm_linux_virtual_machine.honeypot.identity) == 0
    error_message = "Password auth or managed identity unexpectedly enabled."
  }
  assert {
    condition     = azurerm_public_ip.honeypot.allocation_method == "Static" && azurerm_public_ip.honeypot.sku == "Standard" && azurerm_virtual_machine_data_disk_attachment.data.lun == 0
    error_message = "Static IP or separate LUN0 disk contract changed."
  }
}
run "reject_16_gib" {
  command = plan
  variables { vm_memory_mb = 16384 }
  expect_failures = [azurerm_linux_virtual_machine.honeypot]
}
run "reject_public_ssh" {
  command = plan
  variables { admin_source_cidr = "0.0.0.0/0" }
  expect_failures = [var.admin_source_cidr]
}
run "reject_floating_image" {
  command = plan
  variables { image_version = "latest" }
  expect_failures = [var.image_version]
}

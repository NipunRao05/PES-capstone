output "public_ip" { value = azurerm_public_ip.honeypot.ip_address }
output "ssh_command" { value = "ssh ${var.admin_username}@${azurerm_public_ip.honeypot.ip_address}" }
output "grafana_tunnel" { value = "ssh -N -L 3000:127.0.0.1:3000 ${var.admin_username}@${azurerm_public_ip.honeypot.ip_address}" }
output "data_disk_id" { value = azurerm_managed_disk.data.id }
output "vm_id" { value = azurerm_linux_virtual_machine.honeypot.id }
output "deployment_identity" { value = { deployment_id = var.deployment_id, run_id = var.run_id, experiment_id = var.experiment_id, experiment_version = 1 } }
output "public_database_ingress_enabled" { value = var.enable_public_honeypot }
output "budget_status" { value = length(var.budget_contact_emails) > 0 ? "API budget requested; verify alerts" : "Manual budget review REQUIRED; no API budget created" }

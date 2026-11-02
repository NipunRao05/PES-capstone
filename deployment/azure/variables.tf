variable "subscription_id" {
  type = string
}
variable "tenant_id" {
  type = string
}
variable "resource_group_name" {
  type = string
}
variable "location" {
  type = string
}
variable "name_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name_prefix))
    error_message = "Use a short lowercase Azure resource prefix."
  }
}
variable "vm_size" {
  type        = string
  description = "Choose a subscription-available x86_64 SCSI SKU with >=18176MiB and >=4vCPUs; E4as_v5 is the reviewed candidate. No implicit SKU."
}
variable "vm_memory_mb" {
  type        = number
  description = "Actual advertised SKU memory from az vm list-skus; declaration only, verified again on real host."
}
variable "vm_vcpus" {
  type        = number
  description = "Actual advertised SKU vCPUs; verify Student family quota separately."
}
variable "admin_username" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9_-]{2,30}$", var.admin_username)) && !contains(["root", "admin"], var.admin_username)
    error_message = "Use a non-root Linux administrator username."
  }
}
variable "admin_source_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.admin_source_cidr)) && try(tonumber(split("/", var.admin_source_cidr)[1]) >= 24, false)
    error_message = "One explicit IPv4 administrator CIDR /24 through /32 is required; never /0."
  }
}
variable "ssh_public_key" {
  type        = string
  description = "OpenSSH public key only; never a private key."
  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+", trimspace(var.ssh_public_key))) && !strcontains(var.ssh_public_key, "PRIVATE")
    error_message = "Supply an OpenSSH public key."
  }
}
variable "public_ip_name" {
  type = string
}
variable "vnet_cidr" {
  type    = string
  default = "10.42.0.0/16"
}
variable "subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}
variable "enable_public_honeypot" {
  type        = bool
  default     = false
  description = "NSG ingress only. Does not alter loopback Compose publications or host firewall. Requires a separately authorized public-release change."
}
variable "image_version" {
  type        = string
  description = "Exact Canonical Ubuntu24.04 image version verified in the chosen region; latest is prohibited."
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.image_version))
    error_message = "Resolve and record a concrete marketplace image version, not latest."
  }
}
variable "os_disk_size_gb" {
  type    = number
  default = 64
}
variable "data_disk_size_gb" {
  type    = number
  default = 128
  validation {
    condition     = var.data_disk_size_gb >= 128
    error_message = "Reserve at least128GiB for Docker/images, retained data, COW, logs and export headroom."
  }
}
variable "disk_storage_type" {
  type    = string
  default = "StandardSSD_LRS"
}
variable "format_blank_data_disk" {
  type        = bool
  default     = false
  description = "Explicit permission to initialize only a verified blank LUN0 disk. Existing filesystems are never formatted."
}
variable "deployment_id" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,128}$", var.deployment_id))
    error_message = "Use the existing runtime deployment identity alphabet."
  }
}
variable "run_id" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,128}$", var.run_id))
    error_message = "Use the existing runtime run identity alphabet."
  }
}
variable "experiment_id" {
  type    = string
  default = "deterministic_baseline"
  validation {
    condition     = var.experiment_id == "deterministic_baseline"
    error_message = "Only the existing deterministic_baseline experiment is implemented."
  }
}
variable "budget_usd" {
  type    = number
  default = 50
}
variable "budget_thresholds" {
  type    = list(number)
  default = [50, 75, 90]
}
variable "budget_contact_emails" {
  type        = list(string)
  default     = []
  description = "Optional nonsecret notification addresses; reviewed budget is still mandatory without API budget creation."
}
variable "budget_start_date" {
  type        = string
  default     = null
  description = "First day of current month in UTC RFC3339, required only for optional budget."
}
variable "budget_end_date" {
  type    = string
  default = null
}

resource "azurerm_network_security_group" "honeypot" {
  name                = "${var.name_prefix}-nsg"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  security_rule {
    name                       = "AdminSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.admin_source_cidr
    destination_address_prefix = "*"
  }
  dynamic "security_rule" {
    for_each = var.enable_public_honeypot ? { PostgreSQL = { port = "5432", priority = 200 }, MySQL = { port = "3306", priority = 210 } } : {}
    content {
      name                       = security_rule.key
      priority                   = security_rule.value.priority
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = security_rule.value.port
      source_address_prefix      = "Internet"
      destination_address_prefix = "*"
    }
  }
  # Override Azure's default AllowVNetInBound/AllowAzureLoadBalancerInBound too.
  security_rule {
    name                       = "DenyAllOtherInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  tags = local.tags
}
resource "azurerm_consumption_budget_resource_group" "optional" {
  count             = length(var.budget_contact_emails) > 0 ? 1 : 0
  name              = "${var.name_prefix}-budget"
  resource_group_id = azurerm_resource_group.honeypot.id
  amount            = var.budget_usd
  time_grain        = "Monthly"
  time_period {
    start_date = var.budget_start_date
    end_date   = var.budget_end_date
  }
  dynamic "notification" {
    for_each = toset(var.budget_thresholds)
    content {
      enabled        = true
      threshold      = notification.value
      operator       = "GreaterThanOrEqualTo"
      contact_emails = var.budget_contact_emails
    }
  }
  lifecycle {
    precondition {
      condition     = var.budget_start_date != null && var.budget_end_date != null
      error_message = "Optional budget requires reviewed start/end dates; alerts never stop billing."
    }
  }
}

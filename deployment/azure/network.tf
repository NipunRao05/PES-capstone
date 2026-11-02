resource "azurerm_virtual_network" "honeypot" {
  name                = "${var.name_prefix}-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  tags                = local.tags
}
resource "azurerm_subnet" "honeypot" {
  name                 = "${var.name_prefix}-subnet"
  resource_group_name  = azurerm_resource_group.honeypot.name
  virtual_network_name = azurerm_virtual_network.honeypot.name
  address_prefixes     = [var.subnet_cidr]
}
resource "azurerm_public_ip" "honeypot" {
  name                = var.public_ip_name
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  allocation_method   = "Static"
  sku                 = "Standard"
  ip_version          = "IPv4"
  tags                = local.tags
}
resource "azurerm_network_interface" "honeypot" {
  name                = "${var.name_prefix}-nic"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.honeypot.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.honeypot.id
  }
  tags = local.tags
}
resource "azurerm_network_interface_security_group_association" "honeypot" {
  network_interface_id      = azurerm_network_interface.honeypot.id
  network_security_group_id = azurerm_network_security_group.honeypot.id
}

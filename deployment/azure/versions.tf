terraform {
  required_version = ">= 1.14.0, < 1.15.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.64.0"
    }
  }
  # Deliberately local backend. Protect state and its backups outside Git.
  backend "local" {}
}

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 5.10"
    }
  }

  # État chiffré (OpenTofu), une copie par environnement (espace de travail : banc, uat, prod).
  encryption {
    key_provider "pbkdf2" "etat" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "etat" {
      keys = key_provider.pbkdf2.etat
    }
    state {
      method   = method.aes_gcm.etat
      enforced = true
    }
    plan {
      method   = method.aes_gcm.etat
      enforced = true
    }
  }
}

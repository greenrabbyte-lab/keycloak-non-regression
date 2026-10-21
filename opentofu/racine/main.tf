# Configuration de Keycloak en code, un espace de travail OpenTofu par environnement :
#   tofu workspace select banc && tofu apply -var-file=banc.tfvars    (Keycloak éphémère du banc)
#   tofu workspace select uat  && tofu apply -var-file=uat.tfvars
#   tofu workspace select prod && tofu apply -var-file=prod.tfvars
# Le banc applique exactement la configuration promise à l'UAT puis à la production.

provider "keycloak" {
  url           = var.keycloak_url
  realm         = "master"
  client_id     = var.keycloak_client_id
  client_secret = var.keycloak_client_secret
  username      = var.keycloak_utilisateur
  password      = var.keycloak_mot_de_passe
}

module "realm" {
  source = "../modules/realm"

  realm                = var.realm
  nom_affiche          = var.nom_affiche
  ssl_requis           = var.ssl_requis
  roles                = var.roles
  groupes              = var.groupes
  applications         = var.applications
  entra                = var.entra
  entra_client_secret  = var.entra_client_secret
  utilisateurs_de_test = var.utilisateurs_de_test
}

check "pas_de_comptes_de_test_hors_banc" {
  assert {
    condition     = terraform.workspace == "banc" || length(var.utilisateurs_de_test) == 0
    error_message = "Des comptes de test sont déclarés hors de l'espace de travail « banc »."
  }
}

output "realm" {
  value = module.realm.realm
}

variable "state_passphrase" {
  description = "Phrase secrète de chiffrement de l'état (TF_VAR_state_passphrase)."
  type        = string
  sensitive   = true
}

variable "keycloak_url" {
  description = "Adresse de Keycloak (administration)."
  type        = string
}

variable "keycloak_client_id" {
  description = "Client d'administration : compte de service dédié (UAT, production) ou admin-cli (banc)."
  type        = string
  default     = "admin-cli"
}

variable "keycloak_client_secret" {
  description = "Secret du compte de service (TF_VAR_keycloak_client_secret), jamais dans un fichier."
  type        = string
  default     = null
  sensitive   = true
}

variable "keycloak_utilisateur" {
  description = "Banc uniquement : compte d'administration temporaire."
  type        = string
  default     = null
}

variable "keycloak_mot_de_passe" {
  description = "Banc uniquement (TF_VAR_keycloak_mot_de_passe)."
  type        = string
  default     = null
  sensitive   = true
}

variable "realm" {
  type = string
}

variable "nom_affiche" {
  type = string
}

variable "ssl_requis" {
  type    = string
  default = "all"
}

variable "roles" {
  type = map(string)
}

variable "groupes" {
  type    = map(list(string))
  default = {}
}

variable "applications" {
  type = map(object({
    nom                 = string
    redirections        = list(string)
    retours_deconnexion = optional(list(string), [])
    origines_web        = optional(list(string), ["+"])
    session_state       = optional(bool, false)
    secret              = optional(string)
  }))
}

variable "entra" {
  type = object({
    tenant_id = string
    client_id = string
    roles     = map(string)
  })
  default = null
}

variable "entra_client_secret" {
  description = "TF_VAR_entra_client_secret, jamais dans un fichier."
  type        = string
  default     = null
  sensitive   = true
}

variable "utilisateurs_de_test" {
  type = map(object({
    mot_de_passe = string
    roles        = list(string)
  }))
  default   = {}
  sensitive = true
}

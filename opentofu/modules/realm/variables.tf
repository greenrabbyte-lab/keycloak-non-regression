variable "realm" {
  description = "Nom du realm."
  type        = string
}

variable "nom_affiche" {
  description = "Nom affiché sur la page de connexion."
  type        = string
}

variable "ssl_requis" {
  description = "« external » (HTTPS sauf réseau privé) ou « all » (HTTPS partout, recommandé en UAT et en production)."
  type        = string
  default     = "all"

  validation {
    condition     = contains(["external", "all"], var.ssl_requis)
    error_message = "ssl_requis : « external » ou « all » (jamais « none »)."
  }
}

variable "politique_mots_de_passe" {
  description = "Politique des mots de passe locaux (comptes de secours ; les autres viennent d'Entra)."
  type        = string
  default     = "length(12) and notUsername and notEmail"
}

variable "duree_jeton_acces" {
  description = "Durée de vie des jetons d'accès."
  type        = string
  default     = "5m"
}

variable "roles" {
  description = "Rôles du realm : nom => description."
  type        = map(string)
}

variable "groupes" {
  description = "Groupes du realm : nom => rôles accordés."
  type        = map(list(string))
  default     = {}
}

variable "applications" {
  description = <<-EOT
    Clients OIDC confidentiels, flux standard + PKCE S256 uniquement (ni flux implicite, ni mot de
    passe direct). session_state : ajoute la revendication session_state, retirée des jetons par
    Keycloak 25, pour une application qui en dépend (exigence de son contrat).
  EOT
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
  description = <<-EOT
    Fédération avec Microsoft Entra ID (null : désactivée). Les rôles d'application d'Entra
    (revendication « roles ») sont traduits en rôles Keycloak à chaque connexion : Entra (et
    l'outil d'IAM en amont) décide qui a quoi, Keycloak ne fait que traduire.
  EOT
  type = object({
    tenant_id = string
    client_id = string
    roles     = map(string) # rôle d'application Entra => rôle Keycloak
  })
  default = null
}

variable "entra_client_secret" {
  description = "Secret de l'application Keycloak déclarée dans Entra (préférer un certificat : voir docs/strategie.md)."
  type        = string
  default     = null
  sensitive   = true
}

variable "utilisateurs_de_test" {
  description = "Comptes locaux pour le banc de non-régression uniquement (jamais en UAT ni en production)."
  type = map(object({
    mot_de_passe = string
    roles        = list(string)
  }))
  default   = {}
  sensitive = true
}

variable "passkeys" {
  description = "Connexion par passkey (WebAuthn, sans mot de passe) proposée sur la page de connexion."
  type        = bool
  default     = true
}

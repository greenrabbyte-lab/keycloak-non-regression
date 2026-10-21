# Configuration d'un realm Keycloak (26.7 et suivants) décrite en code : réglages de sécurité, rôles,
# groupes, applications, fédération avec Entra ID. Le même module est appliqué au banc de
# non-régression, en UAT puis en production : ce qui est testé est ce qui est déployé.

resource "keycloak_realm" "realm" {
  realm        = var.realm
  enabled      = true
  display_name = var.nom_affiche

  ssl_required             = var.ssl_requis
  registration_allowed     = false
  reset_password_allowed   = false
  remember_me              = false
  login_with_email_allowed = false
  duplicate_emails_allowed = false
  password_policy          = var.politique_mots_de_passe

  access_token_lifespan    = var.duree_jeton_acces
  sso_session_idle_timeout = "30m"
  sso_session_max_lifespan = "10h"
  revoke_refresh_token     = true
  refresh_token_max_reuse  = 0

  security_defenses {
    headers {
      x_frame_options                     = "SAMEORIGIN"
      content_security_policy             = "frame-src 'self'; frame-ancestors 'self'; object-src 'none';"
      content_security_policy_report_only = ""
      x_content_type_options              = "nosniff"
      x_robots_tag                        = "none"
      strict_transport_security           = "max-age=31536000; includeSubDomains"
      referrer_policy                     = "no-referrer"
    }
    brute_force_detection {
      permanent_lockout                = false
      max_login_failures               = 5
      wait_increment_seconds           = 60
      quick_login_check_milli_seconds  = 1000
      minimum_quick_login_wait_seconds = 60
      max_failure_wait_seconds         = 900
      failure_reset_time_seconds       = 43200
    }
  }

  # Passkeys : vérification de l'utilisateur et clé découvrable exigées (Keycloak 26.7 et suivants).
  web_authn_passwordless_policy {
    user_verification_requirement = "required"
    discoverable_credential       = "required"
    passwordless_passkeys_enabled = var.passkeys
    relying_party_entity_name     = var.nom_affiche
  }
}

resource "keycloak_realm_events" "evenements" {
  realm_id                     = keycloak_realm.realm.id
  events_enabled               = true
  events_expiration            = 2592000 # 30 jours
  admin_events_enabled         = true
  admin_events_details_enabled = false
  events_listeners             = ["jboss-logging"]
}

resource "keycloak_role" "roles" {
  for_each    = var.roles
  realm_id    = keycloak_realm.realm.id
  name        = each.key
  description = each.value
}

resource "keycloak_group" "groupes" {
  for_each = var.groupes
  realm_id = keycloak_realm.realm.id
  name     = each.key
}

resource "keycloak_group_roles" "groupes" {
  for_each = var.groupes
  realm_id = keycloak_realm.realm.id
  group_id = keycloak_group.groupes[each.key].id
  role_ids = [for r in each.value : keycloak_role.roles[r].id]
}

resource "keycloak_openid_client" "applications" {
  for_each  = var.applications
  realm_id  = keycloak_realm.realm.id
  client_id = each.key
  name      = each.value.nom
  enabled   = true

  access_type                  = "CONFIDENTIAL"
  client_secret                = each.value.secret
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  pkce_code_challenge_method   = "S256"
  frontchannel_logout_enabled  = true

  valid_redirect_uris             = each.value.redirections
  valid_post_logout_redirect_uris = each.value.retours_deconnexion
  web_origins                     = each.value.origines_web
}

# Revendication session_state (retirée des jetons par Keycloak 25) pour les applications qui
# en dépendent : exigence de leur contrat, vérifiée par le banc à chaque montée de version.
resource "keycloak_generic_protocol_mapper" "session_state" {
  for_each        = { for k, v in var.applications : k => v if v.session_state }
  realm_id        = keycloak_realm.realm.id
  client_id       = keycloak_openid_client.applications[each.key].id
  name            = "session_state"
  protocol        = "openid-connect"
  protocol_mapper = "oidc-session-state-mapper"
  config = {
    "access.token.claim"        = "true"
    "id.token.claim"            = "true"
    "introspection.token.claim" = "true"
  }
}

resource "keycloak_oidc_identity_provider" "entra" {
  count        = var.entra == null ? 0 : 1
  realm        = keycloak_realm.realm.id
  alias        = "entra"
  display_name = "Microsoft Entra ID"
  enabled      = true

  authorization_url  = "https://login.microsoftonline.com/${var.entra.tenant_id}/oauth2/v2.0/authorize"
  token_url          = "https://login.microsoftonline.com/${var.entra.tenant_id}/oauth2/v2.0/token"
  jwks_url           = "https://login.microsoftonline.com/${var.entra.tenant_id}/discovery/v2.0/keys"
  issuer             = "https://login.microsoftonline.com/${var.entra.tenant_id}/v2.0"
  logout_url         = "https://login.microsoftonline.com/${var.entra.tenant_id}/oauth2/v2.0/logout"
  client_id          = var.entra.client_id
  client_secret      = var.entra_client_secret
  default_scopes     = "openid profile email"
  validate_signature = true
  sync_mode          = "FORCE"
  trust_email        = true
  store_token        = false
  extra_config = {
    "pkceEnabled" = "true"
    "pkceMethod"  = "S256"
  }
}

# Rôle d'application Entra (revendication « roles ») => rôle Keycloak, réévalué à chaque connexion.
resource "keycloak_custom_identity_provider_mapper" "entra_roles" {
  for_each                 = var.entra == null ? {} : var.entra.roles
  realm                    = keycloak_realm.realm.id
  name                     = "entra-${each.key}"
  identity_provider_alias  = keycloak_oidc_identity_provider.entra[0].alias
  identity_provider_mapper = "oidc-role-idp-mapper"
  extra_config = {
    syncMode      = "FORCE"
    claim         = "roles"
    "claim.value" = each.key
    role          = each.value
  }
}

resource "keycloak_user" "test" {
  for_each       = nonsensitive(toset(keys(var.utilisateurs_de_test)))
  realm_id       = keycloak_realm.realm.id
  username       = each.key
  enabled        = true
  email          = "${each.key}@banc.invalid"
  email_verified = true
  first_name     = title(each.key)
  last_name      = "Banc"
  initial_password {
    value     = var.utilisateurs_de_test[each.key].mot_de_passe
    temporary = false
  }
}

resource "keycloak_user_roles" "test" {
  for_each = nonsensitive(toset(keys(var.utilisateurs_de_test)))
  realm_id = keycloak_realm.realm.id
  user_id  = keycloak_user.test[each.key].id
  role_ids = [for r in var.utilisateurs_de_test[each.key].roles : keycloak_role.roles[r].id]
}

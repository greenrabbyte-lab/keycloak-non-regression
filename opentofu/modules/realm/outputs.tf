output "realm" {
  description = "Nom du realm."
  value       = keycloak_realm.realm.realm
}

output "applications" {
  description = "Identifiants internes des clients (pour d'autres modules)."
  value       = { for k, c in keycloak_openid_client.applications : k => c.id }
}

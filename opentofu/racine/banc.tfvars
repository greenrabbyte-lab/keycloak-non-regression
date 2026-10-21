# Environnement « banc » : Keycloak éphémère du banc de non-régression (keycloak/banc).
# Valeurs de test uniquement, alignées sur banc.py ; rien de secret.
keycloak_url = "http://localhost:8080"
realm        = "banc"
nom_affiche  = "Banc de non-régression"
ssl_requis   = "external" # le banc tourne en HTTP sur localhost

roles = {
  proprietaire = "Tout, dont l'administration de l'application"
  foyer        = "Consultation, inventaire et étiquettes"
}

applications = {
  "application-banc" = {
    nom                 = "Application de test (banc)"
    redirections        = ["http://localhost:8765/rappel"]
    retours_deconnexion = ["http://localhost:8765/au-revoir"]
    secret              = "banc-uniquement-pas-un-secret"
  }
}

utilisateurs_de_test = {
  alice   = { mot_de_passe = "banc-alice-Mot2Passe", roles = ["proprietaire"] }
  bob     = { mot_de_passe = "banc-bob-Mot2Passe", roles = ["foyer"] }
  victime = { mot_de_passe = "banc-victime-Mot2Passe", roles = ["foyer"] }
}

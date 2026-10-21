# Sécurité

## Signaler une faille

Une faille du kit (workflows, scripts, image, configuration OpenTofu) se signale **en privé**,
par le signalement privé de GitHub : onglet « Security », « Report a vulnerability ». Jamais
dans un ticket ou une pull request publics. Réponse visée sous 7 jours.

Une faille de Keycloak lui-même se signale au projet Keycloak :
https://github.com/keycloak/keycloak/security/policy

## Ce que contient le dépôt

- Aucun secret. Les mots de passe et le secret de client de `realm-banc.json` et de
  `opentofu/racine/banc.tfvars` sont des valeurs de **test**, publiques par construction : ils
  ne servent qu'au banc, sur un Keycloak éphémère lié à `localhost`. Ne jamais les réutiliser.
- Les identifiants réels (administration de Keycloak, secret Entra ID, phrase de chiffrement de
  l'état OpenTofu) passent par des variables d'environnement ou des secrets du dépôt, jamais
  par Git.

## Chaîne d'approvisionnement

- Actions GitHub figées par empreinte de commit ; outils (Trivy, Ruff, ShellCheck, hadolint,
  actionlint, OpenTofu) figés par version et empreinte (`.github/outils.env`) ; image de base de
  Keycloak et image de Renovate figées par empreinte.
- Nouvelle version d'un outil adoptée 14 jours après sa publication.
- Le banc ne tourne pas sur le code d'un fork : seulement sur les branches du dépôt.
- Le workflow ne publie que depuis `main`, et publie l'image testée (pas une reconstruction).

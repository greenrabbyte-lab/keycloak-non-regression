# Montée de version Keycloak : Keycloak 24.0.5 (base d'origine) → Keycloak 26.8.1 (base PostgreSQL migrée depuis 24.0.5)

**Verdict : ✖ BLOQUÉE** — 0 régression(s), 1 amélioration(s), 17 comportement(s) modifié(s), 1 exigence(s) d'application non satisfaite(s).

**Fusion automatique : non** (verdict BLOQUÉE, failles non analysées) : correction obligatoire avant toute fusion.

Banc passé le 2026-10-21T05:31:32Z (référence) et le 2026-10-21T05:32:25Z (candidate).

## Tests

| Catégorie | Référence | Candidate |
|---|---|---|
| fonctionnel | 6/6 | 6/6 |
| securite | 11/12 | 12/12 |
| exploitation | 5/5 | 5/5 |
| performance | 1/1 | 1/1 |

### Améliorations (en échec → réussi)

- ✔ **Santé et métriques absentes du port public (exposées seulement sur le port de gestion)** (`securite.sante_hors_port_public`) : exposées sur le port public : santé 200, métriques 200

## Contrats des applications

| Application | Exigence | Référence | Candidate | Pourquoi | Remède |
|---|---|---|---|---|---|
| Application d'un fournisseur (exemple) | `jeton.acces.forme` : `session_state` | ✔ | ✖ rompue | l'application suit la session Keycloak avec la revendication session_state | mapper de protocole « oidc-session-state-mapper » sur le client (Keycloak 25 et suivants) |
| Application d'un fournisseur (exemple) | `jeton.acces.forme` : `realm_access` | ✔ | ✔ | les droits sont lus dans realm_access.roles |  |
| Application d'un fournisseur (exemple) | `oidc.decouverte.cles` : `end_session_endpoint` | ✔ | ✔ | déconnexion depuis l'application |  |
| Application d'un fournisseur (exemple) | `page_connexion.champs` : `username` | ✔ | ✔ | les tests automatisés du fournisseur remplissent ce champ |  |

## Comportements modifiés

### Sécurité

- `securite.en_tetes` 🔒 à valider par la sécurité
  - − `x-xss-protection` (était « 1; mode=block »)
- `securite.force_brute` 🔒 à valider par la sécurité
  - + `numSecondaryAuthFailures` = « nombre »
- `securite.port_public` 🔒 à valider par la sécurité
  - ~ `/health/ready` : 200 → 404
  - ~ `/metrics` : 200 → 404

### Jetons

- `jeton.acces.forme`
  - − `nonce` (était « texte »)
  - − `session_state` (était « texte »)
- `jeton.identite.forme`
  - − `session_state` (était « texte »)
- `jeton.valeurs` 🔒 à valider par la sécurité
  - ~ `expires_in` : 299 → 300

### OIDC (découverte, clés)

- `oidc.decouverte.cles`
  - + "dpop_signing_alg_values_supported"
  - + "prompt_values_supported"
- `oidc.decouverte.valeurs`
  - ~ `authorization_encryption_alg_values_supported` : ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"] → ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP", "RSA-OAEP-2…
  - ~ `claims_supported` : ["acr", "aud", "auth_time", "email", "family_name", "given_name", "iss", "name", "preferr… → ["acr", "aud", "auth_time", "azp", "email", "exp", "family_name", "given_name", "iat", "i…
  - + `dpop_signing_alg_values_supported` = ["ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"]
  - ~ `grant_types_supported` : ["authorization_code", "client_credentials", "implicit", "password", "refresh_token", "ur… → ["authorization_code", "client_credentials", "implicit", "password", "refresh_token", "ur…
  - ~ `id_token_encryption_alg_values_supported` : ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"] → ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP", "RSA-OAEP-2…
  - + `prompt_values_supported` = ["consent", "login", "none"]
  - ~ `request_object_encryption_alg_values_supported` : ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"] → ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP", "RSA-OAEP-2…
  - ~ `scopes_supported` : ["acr", "address", "email", "microprofile-jwt", "offline_access", "openid", "phone", "pro… → ["acr", "address", "basic", "email", "microprofile-jwt", "offline_access", "openid", "pho…
  - ~ `userinfo_encryption_alg_values_supported` : ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"] → ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP", "RSA-OAEP-2…

### Client applicatif

- `client.attributs` 🔒 à valider par la sécurité
  - + `realm_client` = « false »

### Realm (réglages, flux, actions requises)

- `realm.actions_requises`
  - + "idp_link (active)"
- `realm.portees`
  - + "AuthnContextClassRef"
  - + "basic"
  - + "service_account"
- `realm.reglages` 🔒 à valider par la sécurité
  - + `adminPermissionsEnabled` = false
  - + `bruteForceStrategy` = « MULTIPLE »
  - + `maxSecondaryAuthFailures` = 0
  - + `organizationsEnabled` = false
  - + `scimApiEnabled` = false
  - + `verifiableCredentialsEnabled` = false
  - + `webAuthnPolicyPasswordlessResidentKey` = « required »
  - + `webAuthnPolicyResidentKey` = « not specified »

### Serveur (version, fonctions)

- `serveur.fonctions_apercu`
  - + "CLIENT_ADMIN_API_V2"
  - + "HTTP_OPTIMIZED_SERIALIZERS"
  - + "OID4VC_VCI"
  - + "OPENTELEMETRY_LOGS"
  - + "PARAMETERIZED_SCOPES"
  - + "SPIFFE"
  - + "TOKEN_EXCHANGE_DELEGATION"
  - − "ADMIN_FINE_GRAINED_AUTHZ"
  - − "CLIENT_SECRET_ROTATION"
  - − "DPOP"
  - − "RECOVERY_CODES"
  - − "UPDATE_EMAIL"
- `serveur.fonctions_desactivees`
  - + "AUTHZEN"
  - + "CIMD"
  - + "CLIENT_ADMIN_API_V2"
  - + "CLIENT_AUTH_ABCA"
  - + "CLUSTERLESS"
  - + "DB_TIDB"
  - + "HTTP_CLIENT_V2"
  - + "HTTP_OPTIMIZED_SERIALIZERS"
  - + "IDENTITY_ASSERTION_JWT"
  - + "IDENTITY_BROKERING_API_V2"
  - + "INSTAGRAM_BROKER"
  - + "IPA_TUURA_FEDERATION"
  - + "LDAP_METRICS"
  - + "LOGIN_FAILURES_V1"
  - + "LOGIN_V1"
  - … et 26 autre(s)
- `serveur.version`
  - ~ « 24.0.5 » → « 26.8.1 »

### Exploitation

- `exploitation.sante`
  - ~ `adresse` : « port public » → « port de gestion »

### Page de connexion

- `page_connexion.champs`
  - − "login"

## Performance

| Mesure | Référence | Candidate | Écart |
|---|---|---|---|
| Démarrage (s) | 14.1 | 17.4 | +23 % |
| Première connexion (s) | 1.119 | 1.69 | +51 % ▲ |
| Connexion, médiane de 5 (s) | 0.342 | 0.118 | -65 % |

## À lire avant de fusionner

- Guide de migration : https://www.keycloak.org/docs/latest/upgrading/
- Notes de version : https://www.keycloak.org/docs/latest/release_notes/
- Les lignes marquées 🔒 touchent la sécurité : décision explicite avant de fusionner.

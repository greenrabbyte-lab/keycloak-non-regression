# Montée de version Keycloak : Keycloak 26.7.5 (distribution officielle) → Keycloak 26.8.1 (distribution officielle)

**Verdict : ▲ À EXAMINER** — 0 régression(s), 0 amélioration(s), 3 comportement(s) modifié(s).

**Fusion automatique : non** (verdict À EXAMINER, failles non analysées) : revue humaine du rapport.

Banc passé le 2026-10-21T05:15:20Z (référence) et le 2026-10-21T05:14:26Z (candidate).

## Tests

| Catégorie | Référence | Candidate |
|---|---|---|
| fonctionnel | 6/6 | 6/6 |
| securite | 12/12 | 12/12 |
| exploitation | 5/5 | 5/5 |
| performance | 1/1 | 1/1 |

## Comportements modifiés

### Serveur (version, fonctions)

- `serveur.fonctions_apercu`
  - + "CLIENT_ADMIN_API_V2"
  - + "OID4VC_VCI"
  - + "PARAMETERIZED_SCOPES"
  - + "TOKEN_EXCHANGE_DELEGATION"
  - − "CLIENT_SECRET_ROTATION"
  - − "SCIM_API"
  - − "STATELESS"
- `serveur.fonctions_desactivees`
  - + "HTTP_CLIENT_V2"
  - + "LDAP_METRICS"
  - + "LOGIN_FAILURES_V1"
  - + "OID4VC_MDOC"
  - + "OID4VC_VP"
  - − "CLIENT_SECRET_ROTATION"
  - − "SCIM_API"
- `serveur.version`
  - ~ « 26.7.5 » → « 26.8.1 »

## Performance

| Mesure | Référence | Candidate | Écart |
|---|---|---|---|
| Démarrage (s) | 18.5 | 19.4 | +5 % |
| Première connexion (s) | 1.117 | 1.08 | -3 % |
| Connexion, médiane de 5 (s) | 0.109 | 0.108 | -1 % |

## À lire avant de fusionner

- Guide de migration : https://www.keycloak.org/docs/latest/upgrading/
- Notes de version : https://www.keycloak.org/docs/latest/release_notes/
- Les lignes marquées 🔒 touchent la sécurité : décision explicite avant de fusionner.

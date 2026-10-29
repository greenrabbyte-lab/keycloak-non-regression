# keycloak-non-regression

Durcir Keycloak, le mettre à jour en continu, et **prouver à chaque fois qu'on n'a rien cassé**,
y compris quand des fournisseurs d'applications imposent leur version.

La communauté Keycloak ne corrige que la dernière version : rester sur une ancienne, c'est
accumuler les failles. Monter de version fait peur parce que des comportements changent sans
prévenir (une revendication qui disparaît d'un jeton, un réglage par défaut qui bouge). Ce kit
remplace la peur par un rapport : les mêmes tests sur la version en place et sur la candidate,
sur la même base de données, et un verdict lisible.

```
Dockerfile                  image durcie : construction optimisée, fonctions inutiles coupées, non root
realm-banc.json             realm de test : rôles, client OIDC confidentiel + PKCE, 3 comptes de test
banc/banc.py                le banc : 24 tests (fonctionnels, sécurité, exploitation, performance)
                            + observations comparables ; bibliothèque standard Python seulement
banc/rapport.py             rapport de montée de version : régressions, contrats, comportements,
                            performance, failles ; verdict BLOQUÉE / À EXAMINER / SANS ÉCART
banc/lancer_conteneur.sh    banc sur deux images Docker + PostgreSQL (CI, n'importe quel poste)
banc/lancer_distribution.py banc sur les archives officielles (poste sans Docker, Java 21)
contrats/                   contrats des applications intégrées (exemple fourni)
opentofu/                   configuration de Keycloak en code : module realm, environnements
                            banc, UAT, production
exemples/                   rapports réels (24.0.5 → 26.8.1, 26.7.5 → 26.8.1)
docs/strategie.md           versions imposées, identités (IAM, Entra ID, Keycloak), portail interne
.github/workflows/          banc, fusion automatique, publication, Renovate
```

## Démarrage rapide

```bash
# Avec Docker : la version en place contre la candidate, sur la même base (vraie migration)
banc/lancer_conteneur.sh quay.io/keycloak/keycloak:24.0.5 quay.io/keycloak/keycloak:26.8.1 /tmp/banc
# Sans Docker : sur les archives officielles (Java 21), puis le rapport
python3 banc/lancer_distribution.py --dossier keycloak-26.8.1 --version 26.8.1 --sortie 26.json
python3 banc/rapport.py 24.json 26.json --contrat contrats/mon-application.json > rapport.md
```

Options de `lancer_conteneur.sh` (variables) : `MODE=migration|neuf`, `CONFIGURATION=realm|opentofu`,
`CONTRATS="…"`, `TRIVY=chemin` (failles des deux images dans le rapport), `IMAGE_POSTGRES`.

## Le banc

Le même jeu de tests tourne sur la version en place et sur la candidate.

| Catégorie | Ce qui est vérifié |
|---|---|
| Fonctionnel | découverte OIDC ; connexion complète code + PKCE S256 ; rôles dans le jeton ; userinfo ; rafraîchissement avec rotation ; déconnexion qui révoque |
| Sécurité | signatures RS256 vérifiées avec les clés publiées ; jeton modifié refusé ; code rejoué refusé et jetons associés révoqués ; flux implicite, mot de passe direct, redirection inconnue, absence de PKCE refusés ; verrouillage par force brute ; en-têtes de sécurité ; santé et métriques absentes du port public |
| Exploitation | santé ; métriques ; journal des connexions ; configuration appliquée à l'identique ; sans dérive OpenTofu |
| Performance | démarrage ; première connexion ; médiane de 5 connexions |

Il relève aussi des **observations** : document de découverte, forme des jetons, champs de la
page de connexion, réglages du realm et du client, flux, actions requises, portées, fonctions
du serveur. Le rapport les compare : c'est là qu'apparaissent les changements qu'aucun test
n'avait prévus.

## Le rapport et son verdict

| Verdict | Quand | Suite |
|---|---|---|
| **BLOQUÉE** | un test réussi échoue, une exigence d'application est rompue, ou une faille critique apparaît | rien ne passe : corriger (configuration, contrat, fournisseur) |
| **À EXAMINER** | aucune régression, mais des comportements changent (🔒 : touchent la sécurité) | revue humaine du rapport |
| **SANS ÉCART** | mêmes résultats, mêmes comportements | fusion automatique possible (ci-dessous) |

Le rapport compte aussi les failles des deux images (Trivy) : corrigées par la montée de
version, nouvelles, restantes. Un résumé JSON (`--resume`) alimente un portail ou un tableau de
bord.

## Contrats d'application : la réponse aux versions imposées

Chaque application intégrée a un **contrat** : ce dont elle a besoin de Keycloak, exprimé sur
les observations du banc (une revendication, un champ, un point de terminaison). Une montée de
version qui en casse un est **BLOQUÉE**, avec le remède. Exemple réel : de 24.0.5 à 26.8.1,
`session_state` disparaît des jetons ; une application qui s'en sert casserait. Le banc le voit,
le contrat bloque, un mapper de protocole le rétablit (`session_state = true` dans OpenTofu), et
le banc le prouve (`exemples/`).

Établir le contrat avec le fournisseur (ou le relever dans sa configuration) et le versionner
dans `contrats/<application>.json` : c'est un **test d'acceptation partagé** entre l'équipe
plateforme et le fournisseur.

## Mise à jour continue et fusion automatique

```
Renovate (chaque nuit)
  → pull request : correctif ou reconstruction (étiquette fusion-auto), version (étiquette revue)
  → workflow banc : contrôles, image candidate, banc sur la même base que la version en place,
    Trivy sur les deux images, rapport en commentaire et statut « banc-keycloak »
  → fusion automatique si TOUT est vrai :
      verdict SANS ÉCART ; failles des deux images analysées ; aucune faille nouvelle ;
      aucune faille critique ou haute corrigeable dans la candidate ; pull request de Renovate
      étiquetée fusion-auto ; commit fusionné = commit testé
  → sinon : revue humaine (À EXAMINER), ou rien ne passe (BLOQUÉE)
  → main : banc rejoué contre la version précédente, publication de l'image testée sur ghcr.io
    et note de version (release GitHub : empreinte de l'image + rapport complet)
```

Les versions mineures et majeures ne sont jamais fusionnées seules : elles changent presque
toujours des comportements, un humain lit le rapport.

## Image durcie

- Construction optimisée (`kc.sh build`) : base de données, santé, métriques et fonctions
  figées ; démarrage `start --optimized`, sans reconstruction au démarrage.
- Fonctions coupées : usurpation d'identité, Kerberos, flux par appareil, CIBA, échange de
  jetons, SCIM, connexion X (paramètre `FONCTIONS_DESACTIVEES`).
- Non root, système de fichiers en lecture seule : le banc démarre l'image ainsi (`/tmp`,
  `data/tmp` et `data/transaction-logs` en mémoire), une image qui ne le supporte pas échoue.
- Base officielle (`quay.io/keycloak/keycloak`) figée par empreinte : le workflow refuse une
  image non figée et donne la ligne à écrire.

À l'exécution (Kubernetes) : n'exposer publiquement que `/realms/` et `/resources/` ; console
d'administration et port de gestion (9000) jamais exposés ; NetworkPolicy (entrée depuis le
proxy, sortie vers PostgreSQL seulement) ; PostgreSQL en TLS ; secrets hors Git ; journal des
connexions et des actions d'administration activé et collecté ; compte d'administration initial
supprimé après création d'un compte de service à droits limités.

## Vérifier une image publiée

Chaque image publiée depuis `main` porte, attachées sur ghcr.io et jointes à la note de
version : un **SBOM** (CycloneDX, produit par Trivy), les **déclarations VEX** du kit
(`securite/vex.openvex.json`, failles jugées non exploitables et pourquoi), une **attestation de
provenance SLSA** (construite par ce workflow, sur ce commit) et une **signature Sigstore** sans
clé (identité OIDC du workflow). Avant de déployer, vérifier :

```bash
IMAGE="ghcr.io/greenrabbyte-lab/keycloak@sha256:…"   # empreinte de la note de version
DEPOT=greenrabbyte-lab/keycloak-non-regression

# Provenance et SBOM attestés par GitHub (gh ≥ 2.49) : construit par le workflow banc.yml de ce dépôt
gh attestation verify "oci://$IMAGE" --repo "$DEPOT" \
  --signer-workflow "$DEPOT/.github/workflows/banc.yml"

# Signature et attestations Sigstore (cosign ≥ 2)
cosign verify "$IMAGE" \
  --certificate-identity-regexp "^https://github.com/$DEPOT/\.github/workflows/banc\.yml@refs/heads/main$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type cyclonedx "$IMAGE" \
  --certificate-identity-regexp "^https://github.com/$DEPOT/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com | jq -r .payload | base64 -d | jq .predicate > sbom.cdx.json
cosign verify-attestation --type openvex "$IMAGE" \
  --certificate-identity-regexp "^https://github.com/$DEPOT/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com | jq -r .payload | base64 -d | jq .predicate > vex.openvex.json

# Failles restantes, VEX appliqué (ou avec votre propre VEX)
trivy image --vex vex.openvex.json "$IMAGE"
trivy sbom sbom.cdx.json
```

Une image sans ces preuves, ou dont la signature ne vient pas de ce workflow sur `main`, n'est
pas une image publiée par le kit. Les règles d'écriture du VEX sont dans `securite/README.md`.

## Configuration en code (OpenTofu)

Fournisseur officiel `keycloak/keycloak`. Le module `opentofu/modules/realm` décrit la sécurité
du realm (force brute, en-têtes, mots de passe, jetons, passkeys), les rôles, les groupes, les
clients OIDC (confidentiels, PKCE S256, sans flux implicite ni mot de passe direct), la
fédération avec Entra ID et la traduction de ses rôles d'application en rôles Keycloak.

Un espace de travail par environnement (`banc`, `uat`, `prod`), même module :
**le banc applique exactement la configuration promise à l'UAT puis à la production**
(`CONFIGURATION=opentofu`), et un second `tofu plan` vide prouve l'absence de dérive. Les
personnes ne sont pas gérées dans OpenTofu : elles viennent d'Entra ID (et de l'outil d'IAM en
amont). État chiffré (`state_passphrase`) ; `prod.tfvars` et `uat.tfvars` restent hors Git.

## Mettre le kit en place dans votre organisation (GitHub)

1. Copier le dépôt (modèle ou fork), sans rien d'autre à installer : Python, Bash, Docker et
   OpenTofu suffisent. Transposable à GitLab CI ou Azure DevOps (`banc.yml` sert d'exemple).
2. Base de données du banc : secrets `DHI_UTILISATEUR` et `DHI_JETON` (PostgreSQL durci de
   Docker, jeton en lecture seule), ou variable `IMAGE_POSTGRES` avec une autre image figée
   par empreinte.
3. Réglages du dépôt :
   - Actions : jeton du workflow en lecture par défaut ; « Allow GitHub Actions to create and
     approve pull requests » (Renovate) ; pour un dépôt public, approbation requise pour les
     workflows des contributeurs externes ;
   - règle sur `main` : pull request obligatoire, **statut requis `banc-keycloak`** (posé par le
     banc sur le commit de chaque pull request, après le verdict et l'analyse de l'image ; ne pas
     exiger les noms des jobs : un run en attente d'approbation bloquerait la fusion automatique),
     pas de poussée forcée ni de suppression ;
   - suppression automatique des branches fusionnées ;
   - **jamais de runner auto-hébergé** sur un dépôt public.
4. Remplacer `realm-banc.json` (ou `opentofu/racine/banc.tfvars`) par la configuration type de
   l'organisation, et écrire un contrat par application intégrée.
5. Pour une image imposée : lancer le workflow à la main avec cette image en référence et
   l'image durcie (ou corrigée) en candidate ; le rapport chiffre l'écart.

## Limites

- Le banc couvre le protocole OIDC et la sécurité du serveur ; il ne remplace pas les tests de
  bout en bout de chaque application (d'où les contrats).
- Thèmes de connexion personnalisés : le banc relève les champs de la page, pas son rendu.
- SAML n'est pas encore couvert.
- Les correctifs des anciennes branches (étiquettes 24.0.6 à 24.0.10, 26.0.9 à 26.0.17…)
  existent dans le dépôt de Keycloak sans version communautaire publiée : vraisemblablement les
  branches du support commercial (Red Hat build of Keycloak).

## Contribuer, signaler une faille

Pull requests bienvenues : le banc tourne sur les branches du dépôt ; une proposition venue d'un
fork est reprise dans une branche après relecture. Une faille du kit : voir
[SECURITY.md](SECURITY.md), jamais dans un ticket public.

Le code a été écrit avec l'aide d'une IA (Claude, Anthropic) ; chaque commit le mentionne, et
chaque changement passe les mêmes contrôles que n'importe quel contributeur.

## Licence

[Apache 2.0](LICENSE), comme Keycloak.

# Stratégie : versions imposées, identités, portail interne

Notes d'architecture qui accompagnent le kit. Elles décrivent une façon de faire, à adapter.

## Versions de Keycloak imposées par un fournisseur

Situation fréquente : une application achetée exige « sa » version de Keycloak, souvent
ancienne, donc plus corrigée par la communauté (qui ne corrige que la dernière version). Du
moins risqué au plus efficace, chaque niveau prouvé par le banc et par le contrat de
l'application :

1. **Durcir autour, sans changer la version** : n'exposer que `/realms/` et `/resources/`,
   console d'administration et port de gestion invisibles de l'extérieur, NetworkPolicy,
   lecture seule, fonctions inutiles coupées, règles du proxy contre une faille connue
   (correctif virtuel). Réduit l'exposition, ne corrige pas le code.
2. **Corriger les paquets du système** de l'image du fournisseur (Copacetic, selon la
   distribution de base) : réduit les failles du système, **pas** celles de Keycloak ni de ses
   bibliothèques Java.
3. **Monter de version** avec le banc et le contrat comme preuve ; corriger par la
   configuration ce que le rapport signale (mapper, portée, réglage). Le cas mesuré dans
   `exemples/` (24.0.5 → 26.8.1, base migrée en place) montre que c'est faisable, et ce qu'il
   faut ajuster.
4. **Support commercial** (correctifs rétroportés sur d'anciennes branches) quand une montée
   est impossible, ou reconstruire une branche de maintenance depuis les sources (lourd, à
   réserver aux cas extrêmes).

Le rapport chiffré (tests, comportements, failles corrigées) sert d'argument avec le
fournisseur : « voici ce qui change, voici la preuve que votre application fonctionne ».

## Identités : outil d'IAM, Entra ID, Keycloak

| Couche | Rôle | Ce qu'elle ne fait pas |
|---|---|---|
| Outil d'IAM (gouvernance des identités) | **Source de vérité des droits** : qui a quel rôle, demandes, approbations, revues périodiques, séparation des tâches, départs | Authentifier |
| Entra ID | **Identité et authentification** (MFA, accès conditionnel) ; porte les droits sous forme de groupes ou de **rôles d'application**, provisionnés par l'outil d'IAM | Décider des droits |
| Keycloak | **Courtier** pour les applications : fédère Entra ID, **traduit** les rôles d'application en rôles Keycloak à chaque connexion (création à la volée), configuré en code | Stocker des droits propres, synchroniser des comptes |

- **Un seul sens, aucune synchronisation bricolée** : outil d'IAM → Entra ID → (à la
  connexion) Keycloak. Un départ désactivé dans Entra ID ne peut plus se connecter ; des
  sessions Keycloak courtes limitent la fenêtre. Pour une application qui exige des comptes
  créés à l'avance, l'API SCIM de Keycloak (prise en charge depuis 26.8, coupée par défaut dans
  l'image durcie) permet à l'outil d'IAM de provisionner directement : à évaluer application
  par application.
- **OpenTofu gère la structure** (realms, clients, rôles, correspondances), **jamais les
  personnes** : les affectations restent dans l'outil d'IAM, auditées.
- Entre Keycloak et Entra ID, préférer une authentification du client par certificat à un
  secret partagé.

## Portail interne (Port, Backstage…) : où il a sa place

- **Oui, comme vitrine et libre-service de l'équipe plateforme** :
  - catalogue des applications intégrées à Keycloak : fournisseur, version imposée, contrat,
    dernier verdict du banc, failles ; **tableaux de score** (version encore corrigée par la
    communauté ? contrat présent ? banc vert ?), alimentés par le résumé JSON du rapport ;
  - **actions en libre-service** qui déclenchent des workflows GitOps : « intégrer une
    application à Keycloak » (pull request : client depuis un modèle + contrat, banc, UAT,
    approbation, production), « comparer deux versions de Keycloak » (le workflow `banc` avec
    les deux images, rapport rattaché à l'entité).
- **Non, pour les droits des personnes** : un portail n'est pas un outil de gouvernance des
  identités (approbations, revues, séparation des tâches, preuves d'audit). Les demandes
  d'accès restent dans l'outil d'IAM ; le portail peut y renvoyer.
- Le portail ne modifie jamais Keycloak directement : il passe par une pull request
  (traçabilité, banc, revue), comme tout le reste.

# Déclarations VEX de l'image durcie

`vex.openvex.json` (format [OpenVEX](https://github.com/openvex/spec)) liste les failles
signalées par Trivy dans l'image durcie **que nous jugeons non exploitables dans sa
configuration**, avec la raison. Le banc lit ce fichier (`trivy --vex`) : ces failles
n'entrent plus dans le rapport ni dans le verdict ; il est attaché à chaque image publiée
(attestation `openvex`) et joint à la note de version.

Règles :

- une déclaration par faille, statut `not_affected`, justification OpenVEX
  (`vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
  `component_not_present`, `inline_mitigations_already_exist`), et une phrase en clair
  (`impact_statement`) qui cite la fonction désactivée ou le chemin de code absent ;
- jamais pour une faille **corrigeable** : on met à jour l'image, on ne l'excuse pas ;
- chaque déclaration est datée ; le fichier est relu à la revue mensuelle et toute
  déclaration de plus de 90 jours est reconfirmée ou retirée ;
- `timestamp` et `version` augmentent à chaque modification.

Exemple :

```json
{
  "vulnerability": {"name": "CVE-0000-00000"},
  "products": [{"@id": "pkg:oci/keycloak?repository_url=ghcr.io/greenrabbyte-lab"}],
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "impact_statement": "Kerberos est désactivé à la construction (KC_FEATURES_DISABLED).",
  "timestamp": "2026-10-26T00:00:00Z"
}
```

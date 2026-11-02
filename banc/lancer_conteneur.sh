#!/bin/bash
# Banc de non-régression sur deux images conteneur de Keycloak : la version en place
# (référence) et la candidate, sur PostgreSQL, puis rapport de montée de version. Pour la CI
# (.github/workflows/banc.yml) ou tout poste avec Docker.
#
# Usage : banc/lancer_conteneur.sh <image-référence> <image-candidate> <dossier-de-sortie>
# Variables (facultatives) :
#   MODE                  migration (défaut) : la candidate démarre sur la base de la référence,
#                         comme une vraie montée de version ; neuf : base vierge pour chacune.
#   CONFIGURATION         realm (défaut) : import de realm-banc.json ; opentofu : application de
#                         opentofu/racine (espace de travail « banc », tofu dans le PATH).
#   DEMARRAGE_REFERENCE   « start » (image officielle, défaut) ou « start --optimized » (image durcie).
#   DEMARRAGE_CANDIDATE   idem.
#   ETIQUETTE_REFERENCE, ETIQUETTE_CANDIDATE   noms dans le rapport.
#   IMAGE_POSTGRES        figée par empreinte.
#   CONTRATS              fichiers de contrats d'application, séparés par des espaces.
#   TRIVY                 chemin de trivy : analyse des deux images, failles dans le rapport.
#   VEX                   déclarations OpenVEX (défaut : securite/vex.openvex.json à côté du
#                         banc, s'il existe) : les failles déclarées non exploitables sont
#                         écartées du rapport, pour les deux images.
# Code de sortie : celui de rapport.py (2 : montée bloquée).
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
REF="${1:?image de référence}"
CAND="${2:?image candidate}"
SORTIE="${3:?dossier de sortie}"
MODE="${MODE:-migration}"
CONFIGURATION="${CONFIGURATION:-realm}"
IMAGE_POSTGRES="${IMAGE_POSTGRES:-postgres:17}"
mkdir -p "$SORTIE"
SORTIE="$(cd "$SORTIE" && pwd)"

reseau="banc-keycloak-$$"
mdp_pg="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
mdp_admin="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
# shellcheck disable=SC2329 # appelée par trap
nettoyer() {
  docker rm -f kc-banc pg-banc > /dev/null 2>&1 || true
  docker network rm "$reseau" > /dev/null 2>&1 || true
  [ -n "${TRAVAIL_TOFU:-}" ] && rm -rf "$TRAVAIL_TOFU"
}
trap nettoyer EXIT
docker network create "$reseau" > /dev/null

demarrer_postgres() {
  docker rm -f pg-banc > /dev/null 2>&1 || true
  docker run -d --name pg-banc --network "$reseau" \
    -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD="$mdp_pg" "$IMAGE_POSTGRES" > /dev/null
  for _ in $(seq 60); do
    docker exec pg-banc pg_isready -U keycloak -d keycloak > /dev/null 2>&1 && return 0
    sleep 1
  done
  echo "PostgreSQL ne démarre pas" >&2
  return 1
}

# Génération de Keycloak : options de nom d'hôte (v1 avant 25, v2 ensuite) et port de gestion.
majeure() {
  docker run --rm --entrypoint /opt/keycloak/bin/kc.sh "$1" --version 2> /dev/null \
    | grep -oE 'Keycloak [0-9]+' | head -1 | grep -oE '[0-9]+'
}

# demarrer <image> <démarrage> <import : oui|non> ; écrit la durée de démarrage dans $duree
demarrer_keycloak() {
  local image="$1" demarrage="$2" importer="$3" version options=()
  version="$(majeure "$image")"
  [ -n "$version" ] || { echo "version de Keycloak introuvable dans $image" >&2; return 1; }
  options=(-e KC_DB=postgres -e "KC_DB_URL=jdbc:postgresql://pg-banc:5432/keycloak"
           -e KC_DB_USERNAME=keycloak -e "KC_DB_PASSWORD=$mdp_pg"
           -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true -e KC_METRICS_ENABLED=true
           -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e "KC_BOOTSTRAP_ADMIN_PASSWORD=$mdp_admin"
           -e KEYCLOAK_ADMIN=admin -e "KEYCLOAK_ADMIN_PASSWORD=$mdp_admin")
  if (( version >= 25 )); then
    options+=(-e "KC_HOSTNAME=http://localhost:8080")
    gestion="http://localhost:9000"
  else
    options+=(-e KC_HOSTNAME_STRICT=false -e KC_HOSTNAME_STRICT_HTTPS=false)
    gestion=""
  fi
  local arguments=()
  read -r -a arguments <<< "$demarrage"
  if [ "$importer" = oui ] && [ "$CONFIGURATION" = realm ]; then
    options+=(-v "$ICI/../realm-banc.json:/opt/keycloak/data/import/realm-banc.json:ro")
    arguments+=(--import-realm)
  fi
  docker rm -f kc-banc > /dev/null 2>&1 || true
  local debut fin
  debut="$(date +%s.%N)"
  # Image construite (--optimized) : comme en production, système de fichiers en lecture seule.
  # Image officielle non construite : elle se construit au démarrage, donc doit pouvoir écrire.
  local durcissement=(--security-opt no-new-privileges --cap-drop ALL)
  if [[ "$demarrage" == *--optimized* ]]; then
    durcissement+=(--read-only --tmpfs /tmp --tmpfs /opt/keycloak/data/tmp --tmpfs /opt/keycloak/data/transaction-logs)
  fi
  docker run -d --name kc-banc --network "$reseau" -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 \
    "${durcissement[@]}" "${options[@]}" "$image" "${arguments[@]}" > /dev/null
  for _ in $(seq 300); do
    if curl -fsS "${gestion:-http://localhost:8080}/health/ready" > /dev/null 2>&1; then
      fin="$(date +%s.%N)"
      duree="$(python3 -c "print(round($fin - $debut, 1))")"
      return 0
    fi
    sleep 1
  done
  docker logs kc-banc > "$SORTIE/keycloak-echec.log" 2>&1 || true
  echo "Keycloak ($image) pas prêt après 300 s : $SORTIE/keycloak-echec.log" >&2
  return 1
}

# Configuration en code : un seul espace de travail OpenTofu pour tout le passage (état local,
# chiffré avec une phrase jetable). Appliquée sur la référence, puis « plan » après la migration
# de la candidate : un plan vide prouve que la montée de version n'a rien changé à la
# configuration promise (sinon : dérive, consignée dans derive.json et dans le rapport).
TRAVAIL_TOFU=""
preparer_opentofu() {
  TRAVAIL_TOFU="$(mktemp -d)"
  cp -r "$ICI/../opentofu" "$TRAVAIL_TOFU/"
  export TF_IN_AUTOMATION=1 TF_VAR_keycloak_utilisateur=admin TF_VAR_keycloak_mot_de_passe="$mdp_admin"
  TF_VAR_state_passphrase="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  export TF_VAR_state_passphrase
  (cd "$TRAVAIL_TOFU/opentofu/racine" && tofu init -input=false -no-color > /dev/null \
     && tofu workspace new banc -no-color > /dev/null)
  printf '{}' > "$SORTIE/derive.json"
}
appliquer_opentofu() {
  [ -n "$TRAVAIL_TOFU" ] || preparer_opentofu
  (cd "$TRAVAIL_TOFU/opentofu/racine" && tofu apply -auto-approve -input=false -no-color -var-file=banc.tfvars > /dev/null)
}
# plan_vide <reference|candidate> : plan détaillé ; 0 = aucune dérive, 2 = dérive, 1 = erreur.
plan_vide() {
  local quoi="$1" code=0
  (cd "$TRAVAIL_TOFU/opentofu/racine" && tofu plan -detailed-exitcode -input=false -no-color -var-file=banc.tfvars \
     > "$SORTIE/plan-$quoi.txt" 2>&1) || code=$?
  python3 - "$SORTIE/derive.json" "$quoi" "$code" "$SORTIE/plan-$quoi.txt" <<'PY'
import json, sys
chemin, quoi, code, plan = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
d = json.load(open(chemin))
lignes = [l for l in open(plan, encoding="utf-8", errors="replace").read().splitlines()
          if l.strip().startswith(("#", "~", "+", "-", "Plan:", "Error", "No changes"))][:40]
d[quoi] = {"code": code, "etat": {0: "aucune dérive", 2: "dérive"}.get(code, "erreur"), "extrait": lignes}
json.dump(d, open(chemin, "w"), ensure_ascii=False, indent=2)
PY
  echo "OpenTofu ($quoi) : $(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]['etat'])" "$SORTIE/derive.json" "$quoi")"
  [ "$code" -ne 1 ] || { echo "tofu plan en erreur : $SORTIE/plan-$quoi.txt" >&2; return 1; }
}

passer_banc() {
  local etiquette="$1" fichier="$2" args=()
  [ -n "$gestion" ] && args=(--gestion "$gestion")
  python3 "$ICI/banc.py" --url http://localhost:8080 "${args[@]}" --admin admin --mot-de-passe-admin "$mdp_admin" \
    --etiquette "$etiquette" --demarrage-s "$duree" --sortie "$fichier"
  docker logs kc-banc > "${fichier%.json}.log" 2>&1 || true
}

echo "== Référence : $REF"
demarrer_postgres
demarrer_keycloak "$REF" "${DEMARRAGE_REFERENCE:-start}" oui
if [ "$CONFIGURATION" = opentofu ]; then appliquer_opentofu; plan_vide reference; fi
passer_banc "${ETIQUETTE_REFERENCE:-$REF}" "$SORTIE/reference.json"

echo "== Candidate : $CAND (mode $MODE)"
if [ "$MODE" = neuf ]; then
  demarrer_postgres
  demarrer_keycloak "$CAND" "${DEMARRAGE_CANDIDATE:-start}" oui
  if [ "$CONFIGURATION" = opentofu ]; then appliquer_opentofu; plan_vide candidate; fi
else
  docker rm -f kc-banc > /dev/null
  demarrer_keycloak "$CAND" "${DEMARRAGE_CANDIDATE:-start}" non
  # Après la migration : la configuration appliquée sur la référence doit être intacte.
  [ "$CONFIGURATION" = opentofu ] && plan_vide candidate
fi
passer_banc "${ETIQUETTE_CANDIDATE:-$CAND}" "$SORTIE/candidate.json"

trivy_args=()
if [ -n "${TRIVY:-}" ]; then
  echo "== Failles (Trivy)"
  vex=()
  VEX="${VEX:-$ICI/../securite/vex.openvex.json}"
  if [ -f "$VEX" ]; then vex=(--vex "$VEX"); echo "VEX : $VEX"; fi
  "$TRIVY" image --quiet --scanners vuln "${vex[@]}" --format json --output "$SORTIE/trivy-reference.json" "$REF"
  "$TRIVY" image --quiet --scanners vuln "${vex[@]}" --format json --output "$SORTIE/trivy-candidate.json" "$CAND"
  trivy_args=(--trivy-reference "$SORTIE/trivy-reference.json" --trivy-candidate "$SORTIE/trivy-candidate.json")
fi
contrats=()
for c in ${CONTRATS:-}; do contrats+=(--contrat "$c"); done

derive_args=()
[ "$CONFIGURATION" = opentofu ] && derive_args=(--derive "$SORTIE/derive.json")
code=0
python3 "$ICI/rapport.py" "$SORTIE/reference.json" "$SORTIE/candidate.json" "${trivy_args[@]}" "${contrats[@]}" \
  "${derive_args[@]}" --resume "$SORTIE/resume.json" > "$SORTIE/rapport.md" || code=$?
echo "Rapport : $SORTIE/rapport.md (verdict : $(python3 -c "import json; print(json.load(open('$SORTIE/resume.json'))['verdict'])"))"
exit "$code"

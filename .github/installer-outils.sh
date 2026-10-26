#!/bin/bash
# Installe les outils figés de .github/outils.env (version et empreinte vérifiées) dans un
# dossier, puis l'ajoute au PATH des étapes suivantes du job (GITHUB_PATH).
# Usage : .github/installer-outils.sh <dossier> [analyse] [trivy] [signature]
set -euo pipefail
ICI="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/outils.env
source "$ICI/outils.env"
B="${1:?dossier où installer}"
shift
mkdir -p "$B"

telecharger() {  # url, fichier, empreinte : échec si l'empreinte diffère
  curl -fsSL --max-time 180 -o "$B/$2" "$1"
  echo "$3  $B/$2" | sha256sum -c --quiet -
}

for groupe in "$@"; do
  case "$groupe" in
    analyse)
      telecharger "$SHELLCHECK_URL" sc.tar.xz "$SHELLCHECK_SHA256"
      telecharger "$HADOLINT_URL" hadolint "$HADOLINT_SHA256"
      telecharger "$ACTIONLINT_URL" al.tar.gz "$ACTIONLINT_SHA256"
      telecharger "$RUFF_URL" ruff.tar.gz "$RUFF_SHA256"
      telecharger "$TOFU_URL" tofu.zip "$TOFU_SHA256"
      tar -xJf "$B/sc.tar.xz" -C "$B"
      mv "$B/shellcheck-v$SHELLCHECK_VERSION/shellcheck" "$B/shellcheck"
      tar -xzf "$B/al.tar.gz" -C "$B" actionlint
      tar -xzf "$B/ruff.tar.gz" -C "$B"
      mv "$B/ruff-x86_64-unknown-linux-gnu/ruff" "$B/ruff"
      unzip -q -o "$B/tofu.zip" tofu -d "$B"
      chmod +x "$B/hadolint" "$B/tofu"
      ;;
    trivy)
      telecharger "$TRIVY_URL" trivy.tar.gz "$TRIVY_SHA256"
      tar -xzf "$B/trivy.tar.gz" -C "$B" trivy
      ;;
    signature)
      telecharger "$COSIGN_URL" cosign "$COSIGN_SHA256"
      chmod +x "$B/cosign"
      ;;
    *) echo "groupe inconnu : $groupe" >&2; exit 1 ;;
  esac
done
[ -n "${GITHUB_PATH:-}" ] && echo "$B" >> "$GITHUB_PATH"
exit 0

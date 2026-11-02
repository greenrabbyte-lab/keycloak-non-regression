"""Veille quotidienne de l'image publiée (GRL-45).

Trivy n'analysait l'image qu'au passage du banc : une faille publiée après la dernière release
restait invisible jusqu'à la prochaine proposition de Renovate. Ce script lit l'analyse Trivy
(JSON) de la **dernière image publiée** et classe ses failles critiques et hautes :

  corrigeables     une version corrigée existe → le workflow relance Renovate ; s'il y a une image
                   de base plus récente, la pull request suit le circuit habituel (banc, fusion
                   automatique si le rapport le permet, publication) ; aucune action humaine ;
  sans correctif   pas de version corrigée → un ticket GitHub unique « Failles de l'image
                   publiée » est tenu à jour (ouvert, complété, fermé quand tout est résolu) ;
                   la préparation du rituel le reprend.

Sortie : un fichier de variables pour le workflow (GITHUB_OUTPUT) et le corps du ticket (Markdown).
Usage : python3 veille_image.py trivy.json --image <référence@sha256> --sortie "$GITHUB_OUTPUT" \
          --ticket ticket.md
"""
import argparse
import json
from datetime import datetime, timezone

GRAVES = ("CRITICAL", "HIGH")


def failles(chemin):
    with open(chemin, encoding="utf-8") as f:
        rapport = json.load(f)
    trouvees = {}
    for resultat in rapport.get("Results", []) or []:
        for v in resultat.get("Vulnerabilities", []) or []:
            if v.get("Severity", "UNKNOWN") not in GRAVES:
                continue
            trouvees[v["VulnerabilityID"]] = {
                "gravite": v.get("Severity"), "paquet": v.get("PkgName", "?"),
                "installee": v.get("InstalledVersion", "?"), "corrigee_en": v.get("FixedVersion") or "",
                "titre": (v.get("Title") or "")[:90],
            }
    return trouvees


def main():
    p = argparse.ArgumentParser()
    p.add_argument("trivy")
    p.add_argument("--image", required=True)
    p.add_argument("--sortie", required=True)
    p.add_argument("--ticket", required=True)
    a = p.parse_args()

    f = failles(a.trivy)
    corrigeables = {c: v for c, v in f.items() if v["corrigee_en"]}
    sans = {c: v for c, v in f.items() if not v["corrigee_en"]}
    ordre = {"CRITICAL": 0, "HIGH": 1}
    tri = sorted(f.items(), key=lambda kv: (ordre[kv[1]["gravite"]], kv[0]))
    quand = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lignes = [
        f"Analyse Trivy quotidienne de l'image publiée, le {quand} (VEX appliqué).",
        "",
        f"Image : `{a.image}`",
        "",
        f"- **{len(corrigeables)}** faille(s) critique(s) ou haute(s) **corrigeable(s)** → Renovate relancé ; "
        "la pull request de reconstruction ou de correctif suit le circuit habituel (banc, fusion automatique "
        "si le rapport le permet, publication).",
        f"- **{len(sans)}** faille(s) critique(s) ou haute(s) **sans correctif** : rien à faire côté image ; "
        "à suivre ici, à déclarer dans le VEX si elles ne s'appliquent pas.",
        "",
        "| Faille | Gravité | Paquet | Installée | Corrigée en | Titre |",
        "|---|---|---|---|---|---|",
    ]
    for c, v in tri:
        lignes.append(f"| {c} | {v['gravite']} | {v['paquet']} | {v['installee']} | "
                      f"{v['corrigee_en'] or '—'} | {v['titre']} |")
    lignes += ["", "Ce ticket est tenu à jour automatiquement par le workflow `veille-image` et fermé quand "
               "plus aucune faille critique ou haute ne reste. — Claude (préparation automatique)"]
    with open(a.ticket, "w", encoding="utf-8") as out:
        out.write("\n".join(lignes) + "\n")

    with open(a.sortie, "a", encoding="utf-8") as out:
        out.write(f"corrigeables={len(corrigeables)}\n")
        out.write(f"sans_correctif={len(sans)}\n")
        out.write(f"total={len(f)}\n")
        out.write(f"critiques={sum(1 for v in f.values() if v['gravite'] == 'CRITICAL')}\n")
    print(f"{len(f)} faille(s) critique(s)/haute(s) : {len(corrigeables)} corrigeable(s), {len(sans)} sans correctif")


if __name__ == "__main__":
    main()

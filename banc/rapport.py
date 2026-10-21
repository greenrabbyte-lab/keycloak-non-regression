"""Rapport de montée de version de Keycloak.

Compare deux passages du banc (banc.py) : la version en place (référence) et la version
candidate. Sortie Markdown (résumé de CI, commentaire de pull request, pièce jointe) et,
au besoin, un résumé JSON (verdict, compteurs) pour un portail ou un tableau de bord.

Verdict :
  BLOQUÉE      un test réussi sur la référence échoue sur la candidate (régression), une
               exigence d'un contrat d'application n'est plus satisfaite, ou une faille
               critique apparaît ;
  À EXAMINER   aucune régression, mais des comportements changent : à lire avant de fusionner ;
  SANS ÉCART   mêmes résultats, mêmes comportements.

Fusion automatique : permise seulement si le verdict est SANS ÉCART, que les failles des deux
images ont été analysées (Trivy), que la candidate n'apporte aucune faille nouvelle et ne
contient aucune faille critique ou haute corrigeable. Le rapport le dit, avec les raisons d'un
refus ; le workflow vérifie en plus le type de mise à jour (correctif ou reconstruction).
Code de sortie : 2 si BLOQUÉE, 0 sinon (1 avec --strict si À EXAMINER).

Contrat d'application (--contrat, répétable) : ce dont une application intégrée a besoin
(une revendication dans le jeton, un champ de la page de connexion, un point de terminaison…),
exprimé sur les observations du banc. C'est l'outil pour les applications des fournisseurs :
leurs exigences deviennent des tests, et une montée de version qui les casse est bloquée.

Usage : python3 rapport.py reference.json candidate.json [--trivy-reference r.json
          --trivy-candidate c.json] [--contrat app.json …] [--resume resume.json] > rapport.md
"""
import argparse
import json
import sys

DOMAINES = {
    "securite": "Sécurité", "jeton": "Jetons", "oidc": "OIDC (découverte, clés)",
    "userinfo": "Informations utilisateur",
    "client": "Client applicatif", "realm": "Realm (réglages, flux, actions requises)",
    "serveur": "Serveur (version, fonctions)", "exploitation": "Exploitation", "page_connexion": "Page de connexion",
}
SENSIBLES = ("securite.", "jeton.valeurs", "realm.en_tetes_configures", "oidc.jwks", "client.", "realm.reglages")
LIMITE = 15
GRAVITES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def charger(chemin):
    with open(chemin) as f:
        return json.load(f)


def ecarts(avant, apres):
    """Liste de lignes décrivant l'écart entre deux valeurs (dictionnaires, listes, scalaires)."""
    if avant == apres:
        return []
    if isinstance(avant, dict) and isinstance(apres, dict):
        lignes = []
        for k in sorted(set(avant) | set(apres)):
            if k not in avant:
                lignes.append(f"+ `{k}` = {court(apres[k])}")
            elif k not in apres:
                lignes.append(f"− `{k}` (était {court(avant[k])})")
            elif avant[k] != apres[k]:
                lignes.append(f"~ `{k}` : {court(avant[k])} → {court(apres[k])}")
        return lignes
    if isinstance(avant, list) and isinstance(apres, list):
        a, b = [json.dumps(x, ensure_ascii=False) for x in avant], [json.dumps(x, ensure_ascii=False) for x in apres]
        return [f"+ {x}" for x in b if x not in a] + [f"− {x}" for x in a if x not in b]
    return [f"~ {court(avant)} → {court(apres)}"]


def court(valeur, taille=90):
    texte = json.dumps(valeur, ensure_ascii=False) if not isinstance(valeur, str) else f"« {valeur} »"
    return texte if len(texte) <= taille else texte[: taille - 1] + "…"


def present(observation, cle):
    if isinstance(observation, dict):
        return cle in observation
    if isinstance(observation, list):
        return cle in observation or json.dumps(cle, ensure_ascii=False) in observation
    return observation == cle


def verifier_contrats(chemins, ref, cand):
    """Exigences des applications : satisfaite par la référence et par la candidate ?"""
    lignes = []
    for chemin in chemins:
        contrat = charger(chemin)
        for e in contrat["exigences"]:
            avant = present(ref["observations"].get(e["observation"]), e["cle"])
            apres = present(cand["observations"].get(e["observation"]), e["cle"])
            lignes.append({"application": contrat["application"], **e, "reference": avant, "candidate": apres})
    return lignes


def failles(chemin):
    if not chemin:
        return None
    rapport = charger(chemin)
    trouvees = {}
    for resultat in rapport.get("Results", []) or []:
        for v in resultat.get("Vulnerabilities", []) or []:
            trouvees[v["VulnerabilityID"]] = {"gravite": v.get("Severity", "UNKNOWN"), "paquet": v.get("PkgName"),
                                              "corrigee_en": v.get("FixedVersion") or "", "titre": v.get("Title", "")}
    return trouvees


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument("reference")
    a.add_argument("candidate")
    a.add_argument("--trivy-reference")
    a.add_argument("--trivy-candidate")
    a.add_argument("--contrat", action="append", default=[], help="contrat d'application (JSON), répétable")
    a.add_argument("--resume", help="écrit un résumé JSON (verdict, compteurs)")
    a.add_argument("--strict", action="store_true", help="code 1 si des comportements changent")
    args = a.parse_args()
    ref, cand = charger(args.reference), charger(args.candidate)
    sortie = []
    ecrire = sortie.append

    tests_ref = {t["id"]: t for t in ref["tests"]}
    tests_cand = {t["id"]: t for t in cand["tests"]}
    regressions = [i for i in tests_cand if tests_ref.get(i, {}).get("statut") == "réussi"
                   and tests_cand[i]["statut"] != "réussi"]
    corrections = [i for i in tests_cand if i in tests_ref and tests_ref[i]["statut"] != "réussi"
                   and tests_cand[i]["statut"] == "réussi"]
    toujours_ko = [i for i in tests_cand if i in tests_ref and tests_ref[i]["statut"] != "réussi"
                   and tests_cand[i]["statut"] != "réussi"]

    obs_ref, obs_cand = ref["observations"], cand["observations"]
    differences = {}
    for cle in sorted(set(obs_ref) | set(obs_cand)):
        lignes = ecarts(obs_ref.get(cle), obs_cand.get(cle)) if cle in obs_ref and cle in obs_cand else \
            ([f"+ nouvelle observation : {court(obs_cand[cle])}"] if cle in obs_cand
             else [f"− observation disparue (était {court(obs_ref[cle])})"])
        if lignes:
            differences[cle] = lignes

    f_ref, f_cand = failles(args.trivy_reference), failles(args.trivy_candidate)
    nouvelles_critiques = []
    if f_ref is not None and f_cand is not None:
        nouvelles_critiques = [c for c, v in f_cand.items() if c not in f_ref and v["gravite"] == "CRITICAL"]

    contrats = verifier_contrats(args.contrat, ref, cand)
    ruptures = [c for c in contrats if not c["candidate"]]

    if regressions or nouvelles_critiques or ruptures:
        verdict, signe = "BLOQUÉE", "✖"
    elif differences:
        verdict, signe = "À EXAMINER", "▲"
    else:
        verdict, signe = "SANS ÉCART", "✔"

    raisons_refus, failles_nouvelles, graves_corrigeables = [], [], []
    if verdict != "SANS ÉCART":
        raisons_refus.append(f"verdict {verdict}")
    if f_ref is None or f_cand is None:
        raisons_refus.append("failles non analysées")
    else:
        failles_nouvelles = sorted(c for c in f_cand if c not in f_ref)
        graves_corrigeables = sorted(c for c, v in f_cand.items()
                                     if v["gravite"] in ("CRITICAL", "HIGH") and v["corrigee_en"])
        if failles_nouvelles:
            raisons_refus.append(f"{len(failles_nouvelles)} faille(s) nouvelle(s)")
        if graves_corrigeables:
            raisons_refus.append(f"{len(graves_corrigeables)} faille(s) critique(s) ou haute(s) corrigeable(s)")

    ecrire(f"# Montée de version Keycloak : {ref['etiquette']} → {cand['etiquette']}")
    ecrire("")
    ecrire(f"**Verdict : {signe} {verdict}** — {len(regressions)} régression(s), "
           f"{len(corrections)} amélioration(s), "
           f"{len(differences)} comportement(s) modifié(s)"
           + (f", {len(ruptures)} exigence(s) d'application non satisfaite(s)" if contrats else "")
           + (f", {len(nouvelles_critiques)} faille(s) critique(s) nouvelle(s)" if f_cand is not None else "") + ".")
    ecrire("")
    if raisons_refus:
        suite = "correction obligatoire avant toute fusion" if verdict == "BLOQUÉE" else "revue humaine du rapport"
        ecrire(f"**Fusion automatique : non** ({', '.join(raisons_refus)}) : {suite}.")
    else:
        ecrire("**Fusion automatique : ✔ permise** (sans écart, aucune faille nouvelle, aucune faille "
               "critique ou haute corrigeable).")
    ecrire("")
    ecrire(f"Banc passé le {ref['date']} (référence) et le {cand['date']} (candidate).")
    ecrire("")

    ecrire("## Tests")
    ecrire("")
    ecrire("| Catégorie | Référence | Candidate |")
    ecrire("|---|---|---|")
    for cat in ("fonctionnel", "securite", "exploitation", "performance"):
        r = [t for t in ref["tests"] if t["categorie"] == cat]
        c = [t for t in cand["tests"] if t["categorie"] == cat]
        ecrire(f"| {cat} | {sum(t['statut'] == 'réussi' for t in r)}/{len(r)} | "
               f"{sum(t['statut'] == 'réussi' for t in c)}/{len(c)} |")
    ecrire("")
    for titre, liste, signe_liste in (("Régressions (réussi → en échec)", regressions, "✖"),
                                      ("Améliorations (en échec → réussi)", corrections, "✔"),
                                      ("En échec dans les deux versions", toujours_ko, "▲")):
        if liste:
            ecrire(f"### {titre}")
            ecrire("")
            for i in liste:
                t = tests_cand[i]
                detail = t["detail"] or tests_ref.get(i, {}).get("detail", "")
                ecrire(f"- {signe_liste} **{t['titre']}** (`{i}`) : {detail}")
            ecrire("")

    if contrats:
        ecrire("## Contrats des applications")
        ecrire("")
        ecrire("| Application | Exigence | Référence | Candidate | Pourquoi | Remède |")
        ecrire("|---|---|---|---|---|---|")
        for c in contrats:
            ecrire(f"| {c['application']} | `{c['observation']}` : `{c['cle']}` | "
                   f"{'✔' if c['reference'] else '✖'} | {'✔' if c['candidate'] else '✖ rompue'} | "
                   f"{c.get('raison', '')} | {c.get('remede', '') if not c['candidate'] else ''} |")
        ecrire("")

    ecrire("## Comportements modifiés")
    ecrire("")
    if not differences:
        ecrire("Aucun.")
    for prefixe, nom in DOMAINES.items():
        cles = [k for k in differences if k.split(".")[0] == prefixe]
        if not cles:
            continue
        ecrire(f"### {nom}")
        ecrire("")
        for cle in cles:
            sensible = " 🔒 à valider par la sécurité" if cle.startswith(SENSIBLES) else ""
            ecrire(f"- `{cle}`{sensible}")
            lignes = differences[cle]
            for ligne in lignes[:LIMITE]:
                ecrire(f"  - {ligne}")
            if len(lignes) > LIMITE:
                ecrire(f"  - … et {len(lignes) - LIMITE} autre(s)")
        ecrire("")

    ecrire("## Performance")
    ecrire("")
    ecrire("| Mesure | Référence | Candidate | Écart |")
    ecrire("|---|---|---|---|")
    for cle, nom in (("demarrage_s", "Démarrage (s)"), ("connexion_premiere_s", "Première connexion (s)"),
                     ("connexion_mediane_s", "Connexion, médiane de 5 (s)")):
        v1, v2 = ref["mesures"].get(cle), cand["mesures"].get(cle)
        if v1 and v2:
            delta = 100.0 * (v2 - v1) / v1
            alerte = " ▲" if delta > 25 else ""
            ecrire(f"| {nom} | {v1} | {v2} | {delta:+.0f} %{alerte} |")
    ecrire("")

    if f_ref is not None and f_cand is not None:
        ecrire("## Failles (Trivy)")
        ecrire("")
        ecrire("| Gravité | Référence | Candidate |")
        ecrire("|---|---|---|")
        for g in GRAVITES:
            ecrire(f"| {g} | {sum(v['gravite'] == g for v in f_ref.values())} | "
                   f"{sum(v['gravite'] == g for v in f_cand.values())} |")
        ecrire("")
        corrigees = sorted((c for c in f_ref if c not in f_cand),
                           key=lambda c: (GRAVITES.index(f_ref[c]["gravite"]), c))
        nouvelles = sorted((c for c in f_cand if c not in f_ref),
                           key=lambda c: (GRAVITES.index(f_cand[c]["gravite"]), c))
        ecrire(f"**{len(corrigees)} corrigée(s)** par la montée de version, **{len(nouvelles)} nouvelle(s)**.")
        ecrire("")
        for titre, liste, source in (("Corrigées (les plus graves)", corrigees, f_ref),
                                     ("Nouvelles", nouvelles, f_cand)):
            if liste:
                ecrire(f"### {titre}")
                ecrire("")
                for c in liste[:LIMITE]:
                    v = source[c]
                    ecrire(f"- {v['gravite']} {c} ({v['paquet']}) {v['titre'][:80]}")
                if len(liste) > LIMITE:
                    ecrire(f"- … et {len(liste) - LIMITE} autre(s)")
                ecrire("")

    ecrire("## À lire avant de fusionner")
    ecrire("")
    ecrire("- Guide de migration : https://www.keycloak.org/docs/latest/upgrading/")
    ecrire("- Notes de version : https://www.keycloak.org/docs/latest/release_notes/")
    ecrire("- Les lignes marquées 🔒 touchent la sécurité : décision explicite avant de fusionner.")
    print("\n".join(sortie))

    if args.resume:
        with open(args.resume, "w") as f:
            json.dump({"reference": ref["etiquette"], "candidate": cand["etiquette"], "verdict": verdict,
                       "regressions": regressions, "ameliorations": corrections,
                       "comportements_modifies": len(differences),
                       "failles_critiques_nouvelles": nouvelles_critiques,
                       "failles_nouvelles": failles_nouvelles,
                       "failles_graves_corrigeables": graves_corrigeables,
                       "fusion_automatique": {"permise": not raisons_refus, "raisons": raisons_refus},
                       "exigences_rompues": [f"{c['application']} : {c['cle']}" for c in ruptures]},
                      f, ensure_ascii=False, indent=2)
    if verdict == "BLOQUÉE":
        return 2
    return 1 if args.strict and verdict == "À EXAMINER" else 0


if __name__ == "__main__":
    sys.exit(main())

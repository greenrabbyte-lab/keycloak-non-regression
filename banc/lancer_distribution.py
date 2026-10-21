"""Lance une distribution officielle de Keycloak (archive .tar.gz) avec le realm de test,
le temps de passer le banc, puis l'arrête. Pour un poste sans Docker ; en CI, le banc
tourne sur l'image conteneur (voir README).

Usage : python3 lancer_distribution.py --dossier keycloak-26.8.1 --version 26.8.1 \\
          --realm ../realm-banc.json --sortie resultats-26.8.1.json
        ou, pour tester la configuration OpenTofu au lieu du realm importé :
        python3 lancer_distribution.py … --opentofu ../opentofu/racine
Prérequis : Java 21 (Java 17 ou 21 pour Keycloak 24 et 25) ; tofu dans le PATH pour --opentofu.
"""
import json
import argparse
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ICI = Path(__file__).resolve().parent


def options(version, postgres=None):
    """Options de démarrage selon la génération de Keycloak (nom d'hôte v1 avant 25, v2 ensuite)."""
    majeure = int(version.split(".")[0])
    construction = [f"--db={'postgres' if postgres else 'dev-file'}", "--health-enabled=true",
                    "--metrics-enabled=true"]
    if majeure >= 25:
        demarrage = ["--hostname=http://localhost:8080", "--http-enabled=true"]
        gestion = "http://localhost:9000"
    else:
        demarrage = ["--hostname-strict=false", "--hostname-strict-https=false", "--http-enabled=true"]
        gestion = None  # santé et métriques servies sur le port public
    if postgres:
        demarrage += [f"--db-url={postgres}"]
    return construction, demarrage + ["--import-realm", "--log-level=warn"], gestion


def attendre(url, delai):
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310 -- adresse locale du banc
                if r.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(1)
    return False


def appliquer_opentofu(racine, travail, mdp_admin):
    """Applique la configuration (espace de travail « banc »), puis vérifie qu'un nouveau plan est vide."""
    copie = travail / "opentofu"
    shutil.copytree(Path(racine).resolve().parent, copie, ignore=shutil.ignore_patterns(".terraform", "*.tfstate*"))
    dossier = copie / Path(racine).name
    env = dict(os.environ, TF_IN_AUTOMATION="1", TF_VAR_state_passphrase=secrets.token_urlsafe(24),
               TF_VAR_keycloak_utilisateur="admin", TF_VAR_keycloak_mot_de_passe=mdp_admin)
    def tofu(*arguments, verifier=True):
        r = subprocess.run(["tofu", *arguments, "-no-color"], cwd=dossier, env=env, check=False,  # noqa: S603,S607
                           capture_output=True, text=True)
        if verifier and r.returncode:
            raise RuntimeError(f"tofu {arguments[0]} : {r.stderr.strip()[-2000:]}")
        return r.returncode
    tofu("init", "-input=false")
    tofu("workspace", "new", "banc")
    tofu("apply", "-auto-approve", "-input=false", "-var-file=banc.tfvars")
    print("OpenTofu : configuration appliquée", flush=True)
    code = tofu("plan", "-detailed-exitcode", "-input=false", "-var-file=banc.tfvars", verifier=False)
    print(f"OpenTofu : plan suivant {'vide' if code == 0 else f'non vide (code {code})'}", flush=True)
    return code


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument("--dossier", required=True, help="distribution décompressée (keycloak-X.Y.Z)")
    a.add_argument("--version", required=True)
    a.add_argument("--realm", default=str(ICI.parent / "realm-banc.json"))
    a.add_argument("--etiquette")
    a.add_argument("--opentofu",
                   help="racine OpenTofu à appliquer (espace de travail « banc ») au lieu d'importer le realm")
    a.add_argument("--postgres", help="URL JDBC PostgreSQL (identifiants : KC_DB_USERNAME, KC_DB_PASSWORD)")
    a.add_argument("--garder-donnees", help="copie la base (dossier data) de cette version après le banc")
    a.add_argument("--reprendre-donnees",
                   help="démarre sur la base d'une version précédente (montée de version en place, migration)")
    a.add_argument("--sortie", required=True)
    args = a.parse_args()

    source = Path(args.dossier).resolve()
    travail = Path(tempfile.mkdtemp(prefix=f"banc-keycloak-{args.version}-"))
    kc = travail / "keycloak"
    shutil.copytree(source, kc, symlinks=True)
    if args.reprendre_donnees:
        if not args.postgres:
            shutil.rmtree(kc / "data", ignore_errors=True)
            shutil.copytree(Path(args.reprendre_donnees) / "data", kc / "data")
        shutil.copy(Path(args.reprendre_donnees) / "admin", travail / "admin")
    elif not args.opentofu:
        (kc / "data" / "import").mkdir(parents=True, exist_ok=True)
        shutil.copy(args.realm, kc / "data" / "import" / "realm-banc.json")
    mdp_admin = (travail / "admin").read_text() if args.reprendre_donnees else secrets.token_urlsafe(18)
    env = dict(os.environ, KC_BOOTSTRAP_ADMIN_USERNAME="admin", KC_BOOTSTRAP_ADMIN_PASSWORD=mdp_admin,
               KEYCLOAK_ADMIN="admin", KEYCLOAK_ADMIN_PASSWORD=mdp_admin)
    construction, demarrage, gestion = options(args.version, args.postgres)

    print(f"{args.version} : construction optimisée", flush=True)
    subprocess.run([str(kc / "bin" / "kc.sh"), "build", *construction], env=env, check=True,  # noqa: S603
                   stdout=subprocess.DEVNULL)
    debut = time.monotonic()
    journal = open(travail / "keycloak.log", "w")  # noqa: SIM115 -- fermé à l'arrêt
    serveur = subprocess.Popen([str(kc / "bin" / "kc.sh"), "start", "--optimized", *demarrage],  # noqa: S603
                               env=env, stdout=journal, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        if not attendre(f"{gestion or 'http://localhost:8080'}/health/ready", 240):
            print(f"{args.version} : pas prêt après 240 s (journal : {travail / 'keycloak.log'})", flush=True)
            return 1
        duree = round(time.monotonic() - debut, 1)
        print(f"{args.version} : prêt en {duree} s", flush=True)
        derive = appliquer_opentofu(args.opentofu, travail, mdp_admin) if args.opentofu and not args.reprendre_donnees \
            else None
        commande = [sys.executable, str(ICI / "banc.py"), "--url", "http://localhost:8080",
                    "--admin", "admin", "--mot-de-passe-admin", mdp_admin,
                    "--etiquette", args.etiquette or f"Keycloak {args.version} (distribution officielle)",
                    "--demarrage-s", str(duree), "--sortie", args.sortie]
        if gestion:
            commande[4:4] = ["--gestion", gestion]
        code = subprocess.run(commande, check=False).returncode  # noqa: S603
        if derive is not None:
            resultat = json.loads(Path(args.sortie).read_text())
            resultat["tests"].append({"id": "exploitation.opentofu_sans_derive", "categorie": "exploitation",
                                      "titre": "Configuration OpenTofu appliquée, puis aucun écart au plan suivant",
                                      "statut": "réussi" if derive == 0 else "échec",
                                      "detail": "" if derive == 0 else f"tofu plan : code {derive}", "duree_s": 0})
            Path(args.sortie).write_text(json.dumps(resultat, ensure_ascii=False, indent=2))
            code = code or (0 if derive == 0 else 1)
        return code
    finally:
        os.killpg(serveur.pid, signal.SIGTERM)
        try:
            serveur.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(serveur.pid, signal.SIGKILL)
        journal.close()
        if args.garder_donnees:
            cible = Path(args.garder_donnees)
            shutil.rmtree(cible, ignore_errors=True)
            if not args.postgres:
                shutil.copytree(kc / "data", cible / "data", ignore=shutil.ignore_patterns("import", "tmp"))
            cible.mkdir(parents=True, exist_ok=True)
            (cible / "admin").write_text(mdp_admin)
            (cible / "admin").chmod(0o600)
        shutil.rmtree(travail, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

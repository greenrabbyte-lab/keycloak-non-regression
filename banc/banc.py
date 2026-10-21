"""Banc de non-régression de Keycloak.

Rejoue le même jeu de tests sur un serveur Keycloak démarré avec le realm de test
(realm-banc.json) et écrit un fichier JSON : le résultat de chaque test, et des
« observations » (ce que le serveur expose ou applique) que rapport.py compare d'une version
à l'autre. Bibliothèque standard seulement : aucune dépendance à installer.

Catégories :
  fonctionnel   connexion OIDC complète (code + PKCE), rôles, jetons, rafraîchissement, déconnexion
  securite      refus attendus (flux implicite, mot de passe direct, redirection inconnue, PKCE
                absent, code rejoué, jeton modifié), signature RS256, verrouillage par force brute,
                santé et métriques hors du port public, en-têtes de sécurité
  exploitation  santé, métriques, journal des connexions
  performance   temps de démarrage, durée médiane d'une connexion complète

Usage : python3 banc.py --url http://localhost:8080 --gestion http://localhost:9000 \\
          --admin admin --mot-de-passe-admin … --etiquette "26.8.1" --sortie resultats.json
"""
import argparse
import base64
import hashlib
import hmac
import html.parser
import http.cookiejar
import json
import secrets
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REALM = "banc"
CLIENT = "application-banc"
SECRET_CLIENT = "banc-uniquement-pas-un-secret"  # noqa: S105 -- realm de test, jamais déployé
RAPPEL = "http://localhost:8765/rappel"
UTILISATEURS = {"alice": "banc-alice-Mot2Passe", "bob": "banc-bob-Mot2Passe", "victime": "banc-victime-Mot2Passe"}
EN_TETES_SECURITE = ("x-frame-options", "content-security-policy", "x-content-type-options", "referrer-policy",
                     "x-robots-tag", "x-xss-protection", "strict-transport-security")


# ------------------------------------------------------------------ outils HTTP

class Echec(Exception):
    """Un test n'obtient pas le comportement attendu."""


def verifier(condition, message):
    if not condition:
        raise Echec(message)


class SansRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class PolitiqueBanc(http.cookiejar.DefaultCookiePolicy):
    """Le banc tourne en HTTP sur localhost : on accepte d'envoyer les cookies marqués Secure."""

    def return_ok_secure(self, cookie, request):
        return True


class Reponse:
    def __init__(self, statut, en_tetes, corps):
        self.statut, self.en_tetes, self.corps = statut, {k.lower(): v for k, v in en_tetes.items()}, corps

    def json(self):
        return json.loads(self.corps)

    @property
    def texte(self):
        return self.corps.decode("utf-8", "replace")


class Client:
    """Un navigateur minimal : cookies, aucune redirection suivie automatiquement."""

    def __init__(self):
        self.cookies = http.cookiejar.CookieJar(PolitiqueBanc())
        self.ouvreur = urllib.request.build_opener(SansRedirection(), urllib.request.HTTPCookieProcessor(self.cookies),
                                                   urllib.request.ProxyHandler({}))

    def requete(self, methode, url, donnees=None, en_tetes=None, delai=30):
        corps = urllib.parse.urlencode(donnees).encode() if isinstance(donnees, dict) else donnees
        # S310 : adresses du serveur testé uniquement (http/https)
        req = urllib.request.Request(url, data=corps, method=methode, headers=en_tetes or {})  # noqa: S310
        try:
            with self.ouvreur.open(req, timeout=delai) as r:
                return Reponse(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            return Reponse(e.code, dict(e.headers), e.read())

    def get(self, url, **kw):
        return self.requete("GET", url, **kw)

    def post(self, url, donnees, **kw):
        return self.requete("POST", url, donnees, **kw)


class Formulaires(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.formulaires, self._courant = [], None

    def handle_starttag(self, balise, attrs):
        a = dict(attrs)
        if balise == "form":
            self._courant = {"action": a.get("action", ""), "id": a.get("id"), "champs": {}}
            self.formulaires.append(self._courant)
        elif balise == "input" and self._courant is not None and a.get("name"):
            self._courant["champs"][a["name"]] = {"type": a.get("type", "text"), "valeur": a.get("value", "")}

    def handle_endtag(self, balise):
        if balise == "form":
            self._courant = None


def formulaire_connexion(page):
    p = Formulaires()
    p.feed(page)
    return next((f for f in p.formulaires if "password" in f["champs"]), None)


def b64url(texte):
    return base64.urlsafe_b64decode(texte + "=" * (-len(texte) % 4))


def charge_jwt(jeton):
    return json.loads(b64url(jeton.split(".")[1]))


def verifier_rs256(jeton, jwks):
    """Vérifie une signature RS256 (PKCS#1 v1.5, SHA-256) avec la clé publique du JWKS."""
    entete_b64, charge_b64, signature_b64 = jeton.split(".")
    entete = json.loads(b64url(entete_b64))
    cle = next((k for k in jwks.get("keys", []) if k.get("kid") == entete.get("kid")), None)
    if entete.get("alg") != "RS256" or cle is None or cle.get("kty") != "RSA":
        return False
    n = int.from_bytes(b64url(cle["n"]), "big")
    e = int.from_bytes(b64url(cle["e"]), "big")
    taille = (n.bit_length() + 7) // 8
    recu = pow(int.from_bytes(b64url(signature_b64), "big"), e, n).to_bytes(taille, "big")
    prefixe = bytes.fromhex("3031300d060960864801650304020105000420")  # DigestInfo SHA-256
    empreinte = hashlib.sha256(f"{entete_b64}.{charge_b64}".encode()).digest()
    attendu = b"\x00\x01" + b"\xff" * (taille - 3 - len(prefixe) - len(empreinte)) + b"\x00" + prefixe + empreinte
    return hmac.compare_digest(recu, attendu)


def forme(valeur):
    """Forme d'une valeur, pour comparer des jetons sans leurs valeurs changeantes."""
    if isinstance(valeur, dict):
        return {k: forme(v) for k, v in sorted(valeur.items())}
    if isinstance(valeur, list):
        return sorted({json.dumps(forme(v), sort_keys=True) for v in valeur})
    if isinstance(valeur, bool):
        return "booléen"
    if isinstance(valeur, (int, float)):
        return "nombre"
    return "texte"


# ------------------------------------------------------------------ banc

class Banc:
    def __init__(self, url, gestion, admin, mdp_admin):
        self.url, self.gestion = url.rstrip("/"), (gestion or url).rstrip("/")
        self.admin, self.mdp_admin = admin, mdp_admin
        self.base = f"{self.url}/realms/{REALM}/protocol/openid-connect"
        self.resultats, self.observations, self.mesures = [], {}, {}
        self._jwks = None

    # -------------------------------------------------------------- utilitaires

    def test(self, ident, categorie, titre):
        def decorateur(fonction):
            debut = time.monotonic()
            try:
                detail = fonction() or ""
                statut = "réussi"
            except Echec as e:
                statut, detail = "échec", str(e)
            except Exception as e:  # noqa: BLE001 -- un test ne doit jamais arrêter le banc
                statut, detail = "erreur", f"{type(e).__name__} : {e}"
            self.resultats.append({"id": ident, "categorie": categorie, "titre": titre, "statut": statut,
                                   "detail": detail, "duree_s": round(time.monotonic() - debut, 3)})
            return fonction
        return decorateur

    def jeton_admin(self):
        r = Client().post(f"{self.url}/realms/master/protocol/openid-connect/token",
                          {"grant_type": "password", "client_id": "admin-cli",
                           "username": self.admin, "password": self.mdp_admin})
        verifier(r.statut == 200, f"jeton d'administration refusé ({r.statut})")
        return r.json()["access_token"]

    def admin_get(self, chemin):
        r = Client().get(f"{self.url}/admin{chemin}", en_tetes={"Authorization": f"Bearer {self.jeton_admin()}"})
        verifier(r.statut == 200, f"GET /admin{chemin} : {r.statut}")
        return r.json()

    def jwks(self):
        if self._jwks is None:
            self._jwks = Client().get(f"{self.base}/certs").json()
        return self._jwks

    def autorisation(self, client, **params):
        verificateur = secrets.token_urlsafe(48)
        defaut = {"client_id": CLIENT, "response_type": "code", "scope": "openid", "redirect_uri": RAPPEL,
                  "state": secrets.token_urlsafe(16), "nonce": secrets.token_urlsafe(16),
                  "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verificateur.encode()).digest())
                  .rstrip(b"=").decode(), "code_challenge_method": "S256"}
        defaut.update({k: v for k, v in params.items() if v is not None})
        for k in [k for k, v in params.items() if v is None]:
            defaut.pop(k, None)
        return client.get(f"{self.base}/auth?{urllib.parse.urlencode(defaut)}"), verificateur, defaut

    def connexion(self, utilisateur, mot_de_passe=None, client=None):
        """Flux complet code + PKCE ; renvoie (réponse du jeton ou None, page finale)."""
        client = client or Client()
        page, verificateur, params = self.autorisation(client)
        verifier(page.statut == 200, f"page de connexion : {page.statut}")
        f = formulaire_connexion(page.texte)
        verifier(f, "formulaire de connexion introuvable")
        champs = {k: v["valeur"] for k, v in f["champs"].items() if v["type"] == "hidden"}
        champs.update({"username": utilisateur, "password": mot_de_passe or UTILISATEURS[utilisateur]})
        action = urllib.parse.urljoin(self.url, f["action"].replace("&amp;", "&"))
        r = client.post(action, champs)
        if r.statut not in (302, 303) or not r.en_tetes.get("location", "").startswith(RAPPEL):
            return None, r
        retour = urllib.parse.parse_qs(urllib.parse.urlsplit(r.en_tetes["location"]).query)
        verifier(retour.get("state", [""])[0] == params["state"], "state modifié")
        code = retour["code"][0]
        jeton = client.post(f"{self.base}/token", {"grant_type": "authorization_code", "code": code,
                                                    "redirect_uri": RAPPEL, "code_verifier": verificateur},
                            en_tetes={"Authorization": "Basic " + base64.b64encode(
                                f"{CLIENT}:{SECRET_CLIENT}".encode()).decode()})
        verifier(jeton.statut == 200, f"échange du code : {jeton.statut} {jeton.texte[:200]}")
        donnees = jeton.json()
        donnees["_code"] = code
        donnees["_verificateur"] = verificateur
        return donnees, r

    def basique(self):
        return {"Authorization": "Basic " + base64.b64encode(f"{CLIENT}:{SECRET_CLIENT}".encode()).decode()}

    # -------------------------------------------------------------- tests

    def executer(self):
        c = self

        @c.test("exploitation.sante", "exploitation", "Santé : le serveur se déclare prêt")
        def _():
            r = Client().get(f"{c.gestion}/health/ready")
            verifier(r.statut == 200 and r.json().get("status") == "UP", f"{r.statut}")
            c.observations["exploitation.sante"] = {
                "adresse": "port de gestion" if c.gestion != c.url else "port public"}

        @c.test("securite.sante_hors_port_public", "securite",
                "Santé et métriques absentes du port public (exposées seulement sur le port de gestion)")
        def _():
            sante = Client().get(f"{c.url}/health/ready").statut
            metriques = Client().get(f"{c.url}/metrics").statut
            c.observations["securite.port_public"] = {"/health/ready": sante, "/metrics": metriques}
            verifier(sante == 404 and metriques == 404,
                     f"exposées sur le port public : santé {sante}, métriques {metriques}")

        @c.test("exploitation.metriques", "exploitation", "Métriques Prometheus disponibles")
        def _():
            r = Client().get(f"{c.gestion}/metrics")
            verifier(r.statut == 200 and b"# TYPE" in r.corps, f"{r.statut}")

        @c.test("fonctionnel.decouverte", "fonctionnel", "Document de découverte OIDC")
        def _():
            d = Client().get(f"{c.url}/realms/{REALM}/.well-known/openid-configuration").json()
            verifier(d["issuer"] == f"{c.url}/realms/{REALM}", f"émetteur {d['issuer']}")
            verifier("S256" in d.get("code_challenge_methods_supported", []), "PKCE S256 non annoncé")
            c.observations["oidc.decouverte.cles"] = sorted(d)
            c.observations["oidc.decouverte.valeurs"] = {
                k: sorted(d[k]) if isinstance(d[k], list) else d[k]
                for k in sorted(d) if not str(d[k]).startswith("http")}

        @c.test("securite.jwks", "securite", "Clés publiées : RSA 2048 bits au moins, aucune clé privée exposée")
        def _():
            cles = c.jwks()["keys"]
            verifier(cles, "aucune clé")
            for k in cles:
                verifier("d" not in k and "p" not in k, "partie privée exposée")
                if k.get("kty") == "RSA":
                    verifier(len(b64url(k["n"])) * 8 >= 2048, "clé RSA trop courte")
            c.observations["oidc.jwks"] = sorted(f"{k.get('kty')}/{k.get('alg')}/{k.get('use')}" for k in cles)

        etat = {}

        @c.test("fonctionnel.connexion_proprietaire", "fonctionnel",
                "Connexion complète (code + PKCE S256) d'un compte proprietaire")
        def _():
            debut = time.monotonic()
            jeton, page = c.connexion("alice")
            c.mesures["connexion_premiere_s"] = round(time.monotonic() - debut, 3)
            verifier(jeton, f"connexion refusée ({page.statut})")
            etat["alice"] = jeton
            acces, ident = charge_jwt(jeton["access_token"]), charge_jwt(jeton["id_token"])
            verifier("proprietaire" in acces.get("realm_access", {}).get("roles", []), "rôle proprietaire absent")
            verifier(ident.get("preferred_username") == "alice", "identité inattendue")
            c.observations["jeton.acces.forme"] = forme({k: v for k, v in acces.items()})
            c.observations["jeton.identite.forme"] = forme(ident)
            c.observations["jeton.reponse.champs"] = sorted(k for k in jeton if not k.startswith("_"))
            c.observations["jeton.valeurs"] = {
                "typ": acces.get("typ"), "azp": acces.get("azp"), "aud": acces.get("aud"),
                "scope": sorted(acces.get("scope", "").split()),
                "roles_realm": sorted(acces.get("realm_access", {}).get("roles", [])),
                "duree_acces_s": acces["exp"] - acces["iat"], "expires_in": jeton.get("expires_in"),
                "refresh_expires_in": jeton.get("refresh_expires_in"), "token_type": jeton.get("token_type")}

        @c.test("securite.signature", "securite", "Jetons signés en RS256 et vérifiables avec les clés publiées")
        def _():
            verifier("alice" in etat, "pas de jeton (connexion échouée)")
            for nom in ("access_token", "id_token"):
                verifier(verifier_rs256(etat["alice"][nom], c.jwks()), f"signature invalide ({nom})")

        @c.test("securite.jeton_modifie", "securite", "Un jeton modifié est refusé (userinfo)")
        def _():
            verifier("alice" in etat, "pas de jeton")
            entete, charge, signature = etat["alice"]["access_token"].split(".")
            d = json.loads(b64url(charge))
            d["realm_access"] = {"roles": ["proprietaire", "admin"]}
            faux = base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
            r = Client().get(f"{c.base}/userinfo", en_tetes={"Authorization": f"Bearer {entete}.{faux}.{signature}"})
            verifier(r.statut == 401, f"jeton modifié accepté ({r.statut})")

        @c.test("fonctionnel.userinfo", "fonctionnel",
                "Informations utilisateur avec un jeton valide, refus sans jeton")
        def _():
            verifier("alice" in etat, "pas de jeton")
            porteur = {"Authorization": f"Bearer {etat['alice']['access_token']}"}
            r = Client().get(f"{c.base}/userinfo", en_tetes=porteur)
            verifier(r.statut == 200 and r.json().get("preferred_username") == "alice", f"{r.statut}")
            c.observations["userinfo.champs"] = sorted(r.json())
            verifier(Client().get(f"{c.base}/userinfo").statut == 401, "userinfo accessible sans jeton")

        @c.test("fonctionnel.rafraichissement", "fonctionnel",
                "Rafraîchissement du jeton, et refus d'un jeton de rafraîchissement déjà utilisé (rotation)")
        def _():
            verifier("alice" in etat, "pas de jeton")
            ancien = etat["alice"]["refresh_token"]
            r = Client().post(f"{c.base}/token", {"grant_type": "refresh_token", "refresh_token": ancien},
                              en_tetes=c.basique())
            verifier(r.statut == 200, f"rafraîchissement refusé ({r.statut})")
            etat["alice"]["refresh_token"] = r.json()["refresh_token"]
            r2 = Client().post(f"{c.base}/token", {"grant_type": "refresh_token", "refresh_token": ancien},
                               en_tetes=c.basique())
            verifier(r2.statut == 400, f"jeton de rafraîchissement réutilisé accepté ({r2.statut})")

        @c.test("fonctionnel.deconnexion", "fonctionnel",
                "Déconnexion : la session et le rafraîchissement sont révoqués")
        def _():
            verifier("alice" in etat, "pas de jeton")
            r = Client().post(f"{c.base}/logout", {"refresh_token": etat["alice"]["refresh_token"]},
                              en_tetes=c.basique())
            verifier(r.statut in (200, 204), f"déconnexion : {r.statut}")
            r2 = Client().post(f"{c.base}/token", {"grant_type": "refresh_token",
                                                   "refresh_token": etat["alice"]["refresh_token"]},
                               en_tetes=c.basique())
            verifier(r2.statut == 400, f"rafraîchissement après déconnexion accepté ({r2.statut})")

        @c.test("securite.code_rejoue", "securite",
                "Un code d'autorisation ne sert qu'une fois, et le rejouer révoque les jetons déjà émis")
        def _():
            jeton, page = c.connexion("alice")
            verifier(jeton, f"connexion refusée ({page.statut})")
            r = Client().post(f"{c.base}/token", {"grant_type": "authorization_code", "code": jeton["_code"],
                                                  "redirect_uri": RAPPEL, "code_verifier": jeton["_verificateur"]},
                              en_tetes=c.basique())
            verifier(r.statut == 400, f"code rejoué accepté ({r.statut})")
            r2 = Client().post(f"{c.base}/token",
                               {"grant_type": "refresh_token", "refresh_token": jeton["refresh_token"]},
                               en_tetes=c.basique())
            c.observations["securite.code_rejoue.revocation"] = r2.statut == 400
            verifier(r2.statut == 400, "les jetons émis avec le code rejoué restent valides")

        @c.test("fonctionnel.roles_foyer", "fonctionnel", "Un compte foyer n'a pas le rôle proprietaire")
        def _():
            jeton, page = c.connexion("bob")
            verifier(jeton, f"connexion refusée ({page.statut})")
            roles = charge_jwt(jeton["access_token"]).get("realm_access", {}).get("roles", [])
            verifier("foyer" in roles and "proprietaire" not in roles, f"rôles : {roles}")

        @c.test("securite.mauvais_mot_de_passe", "securite",
                "Mauvais mot de passe : aucun code délivré, message neutre")
        def _():
            jeton, page = c.connexion("bob", "mauvais-mot-de-passe-123")
            verifier(jeton is None, "connexion acceptée avec un mauvais mot de passe")
            verifier(page.statut == 200 and formulaire_connexion(page.texte), "pas de retour au formulaire")

        @c.test("securite.flux_implicite", "securite", "Flux implicite refusé")
        def _():
            r, _, _ = c.autorisation(Client(), response_type="token", code_challenge=None, code_challenge_method=None)
            loc = r.en_tetes.get("location", "")
            refuse = (r.statut == 400) or ("error=" in loc and "access_token" not in loc)
            verifier(refuse, f"flux implicite accepté ({r.statut} {loc[:80]})")

        @c.test("securite.mot_de_passe_direct", "securite", "Connexion directe par mot de passe (ROPC) refusée")
        def _():
            r = Client().post(f"{c.base}/token", {"grant_type": "password", "username": "alice",
                                                  "password": UTILISATEURS["alice"], "scope": "openid"},
                              en_tetes=c.basique())
            verifier(r.statut in (400, 401), f"ROPC accepté ({r.statut})")
            c.observations["securite.ropc.erreur"] = r.json().get("error")

        @c.test("securite.redirection_inconnue", "securite",
                "Adresse de retour non enregistrée refusée, sans redirection")
        def _():
            r, _, _ = c.autorisation(Client(), redirect_uri="https://attaquant.invalid/rappel")
            verifier(r.statut == 400 and "attaquant" not in r.en_tetes.get("location", ""), f"{r.statut}")

        @c.test("securite.pkce_obligatoire", "securite", "Demande sans PKCE refusée")
        def _():
            r, _, _ = c.autorisation(Client(), code_challenge=None, code_challenge_method=None)
            loc = r.en_tetes.get("location", "")
            verifier(r.statut in (302, 303, 400) and ("error=" in loc or r.statut == 400),
                     f"demande sans PKCE acceptée ({r.statut})")
            c.observations["securite.pkce.erreur"] = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query).get(
                "error", [str(r.statut)])[0]

        @c.test("securite.en_tetes", "securite", "En-têtes de sécurité de la page de connexion")
        def _():
            page, _, _ = c.autorisation(Client())
            presents = {k: page.en_tetes[k] for k in EN_TETES_SECURITE if k in page.en_tetes}
            c.observations["securite.en_tetes"] = presents
            csp = presents.get("content-security-policy", "")
            verifier("frame-ancestors" in csp or "x-frame-options" in presents,
                     "protection contre l'intégration absente")
            verifier(presents.get("x-content-type-options") == "nosniff", "nosniff absent")

        @c.test("securite.force_brute", "securite",
                "Force brute : compte verrouillé temporairement après 5 échecs, même avec le bon mot de passe")
        def _():
            for _ in range(5):
                c.connexion("victime", "mauvais-mot-de-passe-123")
                time.sleep(1.1)  # au-delà de la détection des connexions trop rapprochées
            jeton, _ = c.connexion("victime")
            verifier(jeton is None, "connexion acceptée malgré le verrouillage")
            ident = c.admin_get(f"/realms/{REALM}/users?username=victime&exact=true")[0]["id"]
            etat_attaque = c.admin_get(f"/realms/{REALM}/attack-detection/brute-force/users/{ident}")
            verifier(etat_attaque.get("disabled") is True, f"non verrouillé : {etat_attaque}")
            c.observations["securite.force_brute"] = {k: forme(v) for k, v in etat_attaque.items()}

        @c.test("exploitation.journal_connexions", "exploitation",
                "Journal des connexions : réussites et échecs enregistrés")
        def _():
            evenements = c.admin_get(f"/realms/{REALM}/events?max=200")
            types = sorted({e["type"] for e in evenements})
            c.observations["exploitation.evenements"] = types
            verifier("LOGIN" in types and "LOGIN_ERROR" in types, f"types : {types}")

        @c.test("exploitation.configuration_importee", "exploitation",
                "Configuration du realm importée à l'identique")
        def _():
            realm = c.admin_get(f"/realms/{REALM}")
            attendus = {"bruteForceProtected": True, "failureFactor": 5, "eventsEnabled": True,
                        "passwordPolicy": "length(12) and notUsername and notEmail", "accessTokenLifespan": 300,
                        "revokeRefreshToken": True, "sslRequired": "external"}
            ecarts = {k: realm.get(k) for k, v in attendus.items() if realm.get(k) != v}
            c.observations["realm.reglages"] = {k: v for k, v in sorted(realm.items())
                                                if isinstance(v, (str, int, float, bool)) and k not in ("id",)}
            c.observations["realm.en_tetes_configures"] = realm.get("browserSecurityHeaders", {})
            client = c.admin_get(f"/realms/{REALM}/clients?clientId={CLIENT}")[0]
            c.observations["client.reglages"] = {
                k: v for k, v in sorted(client.items())
                if isinstance(v, (str, int, float, bool)) and k not in ("id", "secret")}
            c.observations["client.attributs"] = {k: v for k, v in sorted(client.get("attributes", {}).items())}
            verifier(not ecarts, f"écarts : {ecarts}")
            verifier(client.get("implicitFlowEnabled") is False and client.get("directAccessGrantsEnabled") is False,
                     "client modifié à l'import")

        @c.test("exploitation.inventaire", "exploitation",
                "Inventaire du serveur : version, fonctions, flux, actions requises, portées")
        def _():
            info = c.admin_get("/serverinfo")
            c.observations["serveur.version"] = info.get("systemInfo", {}).get("version")
            profil = info.get("profileInfo", {})
            c.observations["serveur.fonctions_desactivees"] = sorted(profil.get("disabledFeatures", []))
            c.observations["serveur.fonctions_apercu"] = sorted(profil.get("previewFeatures", []))
            flux = c.admin_get(f"/realms/{REALM}/authentication/flows")
            c.observations["realm.flux"] = sorted(f["alias"] for f in flux)
            c.observations["realm.actions_requises"] = sorted(
                f"{a['alias']} ({'active' if a.get('enabled') else 'inactive'})"
                for a in c.admin_get(f"/realms/{REALM}/authentication/required-actions"))
            c.observations["realm.portees"] = sorted(s["name"] for s in c.admin_get(f"/realms/{REALM}/client-scopes"))
            c.observations["page_connexion.champs"] = sorted(
                (formulaire_connexion(c.autorisation(Client())[0].texte) or {}).get("champs", {}))

        @c.test("performance.connexion", "performance", "Durée médiane d'une connexion complète (5 essais)")
        def _():
            durees = []
            for _ in range(5):
                debut = time.monotonic()
                jeton, _ = c.connexion("bob")
                verifier(jeton, "connexion refusée")
                durees.append(time.monotonic() - debut)
            c.mesures["connexion_mediane_s"] = round(statistics.median(durees), 3)
            return f"{c.mesures['connexion_mediane_s']} s"


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument("--url", required=True, help="adresse publique, ex. http://localhost:8080")
    a.add_argument("--gestion", help="port de gestion (santé, métriques), ex. http://localhost:9000")
    a.add_argument("--admin", required=True)
    a.add_argument("--mot-de-passe-admin", required=True)
    a.add_argument("--etiquette", required=True, help="nom de la version testée dans le rapport")
    a.add_argument("--demarrage-s", type=float, help="durée de démarrage mesurée par le lanceur")
    a.add_argument("--sortie", required=True)
    args = a.parse_args()
    banc = Banc(args.url, args.gestion, args.admin, args.mot_de_passe_admin)
    banc.executer()
    if args.demarrage_s is not None:
        banc.mesures["demarrage_s"] = args.demarrage_s
    resultat = {"etiquette": args.etiquette, "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tests": banc.resultats, "observations": banc.observations, "mesures": banc.mesures}
    with open(args.sortie, "w") as f:
        json.dump(resultat, f, ensure_ascii=False, indent=2)
    ok = sum(t["statut"] == "réussi" for t in banc.resultats)
    print(f"{args.etiquette} : {ok}/{len(banc.resultats)} tests réussis", flush=True)
    for t in banc.resultats:
        if t["statut"] != "réussi":
            print(f"  {t['statut'].upper()} {t['id']} : {t['detail']}", flush=True)


if __name__ == "__main__":
    sys.exit(main())

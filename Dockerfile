# Image Keycloak durcie, construite par .github/workflows/banc.yml après le banc
# de non-régression. Construction optimisée : base de données, santé, métriques et fonctions
# figées à la construction (démarrage plus rapide, pas de reconstruction au démarrage) ;
# fonctions inutiles désactivées (surface d'attaque réduite) ; non root ; système de fichiers
# en lecture seule possible (seul /tmp est écrit).
# Base : image officielle, figée par empreinte (Renovate propose versions et reconstructions ;
# chaque proposition passe le banc avant fusion). Pour une image imposée par un fournisseur,
# remplacer les deux FROM par la sienne : le banc dira ce que le durcissement change.
FROM quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244 AS construction

# Désactivées : usurpation d'identité par un administrateur, Kerberos, flux par appareil, CIBA,
# échange de jetons, API SCIM (à réactiver si l'outil d'IAM provisionne par SCIM), connexion X.
ARG FONCTIONS_DESACTIVEES=impersonation,kerberos,device-flow,ciba,token-exchange-standard,scim-api,twitter-broker
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_FEATURES_DISABLED=${FONCTIONS_DESACTIVEES}
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244
COPY --from=construction /opt/keycloak/ /opt/keycloak/
USER 1000
# Santé : port de gestion 9000 (jamais exposé publiquement) ; vérifiée par Kubernetes.
HEALTHCHECK NONE
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]

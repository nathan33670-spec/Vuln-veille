# PROGRESS — Journal d'avancement

## État courant

- **Phase** : 2 (socle de veille et vecteur d'entrée NVD) **en cours**. Phase 1 terminée, CI verte.
- **Dernière étape terminée** : 2.7 à 2.12 (technos, périmètre de veille, éléments collectés, vulnérabilités, preuves et synthèses, sources), backend et tests.
- **Étape en cours** : 2.13 interfaces de la phase 2.
- **Prochaine étape** : clôture de la phase 2 (critère de sortie, CI), puis phase 3 (moteur de workflows).
- **Points d'attention** :
  - Sous le rôle `vv_portal`, la RLS masque une ligne à peine insérée : **pas de `RETURNING`** sur les insertions du portail (renseigner les horodatages côté application).
  - Le garde « toute route a une politique » doit passer par `fastapi.routing.iter_route_contexts` (FastAPI 0.142 enveloppe les routeurs inclus) ; il échoue si moins de 10 routes sont trouvées.
  - Smokescreen accepte les clients sans rôle (ACL `default`) : prévoir des rôles mTLS par type de worker en phase 2.
  - Environnement cloud : builds Docker uniquement via les variantes avec l'autorité du proxy (PROCEDURES §9 bis). Avant un test de la pile locale, partir d'un `.env` régénéré et de volumes vides (`down -v`) : un `.env` ou un volume Postgres d'une session précédente fait échouer `migrate`.
  - Dépendances Go de Caddy et smokescreen figées dans `deploy/*/build/go.{mod,sum}` (montée de version : PROCEDURES §8).
  - Frontend : aucun attribut `style` (CSP) ; les styles vont dans `packages/ui/src/styles.css`. jsdom n'implémente pas `<dialog>.showModal` : polyfill dans `packages/auth/src/test-setup.ts`.
  - Les requêtes typées d'openapi-fetch attendent `null` (et non `undefined`) pour les paramètres facultatifs (`exactOptionalPropertyTypes`).
  - Coffre : l'API n'a que les clés publiques ; un trousseau privé ne se monte que dans le worker de son usage (PROCEDURES §9). `make env` refuse d'écraser des trousseaux existants.
  - Sortie réseau : les workers n'ont **ni DNS externe ni route** ; en mode proxy, `SafeHttpClient` ne résout pas les noms et laisse smokescreen résoudre et filtrer. Obtenir un client par `egress_client(settings, policy)`, jamais directement.
  - L'environnement cloud ne donne pas Internet à smokescreen : un appel réel (NVD…) échoue en `network_error` dans le bac à sable, pas en CI ni en production.
  - NVD : une CVE inconnue n'est annoncée (`cve.published`) que si elle a été publiée depuis moins de 14 jours (paramétrable) ; sinon elle est cataloguée sans événement. Le rattrapage initial n'émet aucun événement.
  - Connecteurs enregistrés : `nvd`, `cisa_kev`, `epss`, `cve_org` (globaux). Une source globale synchronisée déclare `syncs = True`, un champ `sync_interval_minutes` et une méthode `sync` ; la tâche `collect.connector_sync` et le scheduler s'occupent du reste. Après l'ajout d'un type, régénérer `deploy/smokescreen/acl.yaml` par `python -m app.cli egress-acl --static-only --output ../deploy/smokescreen/acl.yaml` (un test vérifie la couverture).
  - Reste à faire (hors 2.3) : approbation du réseau privé par un admin (route et interface). Les colonnes existent ; décider comment un admin VOC approuve un connecteur du CERT qu'il ne voit pas (RLS) avant de l'implémenter.
  - Écart assumé (2.7) : « import depuis le dictionnaire CPE » est réalisé par des suggestions tirées des configurations CPE déjà synchronisées depuis NVD (`/technologies/cpe-suggestions`), sans appel à l'API CPE de NVD : l'API n'a pas d'accès Internet et la donnée est déjà là.
  - Lecture partagée (ADR-024) : `/vulnerabilities`, `/cves` et `/technologies` demandent `vuln.read` (tous les internes, lecteurs compris) ; les écritures passent par `/workspaces/{espace}/…` avec `vuln.qualify`. Les évaluations sont lisibles par l'autre équipe, modifiables par la sienne seulement (RLS).
  - Les éditeurs de texte de l'outil de développement transforment parfois les échappements `\u…` en caractères invisibles : un test bloquant (`tests/security/test_source_hygiene.py`) refuse tout caractère invisible ou de contrôle bidirectionnel dans le code.
  - Questions encore ouvertes : Q33 (LLMaaS), Q34 (charte PDF), Q35 (quotas Gemini).

## Journal

### 2026-10-22 — Session 8 : phase 2, coffre de secrets et sortie réseau

- `SafeHttpClient` (`app/net/`) : politique d'URL, validation des adresses (unicast public seulement, jamais loopback ni métadonnées même sur exception), épinglage d'IP en mode direct, résolution laissée à smokescreen en mode proxy, redirections revalidées sans fuite d'identifiants, décompression bornée (gzip et deflate seulement), échéance totale ; proxy obligatoire en production.
- Cadre des connecteurs : types et registre (refus à l'import des types payants, des identifiants en configuration, des domaines invalides), migration `0004_connectors` (connecteurs, curseurs, RLS), API par famille et par portée, test de connexion exécuté par le worker de la famille, quotas Redis, génération de la liste blanche du proxy.
- NVD : migration `0005_catalog` (`cve_records`, `cve_changes`, `outbox_events`), analyse défensive des enregistrements, détection des changements (CVSS ajouté, sévérité relevée, CPE ajoutées, KEV, référence d'exploit, rejet), synchronisation par fenêtres (rattrapage silencieux, incrémental avec recouvrement, curseur par fenêtre, pause, backoff, verrou), planification par le scheduler.
- Sources globales : CISA KEV (premier import silencieux, entrées récentes annoncées), FIRST EPSS (CVE du catalogue seulement), CVE.org (détection précoce par `delta.json`, rattrapage par `deltaLog.json`, NVD jamais écrasé) ; tâche générique de synchronisation et planification commune.
- Domaine vulnérabilités : migrations `0006_watch` (technos, périmètre, sources, éléments collectés) et `0007_vulnerabilities` (fiches partagées, évaluations par équipe, technos, preuves, synthèses IA, commentaires privés, chronologie) ; moteur de périmètre (KEV, CWE exclues, technos par CPE puis nom, éditeurs, mots-clés, seuil CVSS, CVE sans score) ; API du catalogue CVE (filtre par décision de périmètre, état des synchronisations), des technos (recherche approchée, fusion, suggestions CPE), du périmètre (aperçu), des sources et des vulnérabilités (promotion d'une CVE, création sans CVE, qualification avec transitions contrôlées, reprise de la qualification de l'autre équipe, commentaires, preuves, rattachement aux technos) ; récupération à la demande d'une CVE absente du catalogue par le worker.
- Tests : suite SSRF hors ligne (adresses piégées, écritures numériques, rebinding, redirections, bombes de décompression), test TLS réel de l'épinglage (SNI et nom du certificat), garde « aucune bibliothèque réseau hors `app/net/` » ; vérification sur la pile réelle (refus par smokescreen d'un domaine non autorisé, pas de route directe).

- ADR-013 révisée : chaque secret a sa clé de données AES-256-GCM, enveloppée pour la clé publique X25519 de son usage. L'API du back-office ne détient que les clés publiques : elle écrit les secrets sans pouvoir les lire.
- Migration `0003_vault` : table `secrets`, RLS (un administrateur VOC ne voit pas les secrets du CERT ; les workers lisent et ré-enveloppent mais ne créent ni ne suppriment).
- API : secrets d'espace (`secret.manage`) et globaux (`connector.global.manage`), step-up à chaque écriture, audit sans valeur.
- Exploitation : trousseaux en secrets Docker par worker, `scripts/vault-keygen.sh`, `vault-rotate`, service `vault-admin` (profil `tools`), `.dockerignore` racine.
- Tests : 84 tests backend (cryptographie, liaison des données associées, rotation, isolation VOC/CERT, écriture seule, step-up).

### 2026-10-21 — Session 7 : phase 1, interfaces

- Paquet partagé `@vv/auth` : connexion, vérification et enrôlement MFA (QR code), invitation, mot de passe oublié et réinitialisation (jeton dans le fragment d'URL, effacé de la barre d'adresse), « Mon compte » (mot de passe, MFA, codes de secours, sessions), dialogue de step-up qui rejoue l'action une fois, garde de route, page d'erreur générique (aucun détail technique affiché).
- Back-office : utilisateurs (recherche, pagination, invitation), fiche utilisateur (statut, déverrouillage, réinitialisation MFA, fermeture des sessions, accès VOC/CERT, rôle d'administrateur), espaces, organisations clientes et leurs utilisateurs, journal d'audit (filtres, vérification de la chaîne, export JSON Lines). Navigation masquée selon les permissions ; l'API reste la seule autorité.
- Portail : page des bulletins (en attente de la phase 6), « Mon organisation » pour les référents (rôles, invitations, désactivation), « Mon compte ».
- API portail : la liste des membres de l'organisation expose désormais leur rôle (`OrgUserOut`).
- Images : modules Go de Caddy et smokescreen figés (`go.mod`/`go.sum` commités) après deux échecs CI transitoires de `sum.golang.org` ; manifeste `@vv/auth` ajouté à l'étape SPA de l'image Caddy ; test de fumée de la pile complète vert en local.
- Tests : 16 tests frontend (redirection des anonymes, navigation selon les permissions, refus d'accès, échec de connexion, step-up) ; 60 tests backend.

### 2026-10-21 — Session 6 : phase 1, backend

- Migration `0002_iam` : utilisateurs, rôles globaux, sessions, jetons à usage unique (avec audience), TOTP et codes de secours, espaces VOC/CERT (seed), organisations clientes et appartenances, audit chaîné écrit uniquement via `audit_append` (SECURITY DEFINER), politiques RLS (rôle portail limité au contexte de requête), droits.
- Primitives : AES-256-GCM, HMAC à séparation de domaine, Argon2id, politique de mot de passe (liste SecLists de 10 000 mots de passe courants, motif « mot courant + chiffres »), TOTP avec anti-rejeu.
- API : connexion, MFA (vérification, enrôlement, codes de secours), invitation, mot de passe oublié et réinitialisation, step-up, compte (mot de passe, sessions, codes de secours, désactivation MFA client), administration (utilisateurs, rôles, espaces, clients), organisation (référent client), audit (liste, export JSON Lines, vérification, audit d'espace), CLI `bootstrap-admin`.
- Sécurité : cookies `__Host-`, jeton CSRF dérivé de la session, middleware Origin, limitation Redis, verrouillage progressif, matrice d'autorisation sur six profils.
- Correctif : le test « toute route déclare une politique » ne voyait aucune route depuis la phase 0 (FastAPI 0.142) ; corrigé et durci.


### 2026-10-20 — Session 5 : décisions interactives et phase 0

- Toutes les questions de cadrage posées en interactif ; décisions consignées (OPEN_QUESTIONS.md, ADR-024, ADR-025, ADR-007/008/011/017 acceptées).
- Backend : deux applications ASGI, erreurs RFC 9457, en-têtes de sécurité, identifiant de requête, limite de taille, gestion des erreurs non prévues, marqueurs de politique d'accès et test « aucune route sans politique », Celery (4 files, JSON seul), scheduler élu par verrou consultatif, provisionnement des rôles PostgreSQL sans privilèges, Alembic async + migration de base. 21 tests unitaires/sécurité et 7 tests d'intégration (testcontainers).
- Frontend : workspace pnpm, back-office et portail (React 19, Vite, i18n FR), `SafeHtml` (DOMPurify + Trusted Types), client API généré depuis OpenAPI avec hook CSRF, règle ESLint contre l'injection HTML.
- Déploiement : docker-compose à réseaux cloisonnés, conteneurs durcis, Caddy (CSP stricte, back-office limité aux réseaux internes) et smokescreen compilés avec Go 1.27.2 et `x/net` corrigé, `pip` retiré de l'image backend. Trivy : aucune vulnérabilité HIGH/CRITICAL corrigible. `certifi` monté pour GHSA-6q48-6c7w-9gw2 (exception sécurité à la règle des 14 jours).
- CI : backend, frontend, sécurité (gitleaks, pip-audit, pnpm audit, Semgrep, Trivy) et images (build, scan, smoke test). Actions épinglées par SHA.


### 2026-10-20 — Session 4 : recherche Google pour X

Consigne reçue : « Utilise la recherche Google pour contourner la limitation de X et accéder seulement au strict nécessaire. »

- Principe du strict nécessaire adopté et décrit (spec 07 §2.1, ADR-023) : requêtes sur l'identifiant CVE restreintes à x.com, URL, titre et extrait seulement, 5 posts lus au plus par CVE, jamais de profil ni de timeline, conservation minimale, plafonds.
- Recherche Google évaluée et **non retenue en l'état** : l'API Custom Search JSON n'accepte plus de nouveaux clients et s'arrête le 1er janvier 2027 ; son remplaçant (Vertex AI Search) est payant ; l'interrogation automatisée de google.com est contraire aux conditions de Google. Brave Search API exige une carte bancaire.
- Décision demandée au porteur : Q32 (moteur de découverte des posts X). Hypothèse par défaut : recherche web du moteur IA, sur l'abonnement IA existant.

### 2026-10-20 — Session 3 : contrainte de coût et lecture gratuite de X

Consigne reçue : « Le moteur de lecture sur X doit être gratuit. Aucun abonnement payant en plus de ceux utilisés par l'IA. »

Modifications :
- ADR-023 (acceptée) : zéro abonnement payant hors IA ; classe de coût obligatoire par type de connecteur, avec test bloquant ; X lu par le connecteur `x_reader` (découverte gratuite des URL de posts, recherche web du moteur IA restreinte à x.com, SearXNG en option, lecture par l'oEmbed officiel) ; API X payante, scraping et comptes X exclus.
- ADR-015 révisée (sources gratuites, Reddit en RSS).
- Spec 07 §2 et §2.1, specs 01, 02 et 03 (outils `x_discover` et `x_read`), PLAN (exigence de coût, étapes 2.3, 4.6, 4.9 et nouvelle 4.18 sur l'indicateur de couverture de X), SECURITY (S25 révisé, S26), ARCHITECTURE, CLAUDE.md, OPEN_QUESTIONS (Q7 révisée, Q27 révisée, Q28 à Q31).

### 2026-10-20 — Session 2 : révision du cadrage

Consignes reçues :
1. Le vecteur d'entrée n°1 est la publication d'une nouvelle vulnérabilité sur NVD, qui lance les agents de recherche.
2. Ne pas oublier les connecteurs et le paramétrage des agents de veille.
3. Moteur IA préféré : Claude aujourd'hui, un LLM open source demain.

Modifications :
- Nouvelle spec `docs/specs/07-connectors-ai-engines-nvd.md` : cadre commun des connecteurs (veille, moteurs IA, publication), catalogue des connecteurs de veille, synchronisation NVD et détection des changements, périmètre de veille, moteurs IA (moteur préféré, capacités, paramètres abstraits, compatibilité, politique de données, banc d'évaluation), agents de veille prédéfinis.
- Nouvelles ADR : ADR-020 (NVD vecteur d'entrée n°1), ADR-021 (cadre de connecteurs unifié), ADR-022 (agents de veille spécialisés) ; ADR-011 révisée (moteur IA interchangeable).
- `PLAN.md` : vision révisée ; phase 2 renommée « Socle de veille et vecteur d'entrée NVD » (cadre des connecteurs, synchro NVD, événements, périmètre de veille) ; déclencheurs NVD en phase 3 ; **inversion des phases 4 et 5** : la phase 4 devient « Moteurs IA, connecteurs de veille et agents de veille » (Jalon 1, flux principal de bout en bout), la phase 5 devient « Éditeur visuel ».
- Mises à jour des specs 01 (cve_changes, sync_cursors, watch_scopes, ai_models, préférences de moteur, évaluations, connecteurs unifiés), 02 (déclencheurs `trigger.cve_published`/`trigger.cve_updated`, nœuds `vuln.scope_match` et `vuln.list`, workflows seed), 03 (agents et couche `AIEngine`), 05 (noms de permissions) ; RBAC (permissions des connecteurs, du périmètre et des moteurs IA) ; SECURITY (S21 à S25) ; ARCHITECTURE ; PROCEDURES (ajouter un moteur IA, un connecteur de veille) ; OPEN_QUESTIONS (Q23 à Q27, réponses reçues).

### 2026-10-20 — Session 1 : cadrage

- Dépôt vide au départ, branche `claude/veille-management-tool-845y6h`.
- Analyse du besoin et choix d'architecture : moteur de workflows natif plutôt que n8n embarqué (ADR-004), backend Python/FastAPI, frontend React, deux applications (back-office et portail), PostgreSQL avec RLS, Celery et Redis.
- Documents créés : `CLAUDE.md`, `README.md`, `docs/PLAN.md`, `docs/ARCHITECTURE.md`, `docs/RBAC.md`, `docs/SECURITY.md`, `docs/DECISIONS.md`, `docs/OPEN_QUESTIONS.md`, `docs/PROCEDURES.md`, `docs/specs/01` à `06`.
- Toutes les ADR sont au statut « Proposée », à passer en « Acceptée » après validation.

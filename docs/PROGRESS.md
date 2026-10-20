# PROGRESS — Journal d'avancement

## État courant

- **Phase** : **phase 0 (fondations) terminée** ; prochaine phase : 1 (identité, accès, audit).
- **Dernière étape terminée** : 0.9 (hook SessionStart). Pile complète vérifiée localement (`make up` équivalent, smoke test, filtrage de sortie) ; CI GitHub Actions ajoutée.
- **Étape en cours** : aucune.
- **Prochaine étape** : 1.1 modèles `users`, `sessions`, `auth_tokens`, `user_global_roles` (spec 01 §1), puis 1.2 à 1.12.
- **Points d'attention** :
  - Décisions de cadrage prises le 2026-10-20 (OPEN_QUESTIONS.md) : VOC = admins, vulnérabilités partagées avec qualification par équipe (ADR-024), Gemini palier gratuit (ADR-025), comptes locaux + TOTP, MFA client facultative, admin client délégué, FR + EN, e-mail + PDF.
  - Smokescreen accepte les clients sans rôle (ACL `default`) : prévoir des rôles mTLS par type de worker en phase 2.
  - Environnement cloud : builds Docker uniquement via les variantes avec l'autorité du proxy (PROCEDURES §9 bis).
  - Questions encore ouvertes : Q33 (LLMaaS), Q34 (charte PDF), Q35 (quotas Gemini).

## Journal

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

# PLAN — Vision, périmètre et feuille de route

## 1. Vision

Donner aux analystes vulnérabilités (VOC) et au CERT un outil unique qui :

1. **collecte** automatiquement l'information utile (sources officielles, éditeurs, réseaux sociaux, GitHub, forums) grâce à des workflows et des agents IA ;
2. **pré-mâche** le travail : regroupement par vulnérabilité, enrichissement (CVSS, EPSS, KEV), détection de PoC et d'exploitation, synthèse sourcée ;
3. **accélère la rédaction** de bulletins selon des modèles paramétrables propres à chaque sujet ;
4. **diffuse** les bulletins validés vers les clients (portail) et vers des systèmes tiers (API).

L'humain reste dans la boucle : l'IA propose, l'analyste qualifie, valide et publie.

## 2. Glossaire

| Terme | Définition |
|---|---|
| VOC | Vulnerability Operations Center : équipe des analystes vulnérabilités |
| CERT | Équipe CERT, avec son propre espace cloisonné (agents, workflows, configuration) |
| Espace (workspace) | Périmètre de cloisonnement des données métier (VOC, CERT, d'autres possibles) |
| Vulnérabilité non qualifiée | Vulnérabilité détectée par un workflow (statut `new` ou `triage`) et pas encore évaluée par un analyste |
| Qualification | Décision de l'analyste : pertinente (`qualified`), rejetée, doublon ou en surveillance |
| Élément collecté | Contenu brut récupéré par une source (post, advisory, issue GitHub…), considéré comme non fiable |
| Preuve (evidence) | Élément collecté rattaché à une vulnérabilité (PoC, exploit, correctif, discussion…) |
| Synthèse IA | Dossier structuré produit par un agent pour une vulnérabilité, avec citations des sources |
| Modèle de bulletin | Gabarit paramétrable : champs, consignes de génération, rendu, règles d'application par sujet |
| Draft | Bulletin généré par l'IA, en attente d'édition et de validation |
| Connecteur | Configuration d'envoi vers une API distante (URL, authentification, mapping des champs) |
| Techno | Entrée du catalogue des technologies (éditeur et produit, CPE/purl, alias) |
| TLP | Traffic Light Protocol 2.0 : marquage de diffusion des bulletins |

## 3. Profils (résumé, détail dans RBAC.md)

| Profil | Ce qu'il fait |
|---|---|
| **Admin plateforme** | Gère les utilisateurs, rôles, espaces, organisations clientes et paramètres de sécurité globaux. Rôle cumulable, attribuable à des analystes VOC. |
| **Analyste VOC** | Voit les vulnérabilités non qualifiées de l'espace VOC, les qualifie, édite les workflows, agents et configuration VOC, demande des drafts, édite, valide, publie et pousse via API. |
| **Analyste CERT** | Mêmes capacités que l'analyste VOC, dans l'espace CERT uniquement, sans la partie admin plateforme. Gère ses propres agents et sa configuration. |
| **Client** | Voit uniquement les bulletins publiés qui lui sont destinés. Plus tard : abonnement à des technos et demande d'ajout d'une techno absente. |

## 4. Périmètre fonctionnel

### 4.1 MVP (phases 0 à 8)

- Authentification sécurisée : mot de passe, MFA TOTP obligatoire en interne, sessions, invitations.
- RBAC multi-espace (VOC/CERT) et organisations clientes, journal d'audit.
- Catalogue CVE public (NVD, CISA KEV, EPSS) et catalogue des technos.
- Gestion des vulnérabilités : file des non qualifiées, qualification, assignation, preuves, synthèse IA, historique.
- Moteur de workflows natif : déclencheurs, nœuds de collecte, transformation, IA, vulnérabilités, bulletins, sortie ; versions, exécutions, journaux.
- Éditeur visuel de workflows (canvas type n8n), formulaires de paramètres, test d'un nœud, visualisation des exécutions.
- Agents IA configurables par espace : fournisseur, modèle, prompt, outils autorisés, limites et budgets.
- Modèles de bulletins paramétrables par sujet, demande unitaire de draft, édition, relecture, validation, publication.
- Connecteur HTTP générique pour pousser les bulletins vers des API distantes (mapping configurable, dry-run, journal).
- Portail client : liste, recherche et détail des bulletins publiés.

### 4.2 Après MVP

- Abonnements clients par techno et notifications filtrées (phase 9, modèle de données prêt dès la phase 2).
- Demande d'ajout de techno par un client et circuit de modération (phase 9).
- SSO OIDC (Entra ID, Keycloak), WebAuthn/passkeys, export PDF, CSAF/STIX, connecteurs prédéfinis (MISP, OpenCTI, TheHive, Jira…), flux RSS/Atom client, navigateur headless isolé pour les sites JavaScript.

### 4.3 Hors périmètre (sauf décision contraire)

- Exécution de code arbitraire dans les workflows (nœud « Code »).
- Publication automatique vers les clients sans validation humaine.
- Inscription libre des clients (comptes créés uniquement sur invitation).

## 5. Exigences non fonctionnelles

| Domaine | Exigence |
|---|---|
| Sécurité | OWASP ASVS 5.0 niveau 2 (niveau 3 visé pour l'authentification, les sessions et la cryptographie), OWASP Top 10, API Security Top 10, Top 10 LLM 2025, recommandations ANSSI (MFA, IA générative). Détail dans SECURITY.md. |
| Cloisonnement | Isolation stricte VOC/CERT et entre clients, appliquée par le code et par la RLS PostgreSQL. |
| Traçabilité | Journal d'audit inaltérable (chaîne de hachage) pour les actions sensibles ; provenance de chaque information produite par l'IA. |
| Fiabilité | Exécutions de workflows reprises après crash, retries, timeouts, idempotence. |
| Volumétrie cible (hypothèse) | Moins de 100 utilisateurs internes, moins de 1 000 utilisateurs clients, environ 10 000 éléments collectés par jour. |
| Disponibilité | Instance unique avec sauvegardes chiffrées et restauration testée (haute disponibilité hors MVP). |
| Exploitabilité | Déploiement Docker Compose, configuration par variables d'environnement, métriques et logs structurés. |
| Langue | Interface en français, i18n prête ; bulletins multilingues selon le modèle. |

## 6. Feuille de route

Chaque étape se termine par du code testé, poussé, et une mise à jour de PROGRESS.md. La sécurité est traitée à chaque phase, pas seulement en phase 10. On ne coche une case que si la Definition of Done de PROCEDURES.md est remplie.

### Phase 0 — Fondations

- [ ] 0.1 Arborescence du monorepo, `.gitignore`, `.editorconfig`, `Makefile`, `.env.example`
- [ ] 0.2 Backend : projet `uv`, deux applications ASGI (`main_backoffice`, `main_portal`), configuration via pydantic-settings, endpoint `/healthz`, logs structlog JSON, middleware d'en-têtes de sécurité, gestion d'erreurs RFC 9457
- [ ] 0.3 Base de données : SQLAlchemy async, Alembic, modèle de base (UUIDv7, horodatages), rôles PostgreSQL (`vv_migrator`, `vv_app`, `vv_portal`, `vv_worker`)
- [ ] 0.4 Celery (worker et files `default`, `collect`, `ai`, `publish`) et squelette du scheduler
- [ ] 0.5 Frontend : workspace pnpm, `apps/backoffice`, `apps/portal`, `packages/ui`, `packages/api-client` (client généré depuis OpenAPI), ESLint, Prettier, Vitest
- [ ] 0.6 Docker : Dockerfiles multi-étapes non-root, `deploy/docker-compose.yml` (Caddy, API back-office, API portail, workers, scheduler, PostgreSQL, Redis, smokescreen, Mailpit en dev)
- [ ] 0.7 Qualité : ruff, mypy strict, pytest avec testcontainers, pre-commit (gitleaks, ruff, prettier)
- [ ] 0.8 CI GitHub Actions : lint, typage, tests, pip-audit, pnpm audit, gitleaks, Semgrep, Trivy, build des images (actions épinglées par SHA)
- [ ] 0.9 Hook SessionStart Claude Code (installation des dépendances) pour reprendre rapidement dans un nouveau conteneur

**Critère de sortie** : `make dev` démarre la pile complète, `make lint test` est vert en local et en CI, `/healthz` répond sur les deux applications avec les en-têtes de sécurité.

### Phase 1 — Identité, accès et audit

- [ ] 1.1 Modèles `users`, `sessions`, `invitations`, `password_reset_tokens`, `user_global_roles`
- [ ] 1.2 Hachage Argon2id, politique de mots de passe (longueur minimale, liste de mots de passe compromis hors ligne)
- [ ] 1.3 Connexion et déconnexion, sessions côté serveur (cookie `__Host-`, expirations d'inactivité et absolue, rotation), audience de session (back-office ou portail)
- [ ] 1.4 MFA TOTP : enrôlement, vérification, anti-rejeu, codes de secours ; obligatoire pour les comptes internes
- [ ] 1.5 Protection CSRF (jeton lié à la session et vérification de l'Origin), limitation de débit (Redis), verrouillage progressif, messages génériques (pas d'énumération de comptes)
- [ ] 1.6 RBAC : registre des permissions, dépendance `require_permission`, test qui échoue si une route n'a pas de permission, matrice de tests d'autorisation
- [ ] 1.7 Espaces (`workspaces`, `workspace_memberships`), RLS PostgreSQL et injection du périmètre par transaction
- [ ] 1.8 Organisations clientes et comptes clients (invitation uniquement)
- [ ] 1.9 Journal d'audit append-only avec chaîne de hachage, export JSON
- [ ] 1.10 CLI de bootstrap du premier admin (aucun compte par défaut)
- [ ] 1.11 Interfaces : connexion et MFA (back-office et portail), « Mon compte » (mot de passe, MFA, sessions actives), administration des utilisateurs, espaces et clients, consultation de l'audit
- [ ] 1.12 Ré-authentification (step-up MFA) pour les actions sensibles

**Critère de sortie** : un admin invite un analyste VOC, un analyste CERT et un client ; chacun ne voit que son périmètre ; la matrice d'autorisation est entièrement testée.

### Phase 2 — Socle de données de veille

- [ ] 2.1 Coffre de secrets : chiffrement d'enveloppe AES-256-GCM, clés par usage, API en écriture seule, CLI de rotation
- [ ] 2.2 `SafeHttpClient` anti-SSRF (résolution DNS et blocage des plages internes, épinglage d'IP, redirections revalidées, limites de taille et de temps) et proxy smokescreen, avec sa suite de tests SSRF
- [ ] 2.3 Catalogue CVE global : synchronisation NVD API 2.0, CISA KEV, FIRST EPSS (tâches planifiées, incrémentales)
- [ ] 2.4 Catalogue des technos : CRUD, alias, préfixes CPE, purl, recherche approchée, import depuis le dictionnaire CPE
- [ ] 2.5 Éléments collectés (`collected_items`) avec déduplication et marquage « non fiable »
- [ ] 2.6 Vulnérabilités : modèle, statuts, file des non qualifiées, qualification, assignation, commentaires, historique, rattachement aux technos
- [ ] 2.7 Preuves et synthèses IA rattachées aux vulnérabilités (modèle et API ; la génération vient en phase 5)
- [ ] 2.8 Sources de veille de l'espace (catalogue de flux et de comptes à suivre, avec tags)
- [ ] 2.9 Interfaces : liste des vulnérabilités (filtres, tri, assignation), fiche vulnérabilité (enrichissement, preuves, chronologie, actions de qualification), catalogue des technos, sources

**Critère de sortie** : un analyste VOC qualifie une vulnérabilité créée à la main, enrichie par le catalogue CVE ; l'analyste CERT ne la voit pas.

### Phase 3 — Moteur de workflows

- [ ] 3.1 Modèles `workflows`, `workflow_versions` (immuables), `workflow_triggers`, `workflow_runs`, `node_runs`, `workflow_approvals`
- [ ] 3.2 Schéma JSON du graphe (v1) et validation : acyclicité, ports, paramètres, permissions, références de secrets et connecteurs du même espace
- [ ] 3.3 Registre des types de nœuds, avec export du JSON Schema des paramètres via l'API
- [ ] 3.4 Exécuteur : orchestration du DAG, tâches Celery par nœud, retries, timeouts, idempotence, annulation, reprise après crash
- [ ] 3.5 Expressions JMESPath dans les paramètres, gabarits Liquid pour les chaînes
- [ ] 3.6 Scheduler (cron, intervalle minimal configurable), déclencheurs manuel, événement (outbox) et webhook signé HMAC
- [ ] 3.7 Nœuds de base : déclencheurs, `source.rss`, `source.nvd`, `source.cisa_kev`, `source.github_advisories`, `source.github_search`, `source.stackexchange`, `source.http`, `transform.filter`, `transform.map`, `transform.dedupe`, `transform.extract_cve`, `transform.merge`, `transform.limit`, `vuln.upsert`, `vuln.enrich`, `vuln.match_technologies`, `control.if`, `control.approval`, `notify.email`
- [ ] 3.8 Limites : nœuds par workflow, éléments par sortie, taille par élément, durée d'exécution, concurrence par espace
- [ ] 3.9 API : CRUD, versions, publication d'une version, lancement, annulation, exécutions et journaux, import/export JSON
- [ ] 3.10 Workflow d'exemple « Veille quotidienne » livré en seed (désactivé par défaut)

**Critère de sortie** : le workflow « Veille quotidienne », défini en JSON, crée des vulnérabilités non qualifiées dédupliquées et enrichies, sur planification, avec journal par nœud.

### Phase 4 — Éditeur visuel de workflows

- [ ] 4.1 Canvas React Flow : palette de nœuds issue du registre, glisser-déposer, connexions validées par type de port
- [ ] 4.2 Panneau de paramètres généré depuis le JSON Schema, avec sélecteurs de secrets, connecteurs et agents
- [ ] 4.3 Éditeur d'expressions (CodeMirror 6) avec aide JMESPath et aperçu sur des données d'exemple
- [ ] 4.4 Exécution d'un nœud en test avec données épinglées, mode dry-run pour les nœuds de sortie
- [ ] 4.5 Visualisation des exécutions : statut par nœud, entrées, sorties, erreurs, durées, coûts
- [ ] 4.6 Gestion des versions : brouillon, publication, historique, diff, restauration ; import/export
- [ ] 4.7 Verrou d'édition optimiste (détection d'édition concurrente)

**Critère de sortie** : un analyste construit, teste et publie le workflow « Veille quotidienne » entièrement depuis l'interface.

### Phase 5 — Agents IA

- [ ] 5.1 Abstraction `LLMProvider` ; adaptateur Anthropic (SDK officiel, sorties structurées, cache de prompt, streaming, gestion du stop reason `refusal` et fallback serveur) ; adaptateur compatible OpenAI pour Mistral, Azure OpenAI, vLLM ou Ollama
- [ ] 5.2 Fournisseurs LLM par espace (secret, modèles autorisés, politique de données)
- [ ] 5.3 Agents : configuration versionnée (modèle, effort, prompt système, outils, liste de domaines autorisés, schéma de sortie, limites)
- [ ] 5.4 Runtime d'agent : boucle d'outils avec hooks (autorisation, budget, journalisation), timeouts, limites de tours
- [ ] 5.5 Outils en lecture seule : `web_fetch` (via SafeHttpClient), `github_search`, `nvd_lookup`, `epss_lookup`, `kev_lookup`, `osv_lookup`, `stackexchange_search`, `x_search`, `internal_vuln_search`
- [ ] 5.6 Garde-fous anti-injection de prompt : isolation du contenu non fiable, validation des sorties, citations obligatoires, détection heuristique signalée à l'analyste
- [ ] 5.7 Comptabilité des tokens et des coûts, budgets mensuels par espace avec arrêt dur
- [ ] 5.8 Nœuds `ai.agent`, `ai.summarize`, `ai.classify`, `ai.extract`, `ai.relevance` ; source `source.x` (API payante, désactivée sans identifiants)
- [ ] 5.9 Workflow d'exemple « Investigation CVE » produisant une synthèse IA sourcée
- [ ] 5.10 Interfaces : fournisseurs, agents (édition, test interactif), traces d'exécution d'agent, tableau de bord des coûts
- [ ] 5.11 Corpus de tests d'injection de prompt (contenus collectés piégés) intégré à la CI

**Critère de sortie** : à la création d'une vulnérabilité, l'agent produit une synthèse structurée et sourcée ; un contenu piégé ne déclenche aucune action non prévue.

### Phase 6 — Modèles de bulletins et drafts

- [ ] 6.1 Modèles versionnés : champs typés, consignes IA par champ, gabarit de rendu Liquid, guide de style, exemple, langue
- [ ] 6.2 Règles de sélection par sujet (techno, éditeur, catégorie, sévérité, KEV…) avec priorités
- [ ] 6.3 Éditeur de modèle avec aperçu calculé côté serveur sur une vulnérabilité réelle
- [ ] 6.4 Demande unitaire de draft (depuis une vulnérabilité, un CVE, des URL ou un texte libre), exécution asynchrone, progression en SSE
- [ ] 6.5 Génération par sortie structurée, puis rendu déterministe ; Markdown assaini en HTML
- [ ] 6.6 Cycle de vie : `draft`, `in_review`, `approved`, `published`, `withdrawn` ; révisions et diff ; double validation configurable
- [ ] 6.7 Marquage TLP, audience (tous les clients ou une sélection), technos associées
- [ ] 6.8 Nœud `bulletin.generate_draft` pour les workflows
- [ ] 6.9 Interfaces : bibliothèque de modèles, demande de draft, éditeur de bulletin (champs et aperçu), relecture et validation

**Critère de sortie** : un analyste demande un draft sur une CVE, le modèle adapté au sujet est appliqué, il l'édite, un second analyste valide, le bulletin est publié.

### Phase 7 — Connecteurs de publication API

- [ ] 7.1 Connecteur HTTP générique : URL, méthode, en-têtes, authentification (aucune, clé API, bearer, basic, OAuth2 client credentials, mTLS, signature HMAC)
- [ ] 7.2 Mapping déclaratif du payload (constantes, chemins JMESPath, gabarits Liquid, tables de correspondance)
- [ ] 7.3 Dry-run (aperçu de la requête, secrets masqués), test sur un serveur d'écho, critères de succès, extraction de l'identifiant distant
- [ ] 7.4 Création ou mise à jour (identifiant distant mémorisé), clé d'idempotence, retries avec backoff, limitation de débit
- [ ] 7.5 Journal des publications (requête expurgée, statut, extrait de réponse)
- [ ] 7.6 Réseau privé autorisé uniquement par décision admin, tracée dans l'audit
- [ ] 7.7 Export CSAF 2.0 et Markdown/JSON
- [ ] 7.8 Nœud `publish.api` (avec approbation obligatoire) et action « Pousser » sur un bulletin
- [ ] 7.9 Interfaces : liste et édition des connecteurs, éditeur de mapping avec aperçu, historique des envois

**Critère de sortie** : sans connaître l'API cible à l'avance, un analyste configure un connecteur depuis l'interface et pousse un bulletin validé, avec un journal complet.

### Phase 8 — Portail client

- [ ] 8.1 Application portail séparée (bundle distinct, aucun code back-office), connexion, MFA (selon la décision)
- [ ] 8.2 Vue PostgreSQL `portal_bulletins_v` et rôle `vv_portal` limité à cette vue et aux tables portail
- [ ] 8.3 Liste, recherche, filtres (techno, sévérité, date) et détail des bulletins publiés destinés à l'organisation
- [ ] 8.4 Export Markdown et HTML, impression
- [ ] 8.5 Tests de non-fuite : aucun champ interne, aucune vulnérabilité non publiée, aucune donnée d'une autre organisation

**Critère de sortie** : un client consulte les bulletins qui lui sont destinés, et les tests prouvent qu'il ne peut rien voir d'autre.

### Phase 9 — Abonnements et demandes de technos (fonctionnalité à venir)

- [ ] 9.1 Abonnements par organisation ou par utilisateur à des technos (sévérité minimale, canaux)
- [ ] 9.2 Notifications filtrées (e-mail, puis autres canaux) et vue « Mes technos » dans le portail
- [ ] 9.3 Demande de techno absente : recherche approchée préalable (éviter les doublons), formulaire, limitation de débit
- [ ] 9.4 Modération : file des demandes, approbation (création de la techno et abonnement automatique du demandeur), rejet motivé, fusion avec une techno existante
- [ ] 9.5 Confidentialité : les abonnements d'un client révèlent son parc, ils ne sont visibles que de cette organisation et des rôles autorisés

### Phase 10 — Durcissement et mise en production (en continu, puis finalisation)

- [ ] 10.1 DAST (OWASP ZAP baseline en CI), fuzzing de l'API depuis OpenAPI (schemathesis)
- [ ] 10.2 WebAuthn/passkeys, SSO OIDC optionnel
- [ ] 10.3 Sauvegardes chiffrées, restauration testée, rotation des clés documentée
- [ ] 10.4 Observabilité : métriques (Prometheus), traces OpenTelemetry, alertes (échecs de workflows, budget LLM, échecs de connexion)
- [ ] 10.5 Documentation d'exploitation (installation, mise à jour, réponse à incident, procédure d'urgence)
- [ ] 10.6 Revue de sécurité complète et test d'intrusion externe avant l'ouverture du portail sur Internet

# PLAN — Vision, périmètre et feuille de route

## 1. Vision

Donner aux analystes vulnérabilités (VOC) et au CERT un outil unique qui :

1. **détecte chaque nouvelle CVE publiée sur NVD** : c'est le **vecteur d'entrée n°1**, qui déclenche automatiquement les agents de veille ;
2. **fait chercher les agents IA** sur X, GitHub, Stack Overflow, les avis éditeurs et les flux, pour trouver PoC, exploitation, correctifs et discussions ;
3. **pré-mâche** le travail : vulnérabilité non qualifiée créée, enrichie (CVSS, EPSS, KEV, technos) et accompagnée d'une synthèse sourcée ;
4. **accélère la rédaction** de bulletins selon des modèles paramétrables propres à chaque sujet ;
5. **diffuse** les bulletins validés vers les clients (portail) et vers des systèmes tiers (API).

Le moteur IA est **interchangeable** : Claude est le moteur préféré aujourd'hui, et un LLM open source auto-hébergé pourra le remplacer demain par simple configuration.

L'humain reste dans la boucle : l'IA propose, l'analyste qualifie, valide et publie.

## 2. Glossaire

| Terme | Définition |
|---|---|
| VOC | Vulnerability Operations Center : équipe des analystes vulnérabilités |
| CERT | Équipe CERT, avec son propre espace cloisonné (agents, workflows, configuration) |
| Espace (workspace) | Périmètre de cloisonnement des données métier (VOC, CERT, d'autres possibles) |
| Vecteur d'entrée NVD | Publication d'une nouvelle CVE sur NVD, détectée par la synchronisation et transformée en événement `cve.published` qui lance les workflows |
| Périmètre de veille | Règles d'un espace (technos suivies, mots-clés, seuils CVSS, KEV…) qui décident si une nouvelle CVE mérite une investigation |
| Vulnérabilité non qualifiée | Vulnérabilité créée par un workflow (statut `new` ou `triage`) et pas encore évaluée par un analyste |
| Qualification | Décision de l'analyste : pertinente (`qualified`), rejetée, doublon ou en surveillance |
| Connecteur | Configuration d'accès à un service externe. Trois familles : **veille** (NVD, GitHub, X…), **moteur IA** (Claude, LLM open source), **publication** (API distantes) |
| Moteur IA préféré | Moteur et modèle utilisés par défaut par les agents (plateforme, surchargeable par espace et par agent) |
| Agent de veille | Agent IA spécialisé (PoC GitHub, réseaux sociaux, forums, avis éditeurs, synthèse…) configurable par espace |
| Élément collecté | Contenu brut récupéré par une source (post, advisory, issue GitHub…), considéré comme non fiable |
| Preuve (evidence) | Élément collecté rattaché à une vulnérabilité (PoC, exploit, correctif, discussion…) |
| Synthèse IA | Dossier structuré produit par les agents pour une vulnérabilité, avec citations des sources |
| Modèle de bulletin | Gabarit paramétrable : champs, consignes de génération, rendu, règles d'application par sujet |
| Draft | Bulletin généré par l'IA, en attente d'édition et de validation |
| Techno | Entrée du catalogue des technologies (éditeur et produit, CPE/purl, alias) |
| TLP | Traffic Light Protocol 2.0 : marquage de diffusion des bulletins |

## 3. Profils (résumé, détail dans RBAC.md)

| Profil | Ce qu'il fait |
|---|---|
| **Admin plateforme** | Gère les utilisateurs, rôles, espaces, organisations clientes, connecteurs globaux (NVD, KEV, EPSS), moteur IA préféré de la plateforme et paramètres de sécurité. Rôle cumulable, attribuable à des analystes VOC. |
| **Analyste VOC** | Voit les vulnérabilités non qualifiées de l'espace VOC, les qualifie, paramètre le périmètre de veille, les connecteurs de veille, les agents et les workflows VOC, demande des drafts, édite, valide, publie et pousse via API. |
| **Analyste CERT** | Mêmes capacités que l'analyste VOC, dans l'espace CERT uniquement, sans la partie admin plateforme. Gère ses propres agents, connecteurs et configuration. |
| **Client** | Voit uniquement les bulletins publiés qui lui sont destinés. Plus tard : abonnement à des technos et demande d'ajout d'une techno absente. |

## 4. Périmètre fonctionnel

### 4.1 MVP (phases 0 à 8)

- **Flux principal** : nouvelle CVE sur NVD → filtrage par le périmètre de veille de chaque espace → vulnérabilité non qualifiée enrichie → agents de veille → synthèse sourcée → qualification par l'analyste. Une saisie manuelle (CVE ou vulnérabilité sans CVE) emprunte le même chemin.
- Authentification sécurisée : mot de passe, MFA TOTP obligatoire en interne, sessions, invitations.
- RBAC multi-espace (VOC/CERT) et organisations clientes, journal d'audit.
- **Connecteurs** paramétrables depuis l'interface, **tous gratuits** : veille (NVD, KEV, EPSS, GitHub, X en lecture gratuite, Stack Exchange, Mastodon, Bluesky, Reddit en RSS, Hacker News, RSS, web), moteurs IA, publication ; test de connexion, quotas, budgets, état de santé.
- **Moteur IA interchangeable** : démarrage sur le palier gratuit Gemini (budget 0 €), puis LLMaaS compatible OpenAI, Claude via l'API si un budget apparaît ; moteur préféré par plateforme, par espace et par agent ; banc d'évaluation facultatif.
- **Agents de veille paramétrables** par espace : moteur, modèle, niveau de raisonnement, prompt, connecteurs autorisés, domaines, schéma de sortie, limites et budgets ; agents prédéfinis fournis.
- Gestion des vulnérabilités : file des non qualifiées, qualification, assignation, preuves, synthèse IA, historique, re-veille périodique (nouveaux PoC, ajout au KEV).
- Moteur de workflows natif, puis éditeur visuel (canvas type n8n).
- Modèles de bulletins paramétrables par sujet, demande unitaire de draft, édition, relecture, validation, publication.
- Connecteur HTTP générique pour pousser les bulletins vers des API distantes.
- Portail client : liste, recherche et détail des bulletins publiés.

### 4.2 Après MVP

- Abonnements clients par techno et notifications filtrées (phase 9, modèle de données prêt dès la phase 2).
- Demande d'ajout de techno par un client et circuit de modération (phase 9).
- SSO OIDC, WebAuthn/passkeys, export PDF, STIX, connecteurs de publication prédéfinis (MISP, OpenCTI, TheHive, Jira…), flux RSS/Atom client, navigateur headless isolé.

### 4.3 Hors périmètre (sauf décision contraire)

- Exécution de code arbitraire dans les workflows (nœud « Code »), ou exécution de PoC récupérés.
- Publication automatique vers les clients sans validation humaine.
- Inscription libre des clients (comptes créés uniquement sur invitation).

## 5. Exigences non fonctionnelles

| Domaine | Exigence |
|---|---|
| Sécurité | OWASP ASVS 5.0 niveau 2 (niveau 3 visé pour l'authentification, les sessions et la cryptographie), OWASP Top 10, API Security Top 10, Top 10 LLM 2025, recommandations ANSSI (MFA, IA générative). Détail dans SECURITY.md. |
| Cloisonnement | Isolation stricte VOC/CERT et entre clients, appliquée par le code et par la RLS PostgreSQL. |
| Traçabilité | Journal d'audit inaltérable (chaîne de hachage) pour les actions sensibles ; provenance de chaque information produite par l'IA. |
| Fiabilité | Exécutions de workflows reprises après crash, retries, timeouts, idempotence ; synchronisation NVD reprise sur curseur, sans trou ni doublon. |
| Réactivité | Délai entre publication sur NVD et vulnérabilité visible, synthèse comprise : de l'ordre de l'intervalle de synchronisation NVD (2 h par défaut, recommandation NVD) plus quelques minutes d'investigation. Voir Q24 pour réduire ce délai. |
| Portabilité IA | Changer de moteur IA ne demande aucune modification de code ; prompts et schémas sont indépendants du fournisseur. |
| **Coûts** | **Aucun abonnement ni service payant en dehors de l'abonnement IA** (ADR-023) : connecteurs gratuits (clé ou compte gratuits au plus), composants open source, pas de SaaS payant (monitoring, e-mail, recherche…). Les seuls coûts variables passent par la facture IA et sont plafonnés par des budgets. |
| Volumétrie cible (Q13) | 20 à 100 analystes, jusqu'à 1 000 utilisateurs clients, environ 130 nouvelles CVE par jour, environ 10 000 éléments collectés par jour ; rétention de 3 ans minimum (Q17). |
| Disponibilité | Instance unique avec sauvegardes chiffrées et restauration testée (haute disponibilité hors MVP). |
| Exploitabilité | Déploiement Docker Compose, configuration par variables d'environnement, métriques et logs structurés. |
| Langue | Interface en français, i18n prête ; bulletins multilingues selon le modèle. |

## 6. Feuille de route

Chaque étape se termine par du code testé, poussé, et une mise à jour de PROGRESS.md. La sécurité est traitée à chaque phase. On ne coche une case que si la Definition of Done de PROCEDURES.md est remplie.

**Jalon 1 (fin de la phase 4)** : le flux principal fonctionne de bout en bout (nouvelle CVE NVD → vulnérabilité non qualifiée → agents de veille → synthèse sourcée), avec des workflows livrés en JSON. L'éditeur visuel arrive ensuite (phase 5), pour apporter de la valeur aux analystes au plus tôt.

### Phase 0 — Fondations

- [x] 0.1 Arborescence du monorepo, `.gitignore`, `.editorconfig`, `Makefile`, `.env.example`
- [x] 0.2 Backend : projet `uv`, deux applications ASGI (`main_backoffice`, `main_portal`), configuration via pydantic-settings, endpoint `/healthz`, logs structlog JSON, middleware d'en-têtes de sécurité, gestion d'erreurs RFC 9457
- [x] 0.3 Base de données : SQLAlchemy async, Alembic, modèle de base (UUIDv7, horodatages), rôles PostgreSQL (`vv_migrator`, `vv_app`, `vv_portal`, `vv_worker`)
- [x] 0.4 Celery (worker et files `default`, `collect`, `ai`, `publish`) et squelette du scheduler
- [x] 0.5 Frontend : workspace pnpm, `apps/backoffice`, `apps/portal`, `packages/ui`, `packages/api-client` (client généré depuis OpenAPI), ESLint, Prettier, Vitest
- [x] 0.6 Docker : Dockerfiles multi-étapes non-root, `deploy/docker-compose.yml` (Caddy, API back-office, API portail, workers, scheduler, PostgreSQL, Redis, smokescreen, Mailpit en dev)
- [x] 0.7 Qualité : ruff, mypy strict, pytest avec testcontainers, pre-commit (gitleaks, ruff, prettier)
- [x] 0.8 CI GitHub Actions : lint, typage, tests, pip-audit, pnpm audit, gitleaks, Semgrep, Trivy, build des images (actions épinglées par SHA)
- [x] 0.9 Hook SessionStart Claude Code (installation des dépendances) pour reprendre rapidement dans un nouveau conteneur

**Critère de sortie** : `make dev` démarre la pile complète, `make lint test` est vert en local et en CI, `/healthz` répond sur les deux applications avec les en-têtes de sécurité.

### Phase 1 — Identité, accès et audit

- [x] 1.1 Modèles `users`, `sessions`, `auth_tokens`, `user_global_roles`
- [x] 1.2 Hachage Argon2id, politique de mots de passe (longueur minimale, liste de mots de passe compromis hors ligne)
- [x] 1.3 Connexion et déconnexion, sessions côté serveur (cookie `__Host-`, expirations d'inactivité et absolue, rotation), audience de session (back-office ou portail)
- [x] 1.4 MFA TOTP : enrôlement, vérification, anti-rejeu, codes de secours ; obligatoire pour les comptes internes
- [x] 1.5 Protection CSRF (jeton lié à la session et vérification de l'Origin), limitation de débit (Redis), verrouillage progressif, messages génériques (pas d'énumération de comptes)
- [x] 1.6 RBAC : registre des permissions, dépendance `require_permission`, test qui échoue si une route n'a pas de permission, matrice de tests d'autorisation
- [x] 1.7 Espaces (`workspaces`, `workspace_memberships`), RLS PostgreSQL et injection du périmètre par transaction
- [x] 1.8 Organisations clientes et comptes clients (invitation uniquement)
- [x] 1.9 Journal d'audit append-only avec chaîne de hachage, export JSON
- [x] 1.10 CLI de bootstrap du premier admin (aucun compte par défaut)
- [x] 1.11 Interfaces : connexion et MFA (back-office et portail), « Mon compte » (mot de passe, MFA, sessions actives), administration des utilisateurs, espaces et clients, consultation de l'audit
- [x] 1.12 Ré-authentification (step-up MFA) pour les actions sensibles

**Critère de sortie** : un admin invite un analyste VOC, un analyste CERT et un client ; chacun ne voit que son périmètre ; la matrice d'autorisation est entièrement testée.

### Phase 2 — Socle de veille et vecteur d'entrée NVD

- [x] 2.1 Coffre de secrets : chiffrement d'enveloppe AES-256-GCM, clés par usage, API en écriture seule, CLI de rotation
- [x] 2.2 `SafeHttpClient` anti-SSRF (résolution DNS et blocage des plages internes, épinglage d'IP, redirections revalidées, limites de taille et de temps) et proxy smokescreen, avec sa suite de tests SSRF
- [x] 2.3 Cadre commun des connecteurs (spec 07) : modèle unifié (familles veille, moteur IA, publication ; portée globale ou espace), références de secrets, « Tester la connexion », état de santé, quotas, curseurs de synchronisation, domaines de sortie déclarés, classe de coût (test bloquant : aucun type payant)
- [x] 2.4 **Connecteur NVD (global)** : synchronisation incrémentale (`lastModStartDate`/`lastModEndDate`, pagination, pauses, backoff), curseur avec recouvrement, rattrapage initial par fenêtres de 120 jours **sans** émettre d'événements, intervalle configurable (2 h par défaut)
- [x] 2.5 Détection des nouveautés et changements NVD : `cve.published` (nouvelle CVE), `cve.updated` avec types de changement (CVSS ajouté ou modifié, CPE ajoutées, entrée KEV, référence d'exploit, rejet), écrits dans l'outbox et historisés (`cve_changes`)
- [x] 2.6 Connecteurs globaux CISA KEV et FIRST EPSS (tâches planifiées) et **CVE.org** (cvelistV5, détection précoce, Q24)
- [x] 2.7 Catalogue des technos : CRUD, alias, préfixes CPE, purl, recherche approchée, import depuis le dictionnaire CPE
- [x] 2.8 Périmètre de veille par espace : technos suivies, éditeurs et mots-clés, seuil CVSS, KEV toujours inclus, filtres CWE, mode « toutes les CVE » ou « filtré »
- [x] 2.9 Éléments collectés (`collected_items`) avec déduplication et marquage « non fiable »
- [x] 2.10 Vulnérabilités : modèle, statuts, file des non qualifiées, qualification, assignation, commentaires, historique, rattachement aux technos ; création manuelle à partir d'un identifiant CVE
- [x] 2.11 Preuves et synthèses IA rattachées aux vulnérabilités (modèle et API ; la génération vient en phase 4)
- [x] 2.12 Sources de veille de l'espace (catalogue de flux et de comptes à suivre, avec tags)
- [x] 2.13 Interfaces : connecteurs (liste, configuration, test, santé), catalogue CVE (nouveautés NVD, recherche, bouton « Promouvoir en vulnérabilité »), périmètre de veille, liste des vulnérabilités (filtres, tri, assignation), fiche vulnérabilité (enrichissement, preuves, chronologie, actions), catalogue des technos, sources

**Critère de sortie** : une CVE réellement publiée sur NVD apparaît dans le catalogue après la synchronisation, avec son événement `cve.published` ; un analyste VOC la promeut et la qualifie ; l'analyste CERT voit la fiche et la qualification du VOC et peut la reprendre, mais ne voit ni les commentaires, ni le périmètre, ni les sources, connecteurs et secrets du VOC (critère aligné sur ADR-024 : fiches partagées, qualification par équipe).

### Phase 3 — Moteur de workflows

- [x] 3.1 Modèles `workflows`, `workflow_versions` (immuables), `workflow_triggers`, `workflow_runs`, `node_runs`, `workflow_approvals`
- [x] 3.2 Schéma JSON du graphe (v1) et validation : acyclicité, ports, paramètres, permissions, références de secrets et de connecteurs du même espace
- [x] 3.3 Registre des types de nœuds, avec export du JSON Schema des paramètres via l'API
- [x] 3.4 Exécuteur : orchestration du DAG, tâches Celery par nœud, retries, timeouts, idempotence, annulation, reprise après crash
- [x] 3.5 Expressions JMESPath dans les paramètres, gabarits Liquid pour les chaînes
- [x] 3.6 Scheduler (cron, intervalle minimal configurable), déclencheurs manuel, événement (outbox) et webhook signé HMAC
- [x] 3.7 **Déclencheurs `trigger.cve_published` et `trigger.cve_updated`** : diffusion des événements NVD globaux vers chaque espace qui a un workflow actif abonné, avec filtre et débit borné
- [x] 3.8 Nœuds de base : `source.rss`, `source.nvd`, `source.cisa_kev`, `source.github_advisories`, `source.http`, `transform.filter`, `transform.map`, `transform.dedupe`, `transform.extract_cve`, `transform.merge`, `transform.limit`, `vuln.scope_match`, `vuln.upsert`, `vuln.enrich`, `vuln.match_technologies`, `vuln.list`, `control.if`, `control.approval`, `notify.email`
- [x] 3.9 Limites : nœuds par workflow, éléments par sortie, taille par élément, durée d'exécution, concurrence par espace
- [x] 3.10 API : CRUD, versions, publication d'une version, lancement, annulation, exécutions et journaux, import/export JSON
- [x] 3.11 Workflows livrés en seed par espace (désactivés par défaut) : « Nouvelle CVE NVD » (version sans IA : périmètre, création, enrichissement, technos, notification) et « Veille quotidienne » (flux RSS et avis)

**Critère de sortie** : une nouvelle CVE NVD crée automatiquement, dans chaque espace dont le périmètre correspond, une vulnérabilité non qualifiée enrichie, via le workflow seed, avec un journal par nœud ; une CVE hors périmètre devient éligible quand NVD lui ajoute des CPE correspondants.

### Phase 4 — Moteurs IA, connecteurs de veille et agents de veille (Jalon 1)

- [x] 4.1 Abstraction `AIEngine` (spec 07 §4) : complétion, sortie structurée, outils, streaming, usage, stop reasons normalisés, paramètres abstraits (niveau de raisonnement)
- [x] 4.2 Adaptateur **Gemini** (moteur de démarrage, palier gratuit, ADR-025) : sorties structurées, appels de fonctions, recherche Google intégrée, limiteur de débit sur les quotas gratuits
- [x] 4.3 Adaptateur **compatible OpenAI** pour le futur LLMaaS (et OpenLLM, vLLM, Ollama, Mistral) ; mode outils émulé par sortie JSON contrainte
- [x] 4.3 bis Adaptateur **Claude** (SDK officiel `anthropic`, `claude-opus-5-5`), prêt pour le jour où un budget API existe ; testé contre un serveur simulé
- [x] 4.4 Moteurs IA comme connecteurs : modèles, capacités déclarées puis vérifiées par un test automatique, politique de données (cloud externe ou auto-hébergé, classes de données autorisées)
- [x] 4.5 **Moteur préféré** : défaut plateforme (admin), surcharge par espace, héritage ou épinglage par agent ; rapport de compatibilité avant changement
- [x] 4.6 Connecteurs de veille gratuits : GitHub, **lecture gratuite de X** (découverte des URL de posts, puis lecture par l'oEmbed officiel ; spec 07 §2.1), Stack Exchange, Mastodon, Bluesky, Reddit (flux RSS), Hacker News, OSV, web (avis éditeurs, liste de domaines) ; SearXNG auto-hébergé en option
- [x] 4.7 Agents : configuration versionnée (moteur hérité ou épinglé, modèle, niveau de raisonnement, prompt système, connecteurs autorisés, domaines, schéma de sortie, limites, budget par exécution)
- [x] 4.8 Runtime d'agent : boucle d'outils avec hooks (autorisation, budget, journalisation), timeouts, limites de tours
- [x] 4.9 Outils en lecture seule branchés sur les connecteurs de l'espace : `web_fetch`, `github_search`, `github_get`, `x_discover`, `x_read`, `stackexchange_search`, `social_search`, `nvd_lookup`, `epss_lookup`, `kev_lookup`, `osv_lookup`, `internal_vuln_search`, `technology_lookup`
- [x] 4.10 Garde-fous anti-injection de prompt : isolation du contenu non fiable, validation des sorties, citations obligatoires, détection heuristique signalée à l'analyste ; détection des faux PoC piégés
- [x] 4.11 Comptabilité des tokens et des coûts, budgets mensuels par espace avec arrêt dur
- [x] 4.12 Agents de veille prédéfinis, créés en seed dans chaque espace : triage, chasseur de PoC GitHub, réseaux sociaux, forums techniques, avis éditeurs, synthèse
- [x] 4.13 Nœuds `ai.agent`, `ai.summarize`, `ai.classify`, `ai.extract`, `ai.relevance` ; sources `source.github_search`, `source.x`, `source.stackexchange`, `source.social`
- [x] 4.14 Workflow seed complet **« Nouvelle CVE NVD → investigation »** (agents de veille en parallèle, puis synthèse) et workflow de **re-veille** des vulnérabilités ouvertes (nouveaux PoC, exploitation, ajout au KEV)
- [x] 4.15 Interfaces : moteurs IA (moteur préféré, test de capacités), connecteurs de veille, agents (édition, bac à sable de test, historique des versions), traces d'exécution d'agent, tableau de bord des coûts
- [x] 4.16 **Banc d'évaluation des moteurs** : jeu de CVE de référence validé par les analystes, critères (validité du schéma, citations, exactitude, coût, latence), rapport comparatif ; prérequis à tout changement de moteur préféré
- [x] 4.17 Corpus de tests d'injection de prompt (contenus collectés piégés) intégré à la CI
- [x] 4.18 Indicateur de couverture de X : part des CVE pour lesquelles une discussion X pertinente est trouvée par la lecture gratuite, comparée à un échantillon vérifié à la main ; décision sur l'activation de SearXNG (Q30)

**Critère de sortie (Jalon 1)** : une nouvelle CVE NVD dans le périmètre produit, sans intervention, une vulnérabilité non qualifiée accompagnée d'une synthèse structurée et sourcée par les agents de veille ; un contenu piégé ne déclenche aucune action non prévue ; basculer le moteur préféré vers un point d'accès compatible OpenAI (simulé en CI) ne demande aucune modification de code. **Atteint** (2026-10-22) : `tests/integration/test_jalon1.py` (adaptateurs réels Gemini puis compatible OpenAI, bascule par l'API) et `tests/integration/test_injection_corpus.py`.

### Phase 5 — Éditeur visuel de workflows

- [x] 5.1 Canvas React Flow : palette de nœuds issue du registre, glisser-déposer, connexions validées par type de port
- [x] 5.2 Panneau de paramètres généré depuis le JSON Schema, avec sélecteurs de secrets, connecteurs, agents et modèles
- [x] 5.3 Éditeur d'expressions (CodeMirror 6) avec aide JMESPath et aperçu sur des données d'exemple
- [x] 5.4 Exécution d'un nœud en test avec données épinglées (par exemple, une CVE NVD réelle), mode dry-run pour les nœuds de sortie
- [x] 5.5 Visualisation des exécutions : statut par nœud, entrées, sorties, erreurs, durées, coûts
- [x] 5.6 Gestion des versions : brouillon, publication, historique, diff, restauration ; import/export
- [x] 5.7 Verrou d'édition optimiste (détection d'édition concurrente)

**Critère de sortie** : un analyste modifie le workflow « Nouvelle CVE NVD → investigation » (ajout d'un agent, changement de filtre), le teste sur une CVE et publie la nouvelle version entièrement depuis l'interface. **Atteint** (2026-10-22) : `tests/integration/test_phase5_exit.py` pilote Chromium contre la vraie API (CSP de production, moteur de workflows réel) ; il demande un navigateur (`VV_E2E_CHROMIUM`, `VV_E2E_PLAYWRIGHT`) et n'est pas encore exécuté en CI.

### Phase 6 — Modèles de bulletins et drafts

- [ ] 6.1 Modèles versionnés : champs typés, consignes IA par champ, gabarit de rendu Liquid, guide de style, exemple, langue
- [ ] 6.2 Règles de sélection par sujet (techno, éditeur, catégorie, sévérité, KEV…) avec priorités
- [ ] 6.3 Éditeur de modèle avec aperçu calculé côté serveur sur une vulnérabilité réelle
- [ ] 6.4 Demande unitaire de draft (depuis une vulnérabilité, un CVE, des URL ou un texte libre), exécution asynchrone, progression en SSE
- [ ] 6.5 Génération par sortie structurée avec le moteur IA de l'espace, puis rendu déterministe ; Markdown assaini en HTML
- [ ] 6.6 Cycle de vie : `draft`, `approved`, `published`, `withdrawn` (`in_review` si l'espace active la double validation, désactivée par défaut) ; révisions et diff ; versions FR et EN liées
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
- [ ] 7.9 Interfaces : liste et édition des connecteurs de publication, éditeur de mapping avec aperçu, historique des envois

**Critère de sortie** : sans connaître l'API cible à l'avance, un analyste configure un connecteur depuis l'interface et pousse un bulletin validé, avec un journal complet.

### Phase 8 — Portail client

- [ ] 8.1 Application portail séparée (bundle distinct, aucun code back-office), connexion, MFA (selon la décision)
- [ ] 8.2 Vue PostgreSQL `portal_bulletins_v` et rôle `vv_portal` limité à cette vue et aux tables du portail
- [ ] 8.3 Liste, recherche, filtres (techno, sévérité, date) et détail des bulletins publiés destinés à l'organisation
- [ ] 8.4 Export Markdown, HTML et **PDF**, impression ; **envoi par e-mail** (SMTP) au choix de chaque utilisateur
- [ ] 8.4 bis Référent client `client_admin` : invitation et gestion des utilisateurs de son organisation
- [ ] 8.5 Tests de non-fuite : aucun champ interne, aucune vulnérabilité non publiée, aucune donnée d'une autre organisation

**Critère de sortie** : un client consulte les bulletins qui lui sont destinés, et les tests prouvent qu'il ne peut rien voir d'autre.

### Phase 9 — Abonnements et demandes de technos (fonctionnalité à venir)

- [ ] 9.1 Abonnements par organisation ou par utilisateur à des technos (sévérité minimale, canaux)
- [ ] 9.2 Notifications filtrées (e-mail, puis autres canaux) et vue « Mes technos » dans le portail
- [ ] 9.3 Demande de techno absente : recherche approchée préalable (éviter les doublons), formulaire, limitation de débit
- [ ] 9.4 Modération : file des demandes, approbation (création de la techno et abonnement automatique du demandeur), rejet motivé, fusion avec une techno existante
- [ ] 9.5 Confidentialité : les abonnements d'un client révèlent son parc, ils ne sont visibles que de cette organisation et des rôles autorisés
- [ ] 9.6 Option : inclure automatiquement les technos suivies par les clients dans le périmètre de veille de l'espace

### Phase 10 — Durcissement et mise en production (en continu, puis finalisation)

- [ ] 10.1 DAST (OWASP ZAP baseline en CI), fuzzing de l'API depuis OpenAPI (schemathesis)
- [ ] 10.2 WebAuthn/passkeys, SSO OIDC optionnel
- [ ] 10.3 Sauvegardes chiffrées, restauration testée, rotation des clés documentée
- [ ] 10.4 Observabilité : métriques (Prometheus), traces OpenTelemetry, alertes (synchro NVD en retard, échecs de workflows, budget LLM, échecs de connexion, connecteur en erreur)
- [ ] 10.5 Documentation d'exploitation (installation, mise à jour, réponse à incident, procédure d'urgence)
- [ ] 10.6 Revue de sécurité complète et test d'intrusion externe avant l'ouverture du portail sur Internet

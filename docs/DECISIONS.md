# DECISIONS — Registre des décisions d'architecture (ADR)

Statuts : **Proposée** (en attente de validation par le porteur du projet), **Acceptée**, **Remplacée par ADR-xxx**.
Toute nouvelle décision s'ajoute à la fin, avec le format : Contexte / Décision / Alternatives écartées / Conséquences.

---

## ADR-001 — Monorepo backend, frontend et déploiement

- **Statut** : Proposée (2026-10-20)
- **Contexte** : une petite équipe, des contrats d'API partagés entre le backend et deux frontends, et un besoin de reprise facile.
- **Décision** : un seul dépôt avec `backend/`, `frontend/` (pnpm workspaces : `apps/backoffice`, `apps/portal`, `packages/*`), `deploy/` et `docs/`. Le client TypeScript est généré depuis l'OpenAPI du backend.
- **Alternatives écartées** : un dépôt par composant (synchronisation des versions plus coûteuse).
- **Conséquences** : la CI construit et teste tout ; les chemins de déclenchement filtrent par dossier pour rester rapides.

## ADR-002 — Backend en Python et FastAPI

- **Statut** : Proposée
- **Contexte** : le cœur du produit, c'est de la collecte web, du parsing, de l'IA et de l'analyse de vulnérabilités.
- **Décision** : Python 3.13, FastAPI, Pydantic v2 strict, SQLAlchemy 2 async, Alembic.
- **Alternatives écartées** : TypeScript/NestJS (une seule langue avec le front, mais un écosystème sécurité et IA moins riche : bibliothèques CVSS, parsing, SDK) ; Go (excellent pour l'exécution, plus lent à faire évoluer sur la partie métier et IA).
- **Conséquences** : typage strict avec mypy obligatoire ; la validation Pydantic sert de première ligne de défense.

## ADR-003 — Deux applications (back-office et portail) dans les deux couches

- **Statut** : Proposée
- **Contexte** : les clients sont exposés sur Internet ; les analystes manipulent des données sensibles.
- **Décision** : deux applications ASGI (`main_backoffice`, `main_portal`) et deux SPA, sur deux noms d'hôte, avec des cookies et des rôles de base de données distincts. Le back-office est restreint au réseau interne ou au VPN.
- **Alternatives écartées** : une seule application avec des routes protégées par rôle (surface d'attaque plus large côté Internet, code back-office téléchargé par les clients).
- **Conséquences** : un peu plus de configuration de déploiement ; code partagé dans `app/core` et `packages/ui`.

## ADR-004 — Moteur de workflows natif plutôt que n8n embarqué

- **Statut** : Proposée
- **Contexte** : le besoin est un orchestrateur type n8n, entièrement éditable depuis l'application, multi-espace (VOC/CERT cloisonnés), sécurisé. n8n a été envisagé.
- **Décision** : développer un moteur de workflows natif (graphe JSON versionné, exécuteur Celery, éditeur React Flow) avec des nœuds métier de veille. On garde une passerelle optionnelle : un nœud `integration.n8n_webhook` pour appeler une instance n8n existante, sans exposer son éditeur. Un import partiel de workflows n8n pourra être étudié.
- **Raisons** :
  1. **Sécurité** : n8n a connu en 2026 plusieurs vulnérabilités critiques, dont une RCE sans authentification (CVE-2026-21858, CVSS 10), des évasions du bac à sable d'expressions (CVE-2026-1470) et des RCE authentifiées via des nœuds (CVE-2026-21877, CVE-2026-33660, chaîne CVE-2026-44789/44790/44791). Le nœud Code et le moteur d'expressions JavaScript augmentent fortement la surface d'attaque.
  2. **Licence** : la Sustainable Use License autorise l'usage interne, mais intégrer l'éditeur dans notre propre application (marque blanche, embed) demande un accord commercial n8n.
  3. **Multi-espace et RBAC** : le cloisonnement fin (projets, rôles, SSO) relève des fonctionnalités sous licence entreprise, et devrait de toute façon être synchronisé avec notre propre RBAC.
  4. **Expérience** : « tout éditer depuis l'application » impose une iframe et une double authentification, ou un fork, ce qui revient plus cher qu'un moteur ciblé.
  5. **Métier** : des nœuds natifs (vulnérabilité, bulletin, agent, connecteur) s'intègrent directement au modèle de données, aux permissions et à l'audit.
- **Alternatives écartées** : n8n embarqué en iframe ; n8n headless piloté par API (deux sources de vérité, sécurité du Code node) ; Temporal, Prefect ou Airflow (moteurs d'exécution sans éditeur visuel métier, et lourds à opérer pour ce volume).
- **Conséquences** : on développe l'éditeur et l'exécuteur, soit environ deux phases du plan. En contrepartie, on maîtrise totalement la sécurité et l'UX. Pas de nœud « Code ».

## ADR-005 — Exécution par Celery et Redis, état dans PostgreSQL

- **Statut** : Proposée
- **Décision** : chaque nœud est une tâche Celery (`acks_late`, idempotente par `(run_id, node_id, attempt)`). L'état de référence (exécutions, nœuds, sorties) est dans PostgreSQL. Il y a une file par type de worker (`default`, `collect`, `ai`, `publish`). Le scheduler est maison, sur PostgreSQL (`FOR UPDATE SKIP LOCKED`) avec croniter.
- **Alternatives écartées** : Temporal (exécution durable excellente, mais un serveur et une base en plus) ; arq ou Dramatiq (moins d'outillage) ; file Postgres pure (procrastinate, possible mais moins éprouvée en multi-files).
- **Conséquences** : la reprise après crash repose sur l'état en base et la ré-émission des nœuds en cours, ce qui impose de tester l'idempotence. Une migration vers Temporal reste possible derrière l'interface de l'exécuteur.

## ADR-006 — PostgreSQL avec RLS pour le cloisonnement

- **Statut** : Proposée
- **Décision** : PostgreSQL 17, `workspace_id` ou `client_org_id` sur chaque table cloisonnée, politiques RLS alimentées par `SET LOCAL` à chaque transaction, en plus du filtrage applicatif. Rôles distincts par composant.
- **Alternatives écartées** : une base par espace (opérations plus lourdes, catalogues dupliqués) ; un filtrage applicatif seul (une seule erreur suffit pour une fuite).
- **Conséquences** : les migrations doivent créer les politiques avec les tables ; un test vérifie que chaque table cloisonnée a la RLS activée.

## ADR-007 — Authentification locale avec MFA et sessions côté serveur

- **Statut** : Proposée (dépend de la question ouverte Q8 sur le SSO)
- **Décision** : comptes locaux, Argon2id, TOTP obligatoire en interne, sessions opaques côté serveur en cookie `__Host-` SameSite=Strict, CSRF par jeton en en-tête. Une interface d'authentification abstraite permet d'ajouter le SSO OIDC ensuite. Pas de JWT dans le navigateur.
- **Alternatives écartées** : JWT en localStorage (vol par XSS, révocation difficile) ; Keycloak dès le départ (sûr, mais un composant de plus à opérer ; reste l'option préférée si un IdP d'entreprise existe déjà).
- **Conséquences** : on implémente le MFA, la récupération et les invitations, avec des tests dédiés.

## ADR-008 — RBAC par permissions définies dans le code

- **Statut** : Proposée
- **Décision** : voir RBAC.md. Permissions et rôles déclarés dans le code ; périmètres global, espace et organisation ; l'admin plateforme n'a pas accès aux données métier sans appartenance à l'espace.
- **Conséquences** : test bloquant « route sans permission » et matrice de tests générée.

## ADR-009 — Gabarits Liquid (python-liquid), pas Jinja2

- **Statut** : Proposée
- **Contexte** : les modèles de bulletins et les mappings de connecteurs sont édités par des utilisateurs, donc potentiellement par un compte compromis.
- **Décision** : Liquid, conçu pour des gabarits édités par des utilisateurs non fiables : pas d'accès aux attributs Python, boucles et conditions, filtres en liste blanche, limites de ressources. Le rendu se fait côté serveur, aussi pour l'aperçu.
- **Alternatives écartées** : Jinja2 SandboxedEnvironment (historique d'évasions du bac à sable) ; Mustache (trop limité, bibliothèques Python peu maintenues).
- **Conséquences** : un jeu de filtres maison testés (dates, sévérité, listes) ; les sorties LLM ne sont jamais compilées comme gabarit.

## ADR-010 — Expressions JMESPath, pas de code utilisateur

- **Statut** : Proposée
- **Décision** : la sélection et les conditions dans les workflows et les mappings utilisent JMESPath (déterministe, sans effet de bord, sans accès au système). Pas de nœud « Code ». Les besoins non couverts deviennent de nouveaux types de nœuds, revus et testés.
- **Alternatives écartées** : JavaScript sandboxé façon n8n (évasions régulières) ; simpleeval ou ast Python (surface d'évasion) ; CEL (bonne option, mais l'écosystème Python est moins mûr).
- **Conséquences** : un éditeur JMESPath avec aperçu dans l'interface ; les fonctions personnalisées sont ajoutées au cas par cas.

## ADR-011 — Couche LLM multi-fournisseur, Claude par défaut

- **Statut** : Proposée (dépend de Q6 sur la confidentialité et les fournisseurs autorisés)
- **Décision** : une interface `LLMProvider` (complétion, sortie structurée, outils, streaming, comptage de l'usage). Le premier adaptateur est Anthropic, via le SDK officiel `anthropic`, avec le modèle par défaut `claude-opus-5-5` : réflexion adaptative, `effort` configurable par agent, sorties structurées (`output_config.format`), cache de prompt sur le prompt système et les outils, streaming pour les sorties longues, gestion du stop reason `refusal` avec le fallback serveur. Un second adaptateur, compatible OpenAI, couvre Mistral, Azure OpenAI, vLLM et Ollama. Le modèle est un paramètre de chaque agent, choisi par l'espace.
- **Alternatives écartées** : LangChain ou LlamaIndex (abstraction lourde et instable, contrôle de sécurité plus difficile sur la boucle d'outils) ; la boucle d'agent hébergée par un fournisseur (perte de contrôle des outils et de la sortie réseau).
- **Conséquences** : notre runtime d'agent (boucle d'outils avec hooks) contrôle chaque appel d'outil, le budget et la journalisation.

## ADR-012 — Sortie réseau : SafeHttpClient et proxy smokescreen

- **Statut** : Proposée
- **Décision** : double barrière anti-SSRF, applicative (validation DNS et IP, épinglage, redirections revalidées) et réseau (proxy de sortie obligatoire pour les workers, sans route directe).
- **Conséquences** : les sources ou connecteurs internes demandent une exception explicite, autorisée par un admin et auditée.

## ADR-013 — Secrets par chiffrement d'enveloppe et clés par usage

- **Statut** : Proposée
- **Décision** : AES-256-GCM, une clé de données par secret, une KEK par usage injectée uniquement dans les composants concernés. Vault ou KMS en option plus tard.
- **Conséquences** : CLI de rotation ; la perte d'une KEK rend ses secrets irrécupérables, d'où une procédure de sauvegarde des KEK hors ligne.

## ADR-014 — Connecteur de publication HTTP générique et déclaratif

- **Statut** : Proposée
- **Contexte** : les API cibles (endpoints, champs, authentification) ne sont pas encore connues.
- **Décision** : un connecteur HTTP entièrement configurable (authentifications courantes, mapping JSON déclaratif avec constantes, chemins JMESPath, gabarits Liquid et tables de correspondance, dry-run, idempotence, journal). Formats standards proposés en complément : CSAF 2.0 (avis de sécurité) et plus tard STIX 2.1. Des connecteurs prédéfinis (MISP, OpenCTI, TheHive, Jira…) viendront comme préréglages du connecteur générique quand les cibles seront connues.
- **Conséquences** : ajouter une cible devient une configuration, pas un développement.

## ADR-015 — Sources : API officielles d'abord, collecte respectueuse

- **Statut** : Proposée
- **Décision** : on utilise les API officielles quand elles existent (NVD, GitHub REST/GraphQL, Stack Exchange, X API v2, Reddit, Mastodon, Bluesky, OSV, CISA KEV, EPSS) plutôt que du scraping HTML. Le scraping HTML est réservé aux sites sans API, en respectant le robots.txt, avec limitation de débit et un User-Agent identifiable. Pour X, l'API est payante à l'usage depuis février 2026 (environ 0,005 $ par post lu, à vérifier) : la source est désactivée sans identifiants et soumise à un budget.
- **Conséquences** : des quotas par source ; Bluesky et Mastodon sont des alternatives gratuites à X pour la communauté sécurité.

## ADR-016 — Langues

- **Statut** : Proposée
- **Décision** : code, identifiants et commentaires en anglais ; documentation et interface en français, avec i18n prête. La langue d'un bulletin est un paramètre de son modèle.

## ADR-017 — Déploiement Docker Compose et Caddy

- **Statut** : Proposée (dépend de Q9 sur l'hébergement)
- **Décision** : Docker Compose pour le développement et la production mono-hôte, Caddy en reverse proxy. Les images sont prêtes pour Kubernetes (configuration par variables d'environnement, sans état local).

## ADR-018 — Journal d'audit chaîné par hachage

- **Statut** : Proposée
- **Décision** : table append-only, droits `INSERT` seuls pour l'application, chaîne SHA-256, CLI de vérification, export vers un SIEM.

## ADR-019 — Humain dans la boucle pour toute diffusion

- **Statut** : Proposée
- **Décision** : aucun contenu produit par l'IA n'atteint un client ou une API distante sans action explicite d'un analyste (approbation de bulletin, nœud `control.approval` obligatoire avant `publish.api`). La double validation est configurable par espace et activée par défaut pour le portail.

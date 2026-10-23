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

- **Statut** : Acceptée (mise en œuvre en phase 3, 2026-10-21)
- **Décision** : chaque nœud est une tâche Celery (`acks_late`, idempotente par `(run_id, node_id, attempt)`). L'état de référence (exécutions, nœuds, sorties) est dans PostgreSQL. Il y a une file par type de worker (`default`, `collect`, `ai`, `publish`). Le scheduler est maison, sur PostgreSQL (`FOR UPDATE SKIP LOCKED`) avec croniter.
- **Alternatives écartées** : Temporal (exécution durable excellente, mais un serveur et une base en plus) ; arq ou Dramatiq (moins d'outillage) ; file Postgres pure (procrastinate, possible mais moins éprouvée en multi-files).
- **Conséquences** : la reprise après crash repose sur l'état en base et la ré-émission des nœuds en cours, ce qui impose de tester l'idempotence. Une migration vers Temporal reste possible derrière l'interface de l'exécuteur.
- **Mise en œuvre (phase 3)** :
  - L'orchestrateur (`default.workflow_advance`) s'exécute sous le **verrou de ligne de l'exécution** : des appels concurrents ou rejoués convergent. Il crée les `node_runs` des nœuds prêts et publie une tâche `<file>.workflow_node` dont l'identifiant Celery est celui du `node_run` (révocation ciblée, ré-émission sans doublon).
  - Une tâche de nœud **réclame** son `node_run` par un `UPDATE … WHERE status = 'queued'` : une tâche rejouée ne fait rien. Les effets en base du nœud et l'écriture de sa sortie partagent une transaction ; en cas d'échec, ces effets sont annulés et seul l'échec est enregistré. Les e-mails partent après la validation de la transaction.
  - Un nœud dont toutes les entrées sont vides est marqué `skipped` (sauf les sources, qui lisent sans élément d'entrée) : c'est ainsi qu'une branche `out_of_scope` ou `false` s'arrête.
  - Le scheduler (verrou consultatif, un seul leader) déclenche les crons, diffuse l'outbox (lots de 200, `SKIP LOCKED`) et lance le **balayage de reprise** : nœuds `running` au-delà de leur délai plus 2 minutes (échec `worker_lost`, puis politique de retry), messages perdus (`queued` depuis plus de 10 minutes, ré-émis), exécutions en attente d'un créneau ou au-delà de leur échéance.
  - Limites (constantes `engine.Limits`, réglage par espace à venir) : celles de la spec 02 §5. Une exécution en attente de validation humaine n'occupe pas de créneau, et son échéance repart à la décision.

## ADR-006 — PostgreSQL avec RLS pour le cloisonnement

- **Statut** : Proposée
- **Décision** : PostgreSQL 17, `workspace_id` ou `client_org_id` sur chaque table cloisonnée, politiques RLS alimentées par `SET LOCAL` à chaque transaction, en plus du filtrage applicatif. Rôles distincts par composant.
- **Alternatives écartées** : une base par espace (opérations plus lourdes, catalogues dupliqués) ; un filtrage applicatif seul (une seule erreur suffit pour une fuite).
- **Conséquences** : les migrations doivent créer les politiques avec les tables ; un test vérifie que chaque table cloisonnée a la RLS activée.

## ADR-007 — Authentification locale avec MFA et sessions côté serveur

- **Statut** : Acceptée (2026-10-20, Q8)
- **Décision** : comptes locaux, Argon2id, TOTP obligatoire en interne, sessions opaques côté serveur en cookie `__Host-` SameSite=Strict, CSRF par jeton en en-tête. Une interface d'authentification abstraite permet d'ajouter le SSO OIDC ensuite. Pas de JWT dans le navigateur.
- **Alternatives écartées** : JWT en localStorage (vol par XSS, révocation difficile) ; Keycloak dès le départ (sûr, mais un composant de plus à opérer ; reste l'option préférée si un IdP d'entreprise existe déjà).
- **Conséquences** : on implémente le MFA, la récupération et les invitations, avec des tests dédiés.

## ADR-008 — RBAC par permissions définies dans le code

- **Statut** : Acceptée (2026-10-20, Q1)
- **Décision** : voir RBAC.md. Tous les analystes VOC sont admins plateforme : l'espace VOC porte le réglage `grants_platform_admin`, et l'appartenance `analyst` à cet espace donne les permissions globales. Le CERT ne les a pas. Permissions et rôles déclarés dans le code ; périmètres global, espace et organisation ; l'admin plateforme n'a pas accès aux données métier sans appartenance à l'espace.
- **Conséquences** : test bloquant « route sans permission » et matrice de tests générée.

## ADR-009 — Gabarits Liquid (python-liquid), pas Jinja2

- **Statut** : Acceptée (mise en œuvre en phase 3 : `app/workflows/expressions.py`)
- **Contexte** : les modèles de bulletins et les mappings de connecteurs sont édités par des utilisateurs, donc potentiellement par un compte compromis.
- **Décision** : Liquid, conçu pour des gabarits édités par des utilisateurs non fiables : pas d'accès aux attributs Python, boucles et conditions, filtres en liste blanche, limites de ressources. Le rendu se fait côté serveur, aussi pour l'aperçu.
- **Alternatives écartées** : Jinja2 SandboxedEnvironment (historique d'évasions du bac à sable) ; Mustache (trop limité, bibliothèques Python peu maintenues).
- **Conséquences** : un jeu de filtres maison testés (dates, sévérité, listes) ; les sorties LLM ne sont jamais compilées comme gabarit.

## ADR-010 — Expressions JMESPath, pas de code utilisateur

- **Statut** : Acceptée (mise en œuvre en phase 3 : `app/workflows/expressions.py`)
- **Décision** : la sélection et les conditions dans les workflows et les mappings utilisent JMESPath (déterministe, sans effet de bord, sans accès au système). Pas de nœud « Code ». Les besoins non couverts deviennent de nouveaux types de nœuds, revus et testés.
- **Alternatives écartées** : JavaScript sandboxé façon n8n (évasions régulières) ; simpleeval ou ast Python (surface d'évasion) ; CEL (bonne option, mais l'écosystème Python est moins mûr).
- **Conséquences** : un éditeur JMESPath avec aperçu dans l'interface ; les fonctions personnalisées sont ajoutées au cas par cas.

## ADR-011 — Moteur IA interchangeable : Claude aujourd'hui, LLM open source demain

- **Statut** : Acceptée pour l'abstraction ; le moteur de démarrage est fixé par ADR-025 (Gemini, palier gratuit). Mise à jour le 2026-10-20 après la consigne du porteur : « notre moteur d'IA préféré, aujourd'hui Claude, demain un LLM open source ». Q6 reste ouverte sur la confidentialité.
- **Décision** :
  - Une interface `AIEngine` (complétion, sortie structurée, outils, streaming, usage, stop reasons normalisés) et des agents configurés par **paramètres abstraits** (niveau de raisonnement, schéma de sortie, limites), traduits par chaque adaptateur.
  - Adaptateur **Claude** (SDK officiel `anthropic`), moteur préféré par défaut avec `claude-opus-5-5` : réflexion adaptative, `effort` d'après le niveau de raisonnement, sorties structurées (`output_config.format`), cache de prompt, streaming pour les sorties longues, gestion du stop reason `refusal` avec le fallback serveur.
  - Adaptateur **compatible OpenAI**, livré dès le MVP, pour les LLM open source auto-hébergés (OpenLLM, vLLM, Ollama) et aussi Mistral ou Azure OpenAI, avec un mode outils émulé (JSON contraint) quand le modèle n'a pas d'appel d'outils natif.
  - Les moteurs sont des **connecteurs** (famille `ai_engine`) : capacités déclarées puis vérifiées, politique de données par moteur.
  - **Moteur préféré** à trois niveaux (plateforme, espace, agent). La bascule se fait par configuration, après un **banc d'évaluation** comparatif et un rapport de compatibilité.
- **Alternatives écartées** : LangChain ou LlamaIndex (abstraction lourde et instable, contrôle de sécurité plus difficile sur la boucle d'outils) ; boucle d'agent hébergée par un fournisseur (perte de contrôle des outils et de la sortie réseau, verrouillage) ; coder uniquement pour Claude (bascule future coûteuse).
- **Conséquences** : notre runtime d'agent contrôle chaque appel d'outil, le budget et la journalisation, quel que soit le moteur. Les fonctions propres à Claude (effort, cache, fallback) restent dans l'adaptateur. Les tests tournent avec les deux adaptateurs simulés.

## ADR-012 — Sortie réseau : SafeHttpClient et proxy smokescreen

- **Statut** : Acceptée (phase 2)
- **Décision** : double barrière anti-SSRF, applicative (`SafeHttpClient` : politique d'URL, validation des adresses, redirections revalidées, plafonds) et réseau (proxy smokescreen obligatoire pour les workers, sans DNS ni route directe).
  - En mode direct (développement), le client résout et épingle l'IP validée.
  - En mode proxy, le client ne résout pas les noms (les workers n'ont pas de DNS externe) : smokescreen résout, applique la liste de domaines et refuse les plages internes sur l'adresse composée, ce qui ferme la fenêtre de rebinding côté réseau.
- **Conséquences** : les sources ou connecteurs internes demandent une exception explicite, autorisée par un admin, auditée, et ouverte aux deux barrières (plage du connecteur et `allow_ranges` de smokescreen).

## ADR-013 — Secrets par chiffrement d'enveloppe et clés par usage

- **Statut** : Acceptée (révisée en phase 2 : enveloppe asymétrique)
- **Décision** : chaque secret est chiffré en AES-256-GCM par sa propre clé de données (DEK). La DEK est enveloppée pour la **clé publique X25519 de son usage** (`llm`, `source`, `connector`, `webhook`) : échange ECDH avec une clé éphémère, dérivation HKDF-SHA256, AES-256-GCM. Données associées : usage, identifiant du secret, espace et identifiant de clé.
  - L'API du back-office ne détient que les **clés publiques** : elle chiffre les nouveaux secrets mais ne peut en déchiffrer aucun. L'écriture seule est garantie par la cryptographie, pas seulement par le code.
  - Chaque worker ne reçoit que le **trousseau privé** de son usage, sous forme de secret Docker (`worker-collect` : `source` ; `worker-ai` : `llm`, et `source` pour les outils des agents depuis l'ADR-027 ; `worker-publish` : `connector`).
  - Les secrets TOTP restent chiffrés par une clé symétrique propre (`VV_KEK_TOTP`), car l'API doit les vérifier.
  - Vault ou KMS en option plus tard.
- **Conséquences** : rotation par la CLI (`vault-keygen`, puis `vault-rotate` qui ré-enveloppe les DEK) ; la perte d'un trousseau rend ses secrets irrécupérables, d'où une sauvegarde hors ligne des trousseaux (PROCEDURES §9).

## ADR-014 — Connecteur de publication HTTP générique et déclaratif

- **Statut** : Proposée
- **Contexte** : les API cibles (endpoints, champs, authentification) ne sont pas encore connues.
- **Décision** : un connecteur HTTP entièrement configurable (authentifications courantes, mapping JSON déclaratif avec constantes, chemins JMESPath, gabarits Liquid et tables de correspondance, dry-run, idempotence, journal). Formats standards proposés en complément : CSAF 2.0 (avis de sécurité) et plus tard STIX 2.1. Des connecteurs prédéfinis (MISP, OpenCTI, TheHive, Jira…) viendront comme préréglages du connecteur générique quand les cibles seront connues.
- **Conséquences** : ajouter une cible devient une configuration, pas un développement.

## ADR-015 — Sources : API officielles d'abord, collecte respectueuse

- **Statut** : Proposée
- **Décision** : on utilise les API officielles **gratuites** quand elles existent (NVD, GitHub REST/GraphQL, Stack Exchange, Mastodon, Bluesky, Hacker News, OSV, CISA KEV, EPSS, oEmbed de X) plutôt que du scraping HTML. Le scraping HTML est réservé aux sites sans API qui l'autorisent, en respectant le robots.txt et les conditions d'utilisation, avec limitation de débit et un User-Agent identifiable. X est lu sans API payante ni scraping (ADR-023, spec 07 §2.1) ; Reddit est lu par ses flux RSS publics.
- **Conséquences** : des quotas par source ; Bluesky et Mastodon compensent la couverture partielle de X pour la communauté sécurité.

## ADR-016 — Langues

- **Statut** : Proposée
- **Décision** : code, identifiants et commentaires en anglais ; documentation et interface en français, avec i18n prête. La langue d'un bulletin est un paramètre de son modèle.

## ADR-017 — Déploiement Docker Compose et Caddy

- **Statut** : Acceptée (2026-10-20, Q9 : serveur on-premise, sortie Internet directe)
- **Décision** : Docker Compose pour le développement et la production mono-hôte, Caddy en reverse proxy. Les images sont prêtes pour Kubernetes (configuration par variables d'environnement, sans état local).

## ADR-018 — Journal d'audit chaîné par hachage

- **Statut** : Proposée
- **Décision** : table append-only, droits `INSERT` seuls pour l'application, chaîne SHA-256, CLI de vérification, export vers un SIEM.

## ADR-019 — Humain dans la boucle pour toute diffusion

- **Statut** : Proposée
- **Décision** : aucun contenu produit par l'IA n'atteint un client ou une API distante sans action explicite d'un analyste (approbation de bulletin, nœud `control.approval` obligatoire avant `publish.api`). La double validation est configurable par espace et **désactivée par défaut** (Q4) : un analyste peut approuver et publier son propre bulletin, avec une MFA récente ; un espace qui l'active impose un relecteur différent de l'auteur (`bulletin_settings.review_required`). Toute modification d'un bulletin soumis, approuvé ou publié le renvoie en `draft` : ce qui est approuvé puis publié est toujours la révision courante, et la version déjà publiée reste visible des clients jusqu'à la republication.

## ADR-020 — NVD, vecteur d'entrée n°1 des investigations

- **Statut** : Proposée (2026-10-20), à la demande du porteur : « le 1er vecteur d'entrée est la saisie d'une nouvelle vuln au NVD, c'est l'initiateur qui va lancer les agents ».
- **Contexte** : les agents doivent travailler dès qu'une vulnérabilité apparaît, sans attendre qu'un analyste la repère.
- **Décision** :
  - Une synchronisation **globale** et incrémentale de NVD (API 2.0, `lastModStartDate`/`lastModEndDate`, curseur avec recouvrement, 2 h par défaut selon la recommandation NVD) alimente le catalogue `cve_records`.
  - Chaque nouvelle CVE émet un événement `cve.published` ; les changements significatifs (CVSS, CPE, KEV, référence d'exploit, rejet) émettent `cve.updated`. Les deux passent par l'outbox.
  - Les événements sont diffusés aux espaces : les déclencheurs `trigger.cve_published` et `trigger.cve_updated` lancent, dans chaque espace, le workflow « Nouvelle CVE NVD → investigation », filtré par le **périmètre de veille** de l'espace.
  - Le rattrapage initial n'émet pas d'événements. La saisie manuelle d'une CVE emprunte le même chemin.
- **Alternatives écartées** : un nœud de workflow qui interroge NVD dans chaque espace (multiplie les appels, contraire à la recommandation NVD d'une clé unique par organisation, risque de trous ou de doublons) ; investiguer toutes les CVE sans filtre (environ 130 par jour, coût IA élevé et bruit pour les analystes, mais disponible en mode `all`).
- **Conséquences** : le délai de détection dépend de l'intervalle de synchronisation et des délais de publication et d'enrichissement de NVD. Les CPE arrivent parfois plusieurs jours après la publication, d'où la ré-évaluation du périmètre sur `cve_updated(cpe_added)`. Q24 étudie CVE.org comme accélérateur.

## ADR-021 — Cadre de connecteurs unifié (veille, moteurs IA, publication)

- **Statut** : Proposée (2026-10-20)
- **Contexte** : les sources (NVD, GitHub, X…), les moteurs IA (Claude, LLM open source) et les cibles de publication partagent les mêmes besoins : identifiants, quotas, budgets, santé, audit, sortie réseau contrôlée, paramétrage depuis l'interface.
- **Décision** : une table `connectors` et un cadre de code communs, avec trois familles (`source`, `ai_engine`, `publish`), une portée globale ou espace, un schéma de configuration par type (qui génère le formulaire), des références de secrets, un test de connexion, un suivi de santé et de consommation, et des domaines de sortie déclarés qui alimentent le proxy. Les nœuds et les outils d'agents n'accèdent à l'extérieur **que** par un connecteur.
- **Alternatives écartées** : identifiants dans les paramètres des nœuds façon n8n (dispersion des secrets, pas de quotas centralisés) ; un modèle par famille (duplication).
- **Conséquences** : ajouter une source ou un moteur revient à écrire un type de connecteur, puis l'interface et la gouvernance suivent sans travail supplémentaire.

## ADR-022 — Agents de veille spécialisés orchestrés par workflow

- **Statut** : Proposée (2026-10-20)
- **Décision** : plutôt qu'un agent unique doté de tous les outils, des agents spécialisés (triage, PoC GitHub, réseaux sociaux, forums, avis éditeurs) tournent en parallèle dans le workflow, puis un agent de synthèse sans outil externe produit le dossier sourcé. Ils sont livrés en seed et entièrement paramétrables par espace.
- **Raisons** : moindre privilège (chaque agent n'a que ses connecteurs), parallélisme, coût maîtrisé (l'agent de triage peut arrêter la chaîne), qualité et évaluation agent par agent, choix du moteur et du modèle par agent, analyste capable de comprendre et de modifier chaque étape dans l'éditeur.
- **Conséquences** : plusieurs appels LLM par CVE, d'où le budget par CVE et le filtrage par le périmètre de veille en amont.

## ADR-023 — Zéro abonnement payant hors IA ; lecture gratuite de X

- **Statut** : Acceptée (2026-10-20), sur consigne du porteur : « le moteur de lecture sur X doit être gratuit ; aucun abonnement payant en plus de ceux utilisés par l'IA ».
- **Contexte** : l'API X est payante à l'usage depuis février 2026 et l'ancien palier gratuit est fermé aux nouvelles inscriptions. Les conditions d'utilisation de X interdisent le crawling et le scraping sans accord écrit, avec des dommages-intérêts forfaitaires annoncés pour les gros volumes.
- **Décision** :
  - Aucun service, API, abonnement ou SaaS payant n'est utilisé en dehors de l'abonnement IA. Chaque type de connecteur déclare une classe de coût (`free`, `free_account`, `ai_billed`), et un test bloquant refuse tout type payant.
  - X est lu par le connecteur `x_reader`, en trois couches : (1) découverte gratuite des URL de posts citées dans les sources déjà collectées ; (2) recherche web du moteur IA restreinte à `x.com`, facturée sur l'abonnement IA et plafonnée ; (3) en option, SearXNG auto-hébergé. Le texte d'un post s'obtient par l'oEmbed officiel de X (gratuit, sans authentification).
  - Exclus : l'API X payante, le scraping de x.com (y compris par navigateur headless), l'usage de comptes ou de jetons de session X (Nitter, twscrape), les revendeurs de données.
- **Alternatives écartées** : l'API X à l'usage (contraire à la consigne) ; le scraping avec des comptes (contraire aux conditions de X, risque juridique et financier pour l'entreprise, comptes bannis, maintenance permanente) ; la recherche Google, demandée le 2026-10-20 : l'API Custom Search JSON n'accepte plus de nouveaux clients et s'arrête le 1er janvier 2027, son remplaçant est payant, et l'interrogation automatisée de google.com est contraire aux conditions de Google et vite bloquée (spec 07 §2.1, Q32) ; Brave Search API (carte bancaire obligatoire, facturation au-delà des crédits gratuits).
- **Principe du strict nécessaire** (2026-10-20) : requêtes limitées à l'identifiant CVE et restreintes à x.com, seuls l'URL, le titre et l'extrait sont conservés, au plus 5 posts lus par CVE, jamais de profil ni de timeline, conservation minimale, plafonds avec arrêt dur.
- **Conséquences** : la couverture de X est partielle (pas de recherche exhaustive en temps réel, pas de suivi de comptes), d'où un indicateur de couverture (phase 4) et un poids accru de Mastodon et Bluesky. La couche 2 dépend du moteur IA : avec un LLM auto-hébergé, seules les couches 1 et 3 restent. Le reste de la pile suit la même règle : composants open source, e-mail via le SMTP existant, certificats Let's Encrypt ou PKI interne, CI dans le quota gratuit ou sur un runner auto-hébergé.

## ADR-024 — Vulnérabilités partagées entre VOC et CERT, qualification par équipe

- **Statut** : Acceptée (2026-10-20, Q2, Q2a, Q2b, Q2c)
- **Décision** :
  - La fiche vulnérabilité est **globale** : une seule fiche par CVE (ou par vulnérabilité sans CVE), avec les preuves et les synthèses IA visibles par les deux équipes, l'équipe d'origine étant indiquée.
  - La **qualification est propre à chaque équipe** (table `vulnerability_assessments` : statut, priorité, assigné, commentaire de qualification, par espace). Quand une équipe qualifie, l'autre voit « qualifiée par l'autre équipe » avec le détail, et un bouton **« Reprendre cette qualification »** recopie la qualification dans son espace (action auditée).
  - Restent cloisonnés par espace : agents, workflows, modèles, connecteurs d'espace, configuration, périmètre de veille, bulletins non publiés. Un bulletin publié est lisible par l'autre équipe.
  - Les workflows des deux espaces font un `vuln.upsert` sur la même fiche (clé : identifiant CVE ou alias), sans doublon. Une recherche d'agents déjà faite par une équipe peut être réutilisée par l'autre (économie de quota).
- **Conséquences** : la RLS des fiches vulnérabilités est globale pour les internes (aucun client n'y accède) ; la RLS par espace s'applique aux évaluations, bulletins, agents et workflows.

## ADR-025 — Moteur IA de démarrage : Gemini, palier gratuit

- **Statut** : Acceptée (2026-10-20, Q7, Q7a)
- **Contexte** : budget IA de 0 €. L'abonnement Claude Pro (claude.ai) n'inclut pas l'accès API, et ses conditions excluent l'usage automatisé par une application multi-utilisateur. Le LLMaaS envisagé n'est pas encore disponible.
- **Décision** :
  - Moteur préféré au démarrage : **Gemini, palier gratuit de Google AI Studio**, via un adaptateur `gemini` (SDK officiel `google-genai`) : sorties structurées, appels de fonctions, et **recherche Google intégrée** (grounding) pour la découverte des posts X, dans la limite du quota gratuit.
  - **Aucune facturation** n'est activée sur le projet Google : au-delà du quota, les requêtes échouent au lieu d'être facturées. Un limiteur de débit respecte les quotas gratuits ; arrêt dur et alertes.
  - Politique de données du palier gratuit : uniquement des données publiques et TLP:CLEAR, car le fournisseur peut réutiliser les données du palier gratuit.
  - Les adaptateurs **compatible OpenAI** (pour le futur LLMaaS) et **Claude** (si un budget API apparaît) sont développés et testés avec des serveurs simulés ; la bascule est une configuration.
- **Conséquences** : débit limité, donc on donne la priorité aux CVE du périmètre (KEV, P1 d'abord) et on file d'attente le reste. La qualité doit être mesurée (banc d'évaluation facultatif). L'adaptateur `gemini` s'ajoute à la liste de la spec 07 §4.

## ADR-026 — SDK officiels des fournisseurs IA, branchés sur `SafeHttpClient`

- **Statut** : Acceptée (2026-10-21, phase 4)
- **Contexte** : les specs 03 et ADR-025 prévoient les SDK officiels (`anthropic`, `google-genai`), mais un SDK ouvre par défaut ses propres connexions, ce qui contournerait la règle non négociable « tout appel sortant passe par `SafeHttpClient` et le proxy de sortie ».
- **Décision** :
  - Les adaptateurs Claude et Gemini utilisent les **SDK officiels**, auxquels on fournit un client HTTP dont le transport délègue chaque requête à `SafeHttpClient` (`app/ai/engines/transport.py` : `httpx2` pour `anthropic` 1.x, `httpx` pour `google-genai`). Domaines déclarés, contrôle des adresses, proxy, taille bornée et décompression bornée s'appliquent donc aux appels de modèles. Le client synchrone de `google-genai` est remplacé par un transport qui refuse tout.
  - L'adaptateur **compatible OpenAI** parle directement le protocole `/chat/completions` par `SafeHttpClient` : les serveurs visés (LLMaaS, vLLM, Ollama, Mistral) n'ont pas de SDK commun, et le mode outils émulé demande la maîtrise du protocole.
  - Deux tests bloquants : seuls les adaptateurs importent un SDK de fournisseur (`tests/security/test_ai_isolation.py`), et seul le transport importe une bibliothèque HTTP (`tests/security/test_egress_guard.py`).
  - Le streaming n'est pas utilisé pour l'instant (réponses tamponnées, délai de 180 s par défaut) ; il viendra avec la génération des drafts (phase 6) si les sorties longues l'exigent.
- **Conséquences** : une mise à jour majeure d'un SDK (changement de bibliothèque HTTP) doit être suivie d'un test de l'adaptateur de transport ; les tests unitaires font tourner les SDK réels contre des serveurs simulés.

## ADR-027 — Le worker IA détient aussi le trousseau des sources (outils des agents)

- **Statut** : Acceptée (2026-10-21, phase 4)
- **Contexte** : la boucle d'un agent alterne appels au moteur (trousseau `llm`) et outils en lecture seule sur les connecteurs de veille (`github`, `bluesky`… : trousseau `source`). Répartir chaque appel d'outil sur `worker-collect` imposerait un aller-retour par la file à chaque tour, et l'agent devrait attendre un autre worker au milieu d'un appel de modèle.
- **Décision** :
  - `worker-ai` monte les trousseaux `llm` **et** `source`. Il ne reçoit jamais `connector` (publication) ni `webhook` : un agent ne peut ni publier ni recevoir.
  - Un outil n'ouvre que les connecteurs **autorisés par la version de l'agent** (`allowed_connectors`), actifs, de la famille `source`, de l'espace ou globaux ; les règles du connecteur (domaines déclarés, taille, quotas, proxy de sortie) s'appliquent comme pour un nœud de collecte.
  - Les jetons de source sont des jetons gratuits en lecture seule (ADR-023) ; leur exposition au processus qui manipule du contenu non fiable est acceptée, puisqu'aucun outil n'exécute de code ni n'écrit.
- **Conséquences** : la compromission de `worker-ai` expose les secrets `llm` et `source`, pas ceux de publication. Le tableau de SECURITY.md et le fichier `deploy/docker-compose.yml` sont alignés.

## ADR-028 — Recherche web du moteur IA pour découvrir les posts X (couche 2)

- **Statut** : Acceptée (2026-10-22, phase 4) ; modifiée le 2026-10-22 (couche 2 activée par défaut, Q36)
- **Contexte** : Q32 retient, pour découvrir des posts X sans abonnement, les liens déjà collectés (couche 1) et la recherche web du moteur IA restreinte à x.com (couche 2). Cette recherche est un outil côté fournisseur : la requête part de chez Anthropic ou Google, pas de notre proxy de sortie (spec 03 §5).
- **Décision** :
  - `AIRequest.web_search` (domaines autorisés, nombre d'usages) est un paramètre abstrait ; Claude utilise l'outil serveur `web_search` avec `allowed_domains`, Gemini l'ancrage Google Search (sans filtre de domaine côté fournisseur) ; le compatible OpenAI refuse (`web_search_unsupported`) et la découverte garde sa couche 1.
  - La couche 2 est **activée par défaut** (Q36, choix du porteur du projet pour la couverture de X) : l'espace peut la désactiver sur son connecteur `x_reader` (`engine_web_search`) pour s'en tenir aux liens déjà collectés. Ce trafic part de chez le fournisseur IA, hors de notre proxy : l'exception à la règle de spec 03 §5 (« choix explicite ») est assumée ici au niveau de la plateforme, pour cet usage seulement (identifiant CVE, domaines x.com et twitter.com). Sans moteur capable de recherche web (compatible OpenAI), seule la couche 1 tourne. Les connecteurs créés avant ce changement gardent la valeur enregistrée. La recherche ne porte que sur l'identifiant CVE (ou une requête courte nettoyée), restreinte à x.com et twitter.com, et consomme les quotas du connecteur.
  - Seules des URL de posts X sont retenues, comme candidates : chacune est lue ensuite par l'oEmbed officiel, et une URL inventée revient « retirée ». Le texte renvoyé par le moteur n'est jamais transmis tel quel.
  - Chaque recherche est un appel au moteur comme un autre : contrôle du budget, trace (`purpose: web_search`), coût estimé avec le prix par millier de recherches du modèle (`price_web_search_per_k`, 10 USD chez Claude ; gratuit dans le quota de Gemini).
- **Conséquences** : la couverture de X dépend du moteur préféré ; l'indicateur de couverture (`/workspaces/{espace}/x-coverage`) permet de le mesurer, en le comparant à un échantillon vérifié à la main. SearXNG reste écarté (Q30).

## ADR-029 — Rendu des bulletins : Liquid restreint, Markdown sans HTML, assainissement nh3

- **Statut** : Acceptée (2026-10-22, phase 6)
- **Contexte** : le gabarit de rendu est écrit par un analyste, les valeurs des champs viennent du moteur IA ou des données collectées (non fiables). Le HTML produit part vers le portail, l'e-mail et des API distantes.
- **Décision** :
  - Gabarit Liquid dans un environnement dédié : filtres en liste blanche (vérifiés statiquement à l'enregistrement, y compris sur les branches non atteintes par l'aperçu), sans `include` ni `render`, limites de boucles, de profondeur et de taille de sortie. Les valeurs sont insérées comme texte et ne sont jamais réinterprétées comme gabarit.
  - Markdown rendu par markdown-it-py en mode CommonMark avec `html=False` : le HTML présent dans une valeur est échappé.
  - HTML final assaini par nh3 : liste blanche de balises (titres, paragraphes, listes, tableaux, code, liens), liens `http`, `https` et `mailto` uniquement, avec `rel="noopener noreferrer nofollow"`, aucune image (pas de chargement distant sur le portail).
  - L'aperçu d'un modèle est calculé par le serveur avec exactement ces règles.
- **Conséquences** : un modèle ne peut pas produire de mise en forme hors de cette liste ; un lien inventé par le moteur reste possible en `http(s)` et passe par la relecture humaine (ADR-019).


## ADR-030 — Connecteur de publication HTTP générique et réseau privé sur approbation

- **Statut** : Proposée (2026-10-23), avec les réponses du porteur Q40 à Q43.
- **Contexte** : les API cibles sont inconnues (Q12). Il faut pouvoir en ajouter une par configuration, sans exécuter de code fourni et sans jamais exposer un secret. Le cloisonnement VOC/CERT empêche un admin de voir les connecteurs de l'autre équipe, alors qu'il doit décider des accès au réseau interne.
- **Décision** :
  - Un type de connecteur `http_generic` (famille `publish`), espace ou global (Q40). Sa configuration couvre :
    - la requête : URL, méthode, chemin en gabarit Liquid nourri de valeurs encodées, bloc `update` ;
    - l'authentification : `none`, `api_key`, `bearer`, `basic`, `oauth2_client_credentials`, `mtls` ou `hmac` ;
    - le corps : JSON par mapping, CSAF 2.0 ou Markdown ;
    - la réponse : statuts de succès et chemin JMESPath de l'identifiant distant ;
    - la clé d'idempotence, les reprises et le débit.
  - **Secrets** : ils vont dans des emplacements facultatifs pour le cadre, et le type d'authentification décide lesquels sont exigés (contrôle à l'enregistrement).
  - **Mapping** : c'est un arbre JSON dont chaque feuille est `const`, `path` (JMESPath, avec table de correspondance, valeur par défaut et format) ou `template` (Liquid restreint). Le corps est construit comme une valeur puis sérialisé, et les données lues ne sont jamais compilées. Les limites portent sur la profondeur, le nombre de nœuds et la taille.
  - **Contexte publié** : uniquement le bulletin validé (révision courante d'un bulletin `approved`, révision publiée d'un bulletin `published`), ses CVE et ses technos. Jamais une qualification interne ni un secret.
  - **Dry-run** : il est calculé par l'API, qui ne déchiffre aucun secret. Chaque identifiant et chaque signature y sont masqués. L'envoi réel se fait uniquement dans le worker `publish`, qui détient la clé de la famille.
  - **mTLS** : le certificat et la clé client sont chargés en mémoire (`memfd`), jamais écrits sur disque. Une publication ne suit aucune redirection.
  - **Réseau privé** (Q41) : l'équipe dépose une demande (plages privées, au plus larges /8 ou /32, et un motif) dans `private_network_requests`. Les admins plateforme voient toutes les demandes (nom du connecteur, hôtes, plages, demandeur) sans voir les connecteurs eux-mêmes, et approuvent, refusent ou révoquent, avec audit. Le worker n'applique une plage que si la dernière décision approuvée couvre exactement les hôtes et les plages actuels du connecteur. Changer d'URL ou de plages fait donc retomber l'accès. HTTP en clair n'est permis que vers une plage approuvée.
  - **CSAF 2.0** (Q42) : l'éditeur (nom, catégorie, espace de noms) est un réglage de l'espace, et l'export est refusé tant qu'il est vide. Le document suit le profil `csaf_security_advisory` et est vérifié contre le schéma OASIS.
  - **MFA** (Q43) : une MFA récente est exigée pour créer ou modifier un connecteur, ainsi qu'au premier envoi d'un bulletin vers un connecteur. Les mises à jour suivantes du même bulletin vers le même connecteur n'en redemandent pas.
- **Alternatives écartées** :
  - un nœud « requête HTTP » avec identifiants dans les paramètres : contraire à ADR-021 ;
  - un code de mapping (Python, JavaScript) : refusé par la règle « pas d'exécution de code fourni » ;
  - l'approbation écrite par l'admin directement sur le connecteur de l'autre espace : elle obligerait l'API à écrire hors du contexte RLS de l'admin.
- **Conséquences** :
  - les cibles connues plus tard (MISP, OpenCTI, TheHive…) seront des préréglages de configuration ;
  - le jeton OAuth2 n'est conservé que dans la mémoire du worker, jusqu'à peu avant son expiration ;
  - les secrets de connecteur peuvent être globaux, pour les connecteurs de publication communs.

## ADR-031 — Portail client : instantanés de publication et vues dédiées

- **Statut** : Proposée (2026-10-23).
- **Contexte** : une mise à jour en cours modifie les colonnes du bulletin (titre, TLP, audience, sévérité) avant toute validation. Lire ces colonnes pour le portail ferait fuir du contenu non publié, et un passage en RED ou un changement d'audience ne prendrait pas effet au bon moment. Le rôle `vv_portal` ne doit lire aucune table interne (8.2).
- **Décision** :
  - **Instantanés** : chaque publication, mise à jour publiée ou retrait enregistre un instantané dans `bulletin_publication_events` (révision publiée, titre, sévérité, TLP, audience, CVE, technos et équipe émettrice, tels qu'approuvés). Il est écrit dans la même transaction que la transition. Le portail ne lit que le dernier instantané : une modification n'atteint les clients qu'à la republication, et un retrait les retire immédiatement.
  - **Vues** : `portal_bulletins_v` et `portal_bulletin_history_v` sont des vues `security_barrier` appartenant au rôle de migration, qui lisent sans RLS et filtrent elles-mêmes sur l'organisation de la requête (`app.client_org_id`, organisation active) et sur les règles de Q22 :
    - CLEAR et GREEN : tous les clients ou les organisations choisies ;
    - AMBER et AMBER+STRICT : uniquement les organisations choisies ;
    - RED : jamais.
  - **Droits** :
    - `vv_portal` ne reçoit que la lecture de ces deux vues ;
    - `vv_app` et `vv_worker` perdent leurs privilèges par défaut sur elles et sur la vue intermédiaire `portal_published_v` ;
    - un test vérifie que le rôle portail ne lit aucune table interne.
  - **API** : l'API du portail (`/api/portal/v1/bulletins`) répond par des schémas en liste blanche (référence, titre, sévérité, TLP, langue, équipe, CVE, technos, dates, HTML assaini, historique).
- **Alternatives écartées** :
  - une RLS sur `bulletins` pour `vv_portal` : elle exposerait les colonnes courantes et toute la table au rôle portail ;
  - figer les colonnes du bulletin pendant une mise à jour : cela casserait l'édition et la relecture.
- **Conséquences** :
  - l'historique « mis à jour le … » et les envois par e-mail (8B) partent de ces instantanés ;
  - les bulletins déjà publiés reçoivent un premier instantané à la migration.

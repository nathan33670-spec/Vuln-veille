# CLAUDE.md — point d'entrée pour reprendre le développement

## Le projet en bref

**Vuln-Veille** est une plateforme multi-utilisateur de veille vulnérabilités :

- **vecteur d'entrée n°1 : chaque nouvelle CVE publiée sur NVD** lance automatiquement les agents de veille (ADR-020) ;
- un **orchestrateur de workflows** visuel (type n8n, moteur natif) éditable depuis l'application ;
- des **agents de veille** paramétrables par espace (PoC GitHub, X et réseaux, Stack Overflow, avis éditeurs, synthèse), qui accèdent à l'extérieur uniquement par des **connecteurs** configurés dans l'interface (ADR-021, ADR-022) ;
- un **moteur IA interchangeable** (ADR-011) : démarrage sur le **palier gratuit Gemini** (budget 0 €, ADR-025), puis LLMaaS compatible OpenAI, Claude via l'API si un budget apparaît ;
- des **vulnérabilités partagées** entre VOC et CERT, qualifiées par chaque équipe (ADR-024) ;
- une **qualification** des vulnérabilités par les analystes (VOC et CERT, espaces cloisonnés) ;
- la **rédaction assistée de bulletins** selon des modèles paramétrables ;
- la **publication** vers un portail client et vers des API distantes (connecteur HTTP générique) ;
- un **portail client** qui ne montre que les bulletins publiés (abonnements par techno : fonctionnalité à venir).

La sécurité est une exigence de premier rang : voir `docs/SECURITY.md`.

## Procédure de reprise (à suivre AVANT toute modification)

1. Lire `docs/PROGRESS.md` : état courant, dernière étape terminée, prochaine étape, points bloquants.
2. Vérifier l'état réel : `git fetch origin Main`, `git status`, `git log --oneline -20 origin/Main`. **Le code fait foi** : si `PROGRESS.md` et le code divergent, corriger d'abord `PROGRESS.md`.
3. Lire dans `docs/PLAN.md` la phase en cours (case cochée = fait et testé).
4. Lire la spec de la phase dans `docs/specs/` et les décisions concernées dans `docs/DECISIONS.md`.
5. Lire `docs/OPEN_QUESTIONS.md` : ne rien implémenter contre une réponse déjà donnée. Si une question bloque l'étape, appliquer l'hypothèse par défaut notée et le signaler.
6. Lancer `make lint test` (à partir de la phase 0) avant de modifier le code, pour partir d'un état vert.

## Règles de travail

- **`Main` est la seule branche principale, et elle reste propre** : on n'y pousse jamais directement. Tout changement part d'une branche courte créée depuis `Main` (`claude/<sujet>`, par exemple `claude/phase-4-ai-engines`), puis passe par une **merge request (PR GitHub) vers `Main`**. La merge request n'est fusionnée qu'avec la CI verte. Après la fusion, la branche est supprimée. Détail : `docs/PROCEDURES.md` §0.
- Commits petits et fréquents, au format Conventional Commits (`feat(iam): ...`, `fix(engine): ...`, `docs: ...`).
- À la fin de chaque étape du plan **et avant toute interruption probable** : mettre à jour `docs/PROGRESS.md` et cocher `docs/PLAN.md`, puis commit et push. Le conteneur est éphémère : ce qui n'est pas poussé est perdu.
- Toute décision structurante nouvelle ou modifiée se note en ADR dans `docs/DECISIONS.md`.
- Suivre `docs/PROCEDURES.md` : conventions, Definition of Done, ajout d'un nœud, d'un fournisseur LLM ou d'un connecteur.

## Règles de sécurité non négociables (détail dans docs/SECURITY.md)

- Autorisation **refusée par défaut** : chaque route déclare sa permission, et un test fait échouer la CI si une route n'en déclare pas.
- Toute donnée d'espace (VOC/CERT) est filtrée par `workspace_id` dans le code **et** par la Row-Level Security PostgreSQL.
- Aucune exécution de code fourni par l'utilisateur : pas de nœud « Code », pas d'`eval`. Les expressions passent par JMESPath et les gabarits par Liquid.
- Tout appel HTTP sortant passe par `SafeHttpClient` (anti-SSRF) **et** par le proxy de sortie, et tout accès à un service externe passe par un **connecteur** (jamais d'identifiants dans les paramètres d'un nœud).
- Aucun code propre à un fournisseur IA en dehors de `backend/app/ai/engines/` : les agents n'utilisent que les paramètres abstraits d'`AIEngine`, pour que le passage de Claude à un LLM open source reste une simple configuration.
- Aucun code récupéré (PoC, dépôts) n'est jamais exécuté.
- **Aucun service, API ou abonnement payant en dehors de l'abonnement IA** (ADR-023). X se lit gratuitement (découverte d'URL et oEmbed officiel), jamais par l'API X payante ni par scraping. Chaque type de connecteur déclare sa classe de coût, et un test bloquant refuse les types payants.
- Le contenu collecté et les sorties des LLM ne sont **pas fiables** : validation par schéma, assainissement, jamais interprétés comme gabarit ou instruction, jamais publiés sans validation humaine.
- Les secrets sont chiffrés au repos, en écriture seule via l'API, et jamais journalisés. Aucun secret ni identifiant par défaut dans le dépôt. **Le dépôt GitHub est public** : aucune donnée interne non plus.
- Les réponses de l'API passent par des schémas Pydantic dédiés, jamais par une sérialisation directe de l'ORM, surtout côté portail.

## Conventions

- Code, identifiants et commentaires en anglais ; documentation et interface en français (i18n prête).
- Backend : Python 3.13, FastAPI, SQLAlchemy 2 async, Alembic, Celery/Redis, gestion des paquets par `uv`.
- Frontend : TypeScript strict, React, Vite, pnpm workspaces (`apps/backoffice`, `apps/portal`).
- Commandes (créées en phase 0) : `make dev`, `make test`, `make lint`, `make typecheck`, `make migrate`, `make security`.

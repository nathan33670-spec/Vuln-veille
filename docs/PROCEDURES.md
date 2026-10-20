# PROCEDURES — Développement, conventions et reprise

## 1. Procédure de reprise après interruption

1. Lire `CLAUDE.md`, puis `docs/PROGRESS.md` (section « État courant »).
2. `git fetch origin claude/veille-management-tool-845y6h && git status && git log --oneline -20`.
3. Si `PROGRESS.md` annonce une étape « en cours » : relire le diff des derniers commits, lancer `make lint test`, puis terminer l'étape ou revenir à un état cohérent.
4. Reprendre à la « Prochaine étape » de `PROGRESS.md`, en s'appuyant sur la spec de la phase (`docs/specs/`).
5. Ne jamais recommencer une étape cochée sans raison écrite dans `PROGRESS.md`.

## 2. Boucle de travail par étape

1. Annoncer l'étape dans `PROGRESS.md` (« En cours : 1.3 Sessions »).
2. Écrire les tests en même temps que le code, voire avant pour la sécurité et l'autorisation.
3. `make lint typecheck test` doit être vert.
4. Relire la checklist de sécurité (SECURITY.md §5).
5. Mettre à jour la documentation impactée (spec, ADR, OPEN_QUESTIONS).
6. Cocher l'étape dans `PLAN.md`, mettre à jour `PROGRESS.md` (fait, prochaine étape, points d'attention).
7. Commit (Conventional Commits) et push sur la branche.

Pour une étape longue : commits intermédiaires réguliers (« wip » interdit, préférer des commits cohérents et verts), et `PROGRESS.md` mis à jour au moins toutes les quelques heures de travail.

## 3. Definition of Done

Une étape est terminée quand :

- [ ] le code est fusionné sur la branche et poussé ;
- [ ] les tests unitaires et d'intégration couvrent le nominal, les erreurs et les cas d'autorisation ;
- [ ] lint, typage (mypy strict, tsc strict) et tests sont verts en local et en CI ;
- [ ] les migrations Alembic sont créées, réversibles, et la RLS est posée sur les nouvelles tables cloisonnées ;
- [ ] les permissions sont déclarées et la matrice d'autorisation est à jour ;
- [ ] la checklist de sécurité est relue ;
- [ ] la documentation, `PLAN.md` et `PROGRESS.md` sont à jour.

## 4. Conventions de code

### Général

- Anglais pour le code, les identifiants, les commentaires et les messages de log ; français pour la documentation et l'interface (clés i18n).
- Commits : `type(scope): description` avec les types `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `sec`, et les scopes `iam`, `engine`, `nodes`, `ai`, `bulletins`, `publishing`, `portal`, `vulns`, `catalog`, `infra`, `ui`.
- Pas de secrets dans le dépôt : `.env.example` documente les variables, `.env` est ignoré.

### Backend

- Structure de module : `models.py`, `schemas.py`, `repository.py`, `service.py`, `api.py`, `permissions.py`.
- Les routes appellent des services ; les services appellent des repositories ; les repositories exigent un `Scope`.
- Schémas Pydantic distincts pour l'entrée (`XCreate`, `XUpdate`) et la sortie (`XOut`, `PortalXOut`). Pas de `from_attributes` sur les schémas du portail sans liste explicite de champs.
- Async partout dans l'API ; les tâches Celery appellent des services via un pont async contrôlé.
- Erreurs métier : exceptions typées, converties en RFC 9457 par un handler unique.
- Logs : `structlog`, clés `snake_case`, jamais de secret, de corps de requête complet ni de contenu collecté entier.
- Migrations : un fichier par changement logique, nommé `YYYYMMDD_HHMM_description`.

### Frontend

- TypeScript strict, pas de `any` non justifié.
- Appels d'API uniquement via `packages/api-client` (types générés). Régénérer après chaque changement d'API (`make api-client`).
- Pas de `dangerouslySetInnerHTML` sauf à travers le composant `SafeHtml` (DOMPurify et Trusted Types).
- Toute chaîne visible passe par i18n.

### Tests

- Backend : `tests/unit` (pur), `tests/integration` (PostgreSQL et Redis via testcontainers), `tests/security` (permissions, matrice, SSRF, XSS, injection de prompt).
- Fabriques de données (factory_boy ou équivalent) ; jamais de données réelles de clients.
- Les appels LLM sont simulés dans les tests (fixtures de réponses enregistrées), sauf dans une suite d'évaluation optionnelle, lancée manuellement et budgétée.

## 5. Ajouter un type de nœud de workflow

1. Créer `backend/app/workflows/nodes/<categorie>/<nom>.py` avec une classe qui implémente `NodeType` : `type` (par exemple `source.rss`), `version`, `category`, `Params` (modèle Pydantic qui génère le JSON Schema), ports d'entrée et de sortie, `queue` (`default`, `collect`, `ai` ou `publish`), `required_permissions`, `uses_egress`, et `async def execute(ctx, inputs) -> outputs`.
2. L'enregistrer dans le registre (`nodes/__init__.py`).
3. Respecter les règles : HTTP via `ctx.http` (SafeHttpClient) uniquement, secrets via `ctx.secrets.get(ref)` (vérification de l'espace), éléments marqués `trust="untrusted"` s'ils viennent de l'extérieur, limites de taille et de nombre appliquées.
4. Tests : paramètres valides et invalides, exécution nominale avec des réponses HTTP simulées, erreurs et retries, limites.
5. Ajouter l'icône et la catégorie côté frontend (le formulaire est généré depuis le schéma) et un libellé i18n.
6. Documenter le nœud dans `docs/specs/02-workflow-engine.md` (catalogue).
7. Tout changement incompatible des paramètres crée une nouvelle `version` du nœud ; les anciennes versions restent exécutables pour les workflows existants.

## 6. Ajouter un moteur IA (nouvel adaptateur)

Un nouveau modèle sur un serveur compatible OpenAI (OpenLLM, vLLM, Ollama…) **ne demande pas de code** : on crée un connecteur `openai_compatible` dans l'interface, on lance le test de capacités puis le banc d'évaluation. Un adaptateur n'est à écrire que pour une API non compatible.

1. Implémenter `AIEngine` dans `backend/app/ai/engines/<nom>.py` : `complete`, `stream`, outils (natifs ou émulés), sortie structurée, traduction des paramètres abstraits (niveau de raisonnement…), mapping de l'usage (tokens, cache) et des stop reasons, y compris le refus.
2. Déclarer ses capacités et implémenter le test automatique de capacités.
3. Tests avec des réponses enregistrées ; aucun appel réel en CI. Faire passer le corpus d'injection de prompt avec ce moteur simulé.
4. Déclarer le type de connecteur `ai_engine` (schéma de configuration, emplacements de secrets, domaines de sortie, politique de données par défaut).
5. Avant d'en faire le moteur préféré d'un espace ou de la plateforme : banc d'évaluation, puis rapport de compatibilité des agents.

## 6 bis. Ajouter un connecteur de veille

1. Créer `backend/app/connectors/<type>/` : `ConfigModel` (Pydantic, qui génère le formulaire), emplacements de secrets, `egress_domains`, `health_check()` sans effet de bord, client utilisant `SafeHttpClient`, gestion des quotas et du budget.
2. Exposer ses capacités aux nœuds (`source.<type>`) et aux outils d'agents (`<type>_search`…) ; les éléments produits sont marqués `trust="untrusted"`.
3. Respecter les conditions d'utilisation et le robots.txt, avec un User-Agent identifiable et une limitation de débit.
4. Tests : configuration valide et invalide, test de connexion, pagination, quotas épuisés, erreurs HTTP, contenus piégés.
5. Ajouter le type au catalogue de la spec 07 §2 et l'icône et les libellés côté interface.

## 7. Ajouter un préréglage de connecteur de publication

1. Partir du connecteur HTTP générique : un préréglage est un ensemble de valeurs par défaut (authentification, chemins, mapping) dans `backend/app/publishing/presets/<nom>.yaml`.
2. Ajouter un test de mapping (bulletin de référence vers payload attendu) et un test contre un serveur simulé.
3. Documenter dans `docs/specs/05-publishing-connectors.md`.

## 8. Gestion des dépendances

- Ajouter une dépendance uniquement si elle est maintenue (version récente, mainteneurs actifs), avec une licence compatible et sans vulnérabilité connue.
- Épingler la version dans `uv.lock` ou `pnpm-lock.yaml` ; prendre une version publiée depuis au moins deux semaines. C'est automatique : `exclude-newer` dans `backend/pyproject.toml` (date à avancer délibérément) et `minimumReleaseAge` dans `frontend/pnpm-workspace.yaml`.
- **Exception : correctif de sécurité.** Un correctif d'une vulnérabilité connue s'applique tout de suite, paquet par paquet (`exclude-newer-package` côté Python), avec la référence de l'avis en commentaire.
- Images Docker et GitHub Actions : épinglées par digest ou SHA de commit, avec la version en commentaire. Caddy et smokescreen sont compilés depuis les sources avec une chaîne Go corrigée : au moindre avis Go ou `x/net`, monter les versions dans leurs Dockerfiles.
- TypeScript est figé en 6.x (`overrides` pnpm) tant que l'outillage ne prend pas en charge TypeScript 7.
- Justifier l'ajout dans le message de commit.

## 9 bis. Particularités de l'environnement cloud Claude Code

- Le hook `SessionStart` (`scripts/session-start.sh`) installe les dépendances et lance `dockerd` si possible.
- Le proxy réseau du conteneur intercepte TLS avec sa propre autorité (`/root/.ccr/ca-bundle.crt`) : les **builds Docker** échouent avec `SELF_SIGNED_CERT_IN_CHAIN`. Ce n'est pas un défaut du dépôt. Pour vérifier localement, générer dans le scratchpad des variantes des Dockerfiles qui copient cette autorité (contexte additionnel `--build-context sandboxca=/root/.ccr`), construire avec `docker build`, puis `docker compose ... up --no-build`. Ne jamais commiter ces variantes.
- Les tests d'intégration (testcontainers) fonctionnent dès que `dockerd` tourne.

## 9. Gestion des secrets en développement

- `make dev` génère un `.env` local à partir de `.env.example`, avec des KEK aléatoires de développement.
- Les identifiants de sources et de LLM se saisissent par l'interface (coffre de secrets), jamais dans le code ni dans le `.env` commité.

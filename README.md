# Vuln-Veille

Plateforme multi-utilisateur d'orchestration de la veille vulnérabilités. Elle réunit des workflows visuels (type n8n), des agents IA de collecte et de synthèse, la qualification des vulnérabilités par les analystes VOC et CERT, la rédaction assistée de bulletins selon des modèles paramétrables, et la publication vers un portail client et des API distantes.

> **Statut** : phase 0 (fondations) terminée. Voir [docs/PROGRESS.md](docs/PROGRESS.md).

## Démarrage rapide

Prérequis : Docker (avec Compose), `uv`, Node 22 et `pnpm`.

```sh
make install          # dépendances backend et frontend
make check            # lint, typage, tests unitaires et de sécurité
make test-integration # tests avec PostgreSQL et Redis (Docker)
make env              # crée .env avec des secrets aléatoires (jamais commité)
make up               # construit et démarre la pile complète
./scripts/smoke-test.sh
```

Back-office : https://backoffice.localhost — portail : https://portal.localhost (certificats de l'autorité locale de Caddy en développement). `make help` liste toutes les commandes.

## Documentation

| Document | Contenu |
|---|---|
| [CLAUDE.md](CLAUDE.md) | Point d'entrée et procédure de reprise du développement |
| [docs/PLAN.md](docs/PLAN.md) | Vision, périmètre, exigences, feuille de route par phases (cases à cocher) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Composants, stack, arborescence, déploiement, flux principaux |
| [docs/RBAC.md](docs/RBAC.md) | Rôles, périmètres et matrice des permissions |
| [docs/SECURITY.md](docs/SECURITY.md) | Modèle de menace, mesures de sécurité, checklist |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Décisions d'architecture (ADR) |
| [docs/OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md) | Questions ouvertes et hypothèses par défaut |
| [docs/PROCEDURES.md](docs/PROCEDURES.md) | Procédures de développement, conventions, Definition of Done |
| [docs/PROGRESS.md](docs/PROGRESS.md) | Journal d'avancement |
| [docs/specs/](docs/specs/) | Spécifications détaillées par domaine |

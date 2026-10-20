# PROGRESS — Journal d'avancement

## État courant

- **Phase** : cadrage terminé, **en attente du feu vert** du porteur du projet pour démarrer le développement.
- **Dernière étape terminée** : rédaction de la documentation de cadrage (plan, architecture, RBAC, sécurité, ADR, questions ouvertes, procédures, specs).
- **Étape en cours** : aucune.
- **Prochaine étape** : Phase 0, étape 0.1 (arborescence du monorepo), dès le feu vert.
- **Points bloquants** : aucun pour la phase 0. Les questions Q1, Q2 et Q8 (OPEN_QUESTIONS.md) doivent idéalement être tranchées avant la phase 1 ; à défaut, on applique les hypothèses par défaut.

## Journal

### 2026-10-20 — Session 1 : cadrage

- Dépôt vide au départ, branche `claude/veille-management-tool-845y6h`.
- Analyse du besoin et choix d'architecture : moteur de workflows natif plutôt que n8n embarqué (ADR-004), backend Python/FastAPI, frontend React, deux applications (back-office et portail), PostgreSQL avec RLS, Celery et Redis.
- Documents créés : `CLAUDE.md`, `README.md`, `docs/PLAN.md`, `docs/ARCHITECTURE.md`, `docs/RBAC.md`, `docs/SECURITY.md`, `docs/DECISIONS.md`, `docs/OPEN_QUESTIONS.md`, `docs/PROCEDURES.md`, `docs/specs/01` à `06`.
- Toutes les ADR sont au statut « Proposée », à passer en « Acceptée » après validation.

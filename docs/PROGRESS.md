# PROGRESS — Journal d'avancement

## État courant

- **Phase** : cadrage terminé (révision 2), **en attente du feu vert** du porteur du projet pour démarrer le développement.
- **Dernière étape terminée** : intégration des consignes de la session 2 (NVD vecteur d'entrée n°1, connecteurs, paramétrage des agents de veille, moteur IA interchangeable).
- **Étape en cours** : aucune.
- **Prochaine étape** : Phase 0, étape 0.1 (arborescence du monorepo), dès le feu vert.
- **Points bloquants** : aucun pour la phase 0. À trancher idéalement avant la phase 1 : Q1, Q2 et Q8 ; avant la phase 2 : Q23 (quelles CVE lancent les agents) et Q24 (délai de détection). À défaut, on applique les hypothèses par défaut.

## Journal

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

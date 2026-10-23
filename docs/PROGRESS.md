# PROGRESS — Journal d'avancement

## État courant

- **Phase** : 8 (portail client) **terminée** : critère de sortie atteint et testé dans un navigateur. La phase 9 (abonnements et demandes de technos) est une fonctionnalité « à venir ».
- **Dernière étape terminée** : écrans du portail (merge request 8C, fusionnée). Côté client : liste, recherche, filtres, détail, historique, exports PDF/HTML/Markdown, impression, préférence e-mail, en-tête aux couleurs de l'émetteur. Côté back-office : page de charte. Le critère de sortie est testé dans un navigateur. Les trois merge requests de la phase 8 (8A, 8B, 8C) sont fusionnées. Le guide de mise en service est rédigé : `docs/DEPLOYMENT.md`.
- **Étape en cours** : merge request « modèle IA local » en revue (branche `claude/ai-engine-private-network`, ADR-032) :
  - éditeur de moteur IA dans l'interface (modèles, données autorisées, secrets) ;
  - réseau privé sur approbation pour les moteurs ;
  - autorité de certification interne ;
  - HTTP et port propre vers une plage approuvée ;
  - carte « Interroger le modèle » ;
  - `allow_ranges` de smokescreen générée ;
  - étape LLM du test de fumée (`VV_SMOKE_LLM_CONNECTOR`).
- **Prochaine étape** : phase 9 (abonnements et demandes de technos), demandée par le porteur du projet après cette merge request.
- **Points d'attention** :
  - Moteurs IA (ADR-026) : seuls `app/ai/engines/*` importent un SDK de fournisseur, et seul `app/ai/engines/transport.py` importe une bibliothèque HTTP ; deux tests bloquants le vérifient. Ajouter un moteur : sous-classer `EngineConnectorType` (catalogue des modèles et vérification des capacités fournis), écrire l'adaptateur, le tester contre un serveur simulé (`tests/unit/test_ai_engines.py`). Le SDK Gemini envoie certains champs en snake_case (`thinking_level`) : c'est accepté par l'API.
  - Les modèles par défaut des connecteurs (Gemini `gemini-2.5-flash`, Claude `claude-opus-5-5`) sont des valeurs de départ : vérifier la liste du palier gratuit dans AI Studio (Q35).
  - **Branches** : `Main` est la seule branche principale ; chaque sujet se développe sur une branche `claude/<sujet>` partie de `Main` et revient par une merge request, fusionnée avec la CI verte (PROCEDURES §0). L'ancienne branche `claude/veille-management-tool-845y6h` est fusionnée et supprimée.
  - Sous le rôle `vv_portal`, la RLS masque une ligne à peine insérée : **pas de `RETURNING`** sur les insertions du portail (renseigner les horodatages côté application).
  - Le garde « toute route a une politique » doit passer par `fastapi.routing.iter_route_contexts` (FastAPI 0.142 enveloppe les routeurs inclus) ; il échoue si moins de 10 routes sont trouvées.
  - Smokescreen accepte les clients sans rôle (ACL `default`) : prévoir des rôles mTLS par type de worker en phase 2.
  - Environnement cloud : builds Docker uniquement via les variantes avec l'autorité du proxy (PROCEDURES §9 bis). Avant un test de la pile locale, partir d'un `.env` régénéré et de volumes vides (`down -v`) : un `.env` ou un volume Postgres d'une session précédente fait échouer `migrate`.
  - Dépendances Go de Caddy et smokescreen figées dans `deploy/*/build/go.{mod,sum}` (montée de version : PROCEDURES §8).
  - Frontend : aucun attribut `style` (CSP) ; les styles vont dans `packages/ui/src/styles.css`. jsdom n'implémente pas `<dialog>.showModal` : polyfill dans `packages/auth/src/test-setup.ts`.
  - Les requêtes typées d'openapi-fetch attendent `null` (et non `undefined`) pour les paramètres facultatifs (`exactOptionalPropertyTypes`).
  - Coffre : l'API n'a que les clés publiques ; un trousseau privé ne se monte que dans le worker de son usage (PROCEDURES §9). `make env` refuse d'écraser des trousseaux existants.
  - Sortie réseau : les workers n'ont **ni DNS externe ni route** ; en mode proxy, `SafeHttpClient` ne résout pas les noms et laisse smokescreen résoudre et filtrer. Obtenir un client par `egress_client(settings, policy)`, jamais directement.
  - L'environnement cloud ne donne pas Internet à smokescreen : un appel réel (NVD…) échoue en `network_error` dans le bac à sable, pas en CI ni en production.
  - NVD : une CVE inconnue n'est annoncée (`cve.published`) que si elle a été publiée depuis moins de 14 jours (paramétrable) ; sinon elle est cataloguée sans événement. Le rattrapage initial n'émet aucun événement.
  - Connecteurs enregistrés : `nvd`, `cisa_kev`, `epss`, `cve_org` (globaux). Une source globale synchronisée déclare `syncs = True`, un champ `sync_interval_minutes` et une méthode `sync` ; la tâche `collect.connector_sync` et le scheduler s'occupent du reste. Après l'ajout d'un type, régénérer `deploy/smokescreen/acl.yaml` par `python -m app.cli egress-acl --static-only --output ../deploy/smokescreen/acl.yaml` (un test vérifie la couverture).
  - Réseau privé des connecteurs : file d'approbation par les admins plateforme (Q41, ADR-030), côté API en 7A ; l'interface d'approbation vient en 7C. Les demandes ne concernent que les connecteurs de publication d'un espace pour l'instant.
  - Écart assumé (2.7) : « import depuis le dictionnaire CPE » est réalisé par des suggestions tirées des configurations CPE déjà synchronisées depuis NVD (`/technologies/cpe-suggestions`), sans appel à l'API CPE de NVD : l'API n'a pas d'accès Internet et la donnée est déjà là.
  - Lecture partagée (ADR-024) : `/vulnerabilities`, `/cves` et `/technologies` demandent `vuln.read` (tous les internes, lecteurs compris) ; les écritures passent par `/workspaces/{espace}/…` avec `vuln.qualify`. Les évaluations sont lisibles par l'autre équipe, modifiables par la sienne seulement (RLS).
  - Les éditeurs de texte de l'outil de développement transforment parfois les échappements `\u…` en caractères invisibles : un test bloquant (`tests/security/test_source_hygiene.py`) refuse tout caractère invisible ou de contrôle bidirectionnel dans le code.
  - Critère de sortie de la phase 2 aligné sur ADR-024 (décision du porteur) : le CERT voit la fiche et la qualification du VOC et peut la reprendre ; seuls les commentaires, le périmètre, les sources, connecteurs et secrets restent cloisonnés. L'ancienne formulation (« le CERT ne voit pas la vulnérabilité VOC ») datait d'avant cette décision.
  - Vérifié sur l'API NVD réelle (via le proxy du bac à sable, test temporaire non commité) : 159 `cve.published` sur 6 heures de modifications, format de dates accepté. Cette vérification a révélé les métriques SSVC (`ssvcV203`) qui faisaient rejeter 61 % des CVE : corrigé. Flux KEV et enregistrements CVE.org réels analysés sans erreur.
  - Interfaces : les textes externes (descriptions, références, preuves) s'affichent comme du texte, jamais comme du HTML ; les liens passent par `ExternalLink` (http(s) seulement, sans référent ni `opener`). Le rendu Markdown assaini des justifications et commentaires viendra avec les bulletins (phase 6) : affichage en texte brut d'ici là.
  - Moteur de workflows (ADR-005) : un nœud n'accède à la base que par `WorkspaceRepo` (périmètre de l'espace), à l'extérieur que par `ctx.connectors.open(id, kinds)` ; ses paramètres sont un modèle Pydantic (`expect(params, Modèle)` pour les typer). Ajouter un nœud : `app/workflows/nodes/`, `@register_node`, test unitaire ; les types `test.*` sont masqués de l'API.
  - Tests du moteur : `tests/integration/workflow_harness.py` exécute les tâches mises en file dans l'ordre (`drain`), et peut en « garer » pour simuler une perte (`skip_nodes`, `unpark`).
  - `TaskQueue.send` accepte `task_id` et `countdown` ; `revoke` sert à l'annulation. Les tâches de nœud ont pour identifiant celui du `node_run`.
  - Le worker `default` détient le trousseau `webhook` (vérification des signatures). La commande `seed-workflows` tourne après les migrations (service `migrate`) et ne recrée jamais un seed existant.
  - SQLAlchemy 2.1 : `Result.tuples()` et `select().distinct(expr)` sont dépréciés, et les avertissements font échouer les tests ; utiliser `.all()` et `.ext(distinct_on(...))`. Après un `commit`, un `updated_at` mis à jour côté serveur est expiré : `await db.refresh(obj)` avant de le lire (sinon `MissingGreenlet`).
  - Écarts assumés de la phase 3 : `test-node` et le flux SSE des exécutions arrivent avec l'éditeur visuel (phase 5), et l'écran d'exécution interroge l'API toutes les 3 secondes ; l'éditeur de graphe est provisoire (JSON validé par le serveur) ; les limites d'exécution ne sont pas encore réglables par espace ; la « Veille quotidienne » livrée ne lit que les ajouts KEV, car un flux RSS demande un connecteur propre à l'espace ; un secret de webhook reste dans le coffre si son nœud disparaît.
  - Connecteurs ajoutés : `rss` (domaines déclarés dans la configuration), `http_api` (lecture GET, en-tête d'authentification facultatif dans le coffre), `github` (jeton facultatif). Le fichier `deploy/smokescreen/acl.yaml` versionné garde la liste des services prévus ; en production, le générer avec les connecteurs actifs (`egress-acl` sans `--static-only`).
  - Agents (spec 03, `app/ai/agents/`) : une version d'agent est un JSON validé (`AgentSpec`) ; chaque exécution est liée à sa version. Le runtime (`runtime.py`) tourne dans `worker-ai`, qui détient aussi le trousseau `source` pour les outils (ADR-027). Ajouter un outil : l'ajouter à `TOOL_NAMES` (`spec.py`) et au registre `TOOLS` (`tools.py`) avec un schéma d'arguments strict, en lecture seule, et un test.
  - Le contenu non fiable va au modèle en **JSON** (`{"untrusted_document": {...}}`) plutôt qu'en balises : l'échappement JSON empêche de fermer le conteneur (même choix que l'émulation d'outils de 4A, Semgrep refusant le HTML construit à la main).
  - Budgets : `llm_budgets` (plafond, écrit par l'API) et `llm_spend` (dépense du mois, écrite par le worker seulement). Pas de ligne de budget = pas de plafond, coûts suivis quand même. Le coût est une estimation à partir des prix déclarés du modèle (gratuit = 0).
  - Écarts assumés de 4C : le rapport de compatibilité est par espace (`/workspaces/{espace}/ai-engine/compatibility`) ; au niveau plateforme, l'administrateur ne voit pas les agents des espaces (RLS), et chaque espace consulte son rapport. `x_discover` ne fait que la couche 1 (liens déjà collectés, références NVD) ; la recherche web du moteur restreinte à x.com viendra avec l'agent réseaux sociaux (4D). Les variantes de prompt par moteur et les outils serveur des fournisseurs ne sont pas encore proposés. Les alertes de budget partent par e-mail aux analystes de l'espace.
  - Nœuds IA (`app/workflows/nodes/ai.py`, file `ai`) : ils passent par le runtime d'agent (budgets, traces, garde-fous). Un agent échoué, refusé ou désactivé n'arrête pas le workflow : son statut est dans l'élément, sous `output_key`. Seuls un agent introuvable ou l'absence d'accès aux agents font échouer le nœud. Chaque exécution d'agent a sa propre session : sa trace survit à l'échec du nœud. Les tâches `ai.summarize`, `ai.classify`, `ai.extract` et `ai.relevance` sont des exécutions sans agent (`agent_runs.task` et `spec`, migration 0011).
  - Agents prédéfinis (`app/ai/agents/presets.py`) : créés par `seed-workflows` dans chaque espace, avant les workflows. Un agent dont les outils demandent un connecteur absent de l'espace est créé désactivé. Le « Rédacteur de bulletin » arrivera avec les bulletins (phase 6).
  - Seeds : une nouvelle livraison d'un seed ajoute une version non activée seulement si aucune version n'a été créée par un analyste. « Nouvelle CVE NVD » devient « Nouvelle CVE NVD → investigation » ; le test de sortie de la phase 3 garde sa propre copie du graphe sans IA.
  - Écarts assumés de 4D : la re-veille enregistre une nouvelle synthèse à chaque passage, au lieu de ne mettre à jour qu'en cas de nouveauté (historique conservé, alerte dédupliquée sur 30 jours) ; la comparaison avec la synthèse précédente viendra avec les interfaces (4.15). Les fusions parallèles passent par trois `transform.merge` en jointure sur `vulnerability_id`, le nœud n'ayant que deux entrées.
  - Corpus d'injection (`tests/security/injection_corpus.py`, joué par `tests/integration/test_injection_corpus.py`) : chaque charge piégée est placée dans chaque lieu de lecture d'un agent, puis un modèle entièrement compromis lui obéit, derrière les vrais adaptateurs (Claude par le SDK, compatible OpenAI natif et émulé). Ajouter une charge : un `Payload` avec le signal attendu ; le test vérifie l'absence de requête hors domaine, d'outil hors liste et d'écriture hors de la trace de l'agent. Les charges invisibles se construisent avec `chr` (test d'hygiène des sources).
  - Banc d'évaluation (`app/ai/evaluation/`) : cas de référence par espace (`expected` : champs clés validés par un analyste), exécution de la version active d'un agent épinglée sur le modèle candidat (`ai.evaluation_run`, budget propre et budget mensuel), notation déterministe (schéma, citations, refus, exactitude des champs, coût, latence), comparaison de deux exécutions. Le changement de moteur préféré accepte un `evaluation_id` facultatif, cité dans l'audit (Q26). La grille de relecture par un analyste ou un LLM juge n'est pas encore proposée.
  - Découverte de X, couche 2 (ADR-028, Q36) : activée par défaut, désactivable par l'espace sur son connecteur `x_reader` (`engine_web_search`) ; la recherche part de chez le fournisseur IA. Les connecteurs créés avant ce changement gardent leur valeur enregistrée. Le modèle préféré doit déclarer `web_search` (Claude et Gemini par défaut). La re-veille ne limite pas encore la couche 2 aux CVE KEV, P1 ou P2 (spec 07 §2.1) : à faire avec les interfaces, par une condition dans le workflow.
  - Indicateur de couverture de X (`app/ai/coverage.py`) : un post compte s'il est cité dans la sortie validée de l'agent « Réseaux sociaux » **et** lu par l'oEmbed pendant la même exécution ; comparaison avec les vérifications manuelles (`/x-coverage/checks`, permission `vuln.qualify`).
  - Interfaces de la phase 4 (`apps/backoffice/src/pages/ai/`) : moteurs IA (catalogue, moteur préféré bloqué tant que le rapport de compatibilité signale un agent incompatible, évaluation citée en option, budget et coûts du mois par agent), agents (liste, configuration en JSON validée par le serveur, versions et réactivation, bac à sable), traces d'exécution (signaux d'injection, sortie et étapes en texte inerte, liens http(s) seulement), banc d'évaluation (cas, exécutions, comparaison), couverture de X. Écarts assumés : l'édition d'un agent se fait en JSON (formulaire guidé avec l'éditeur visuel, phase 5) ; le tableau de bord des coûts agrège les 200 dernières exécutions du mois côté navigateur (agrégation serveur par agent et par jour à prévoir si le volume l'exige) ; la notation par grille du banc n'est pas encore proposée.
  - `ai.*` : paramètre `run_if` (condition par élément ; sinon l'élément passe avec le statut `skipped`, sans appel au moteur). La re-veille l'utilise pour ne relancer l'agent réseaux sociaux, donc la recherche X, que pour les CVE KEV, P1 ou P2.
  - Éditeur, côté serveur (phase 5) : `GET/PUT/DELETE …/workflows/{id}/draft` (brouillon unique par workflow, enregistré tel quel avec ses erreurs de validation, `stale` si une version a été publiée depuis son point de départ) ; `POST …/workflows/{id}/test-node` (graphe complet validé comme une publication, nœud exécuté seul sur le worker de sa file avec les éléments épinglés, en dry-run, écritures en base annulées ; 60 tests par heure et par utilisateur) ; `GET …/runs/{id}/events` (SSE : un événement `node` par changement d'état, puis `run`, dix minutes au plus, sans transaction ouverte). Les exécutions de test (`workflow_runs.mode = 'test'`, sans version) n'apparaissent ni dans l'historique ni dans « dernière exécution ». Les agents appelés pendant un test sont réellement exécutés (et comptés dans le budget) : seules les écritures du nœud sont annulées.
  - Éditeur visuel (`apps/backoffice/src/pages/workflows/editor/`, route `/workflows/{id}/edit`, chargée à la demande) : palette par catégorie issue de `GET /node-types` (types dont l'analyste n'a pas la permission grisés), glisser-déposer ou clic, connexions refusées côté navigateur (port inexistant, doublon, boucle, nœud relié à lui-même) et revalidées par le serveur, annuler/rétablir (Ctrl+Z, Ctrl+Maj+Z, une étape par champ modifié), mise en page automatique des graphes sans positions. Le panneau de paramètres est généré depuis le JSON Schema : expressions JMESPath et gabarits Liquid en champ texte (CodeMirror en 5C), listes, choix multiples, objets en JSON. `NodeTypeOut.reference_fields` indique les paramètres qui désignent un connecteur (famille et types acceptés) ou un agent : l'éditeur propose les objets de l'espace, ou un champ libre si l'analyste ne peut pas les lister. Aucun nœud ne prend de secret ni de modèle en paramètre (identifiants dans les connecteurs, moteur choisi par espace) : ces sélecteurs n'ont pas d'objet aujourd'hui. Le brouillon est enregistré 1,2 s après chaque modification ; les erreurs de validation renvoyées s'affichent sur le nœud et sur le champ. Publication : `base_version_no` du brouillon ; un brouillon périmé ou un conflit (409) propose de repartir de la dernière version ou de garder ses modifications par-dessus.
  - Éditeur, test et exécutions (5C) : les champs JMESPath et Liquid sont des éditeurs CodeMirror 6 montés dans un shadow root (leurs styles passent par une feuille construite, `adoptedStyleSheets`, que la CSP `style-src 'self'` autorise ; une balise `<style>` serait bloquée), avec complétion des chemins de l'élément d'exemple et des fonctions. L'aperçu est calculé par le serveur (`POST …/workflows/preview-expression`, même évaluateur et mêmes limites qu'à l'exécution, 1 200 aperçus par heure) sur le premier élément épinglé du nœud. Données épinglées (choix du porteur du projet) : une CVE du catalogue (`GET …/workflow-samples/cve/{id}`, sous forme d'événement NVD ou de fiche complète), ou la sortie d'un nœud amont lors de son dernier test ou d'une exécution réelle (`GET …/workflows/{id}/nodes/{nœud}/outputs`). Le test d'un nœud `ai.*` demande une confirmation explicite, avec le budget du mois. Le suivi d'une exécution passe par le flux SSE, ou par une interrogation toutes les 1,5 s sans EventSource ; la page d'exécution montre le graphe de la version (canvas chargé à la demande) avec statut, éléments entrés et sortis, durée et coût IA par nœud (`ai_calls`, `ai_cost_usd`, agrégés depuis `agent_runs`).
  - Versions (5D) : la restauration crée une nouvelle version depuis l'ancienne (`…/versions/{n}/restore`, revalidée avec les permissions de l'analyste, auditée `workflow.version_restored`) ; l'historique n'est jamais réécrit. La comparaison (`/workflows/{id}/compare?from=&to=`, `draft` accepté) ignore les positions sur le canvas. Fichiers d'échange : format `vuln-veille.workflow/1` ou graphe nu, 1 Mio au plus, lus comme JSON seulement et validés par le serveur. Le cron des planifications est expliqué en français par `cronstrue` (chargé avec l'éditeur).
  - Test navigateur (critère de sortie de la phase 5) : `tests/integration/test_phase5_exit.py` sert le back-office construit et l'API réelle sur `localhost` avec la CSP de production, fait tourner le moteur de workflows en processus et pilote Chromium (connexion avec TOTP, ajout d'un agent, modification d'un filtre, test sur une CVE, publication). Il est ignoré sans `VV_E2E_CHROMIUM` et `VV_E2E_PLAYWRIGHT` (PROCEDURES §4) ; il ne tourne donc pas encore en CI.
  - Bulletins (phase 6, `app/bulletins/`) : réponses du porteur du projet Q37 (préfixe de référence configurable par espace), Q38 (TLP par défaut porté par le modèle, AMBER sinon), Q39 (modèles livrés : générique FR par défaut et EN, « exploitée ou critique »). La double validation reste désactivée par défaut (Q4 ; ADR-019 corrigée en ce sens) ; le critère de sortie de la phase 6 (« un second analyste valide ») sera testé avec l'option activée. Les modèles livrés sont créés par `seed-workflows` avec les réglages d'espace (préfixe = slug). PDF et e-mail aux clients : phase 8 (Q11).
  - Bulletins, 6B (détail : spec 04 §5 bis) : un bulletin n'existe qu'après une génération réussie ; l'échec reste sur la demande de draft. Les tests d'intégration simulent le moteur IA (`tests/integration/test_bulletins.py`, `Writer` répond aux champs du schéma demandé). La connexion compte comme une MFA récente : pour tester `step_up_required`, vieillir `sessions.step_up_at`, puis confirmer avec le code TOTP de la fenêtre suivante (le code de connexion ne peut pas être rejoué).
  - Bulletins, 6C : les modèles livrés utilisent `{% if x and x != blank %}` : dans la bibliothèque Liquid utilisée, `nil != blank` est vrai (contrairement à Shopify), et un champ facultatif absent laissait son titre de section. Le test navigateur de la phase 6 simule le moteur IA (`tests/integration/bulletin_support.py`) et fait tourner les demandes de draft en processus ; la connexion compte comme MFA récente, donc la publication ne redemande pas de code.
  - Publication (7A, ADR-030) : l'API ne déchiffre jamais un secret, donc le dry-run masque chaque identifiant ; l'envoi réel sera fait par le worker `publish`. Le CSAF produit a été vérifié contre le schéma JSON OASIS (validation ponctuelle hors dépôt ; le test unitaire vérifie la structure). Les secrets globaux acceptent maintenant le type « connecteur » (Q40). Le client mTLS charge certificat et clé par `memfd` (Linux).
  - Publication (7B) : le harnais de workflows garde les tâches d'autres workers dans `Harness.others` ; `NodeContext.tasks` met des tâches en file après la validation du nœud (jamais en test). Le nœud `publish.api` ne pousse rien lui-même : il crée l'envoi et le worker `publish` l'exécute.
  - Portail (8A, ADR-031) : le portail ne lit jamais les colonnes du bulletin, seulement le dernier instantané de publication ; la mise à jour d'un bulletin publié n'atteint les clients qu'à sa republication. Une nouvelle relation lisible par le portail doit être accordée explicitement à `vv_portal` (rien par défaut), et retirée à `vv_app` et `vv_worker` si c'est une vue sans RLS.
  - Questions encore ouvertes : Q33 (LLMaaS), Q35 (quotas Gemini). Q34 est remplacée par Q46.

## Journal

### 2026-10-23 — Session 13 (suite) : modèle IA local (ADR-032)

- Les moteurs IA peuvent demander une plage privée (même file d'approbation que la publication).
- Le connecteur compatible OpenAI accepte une autorité interne (`ca_bundle`), ainsi que le HTTP et son propre port vers une plage approuvée.
- `app.cli egress-acl --config-output` génère `allow_ranges` pour smokescreen.
- `app.cli llm-check` et l'étape facultative du test de fumée.
- Interface : éditeur de moteur IA et carte « Interroger le modèle » (question au worker IA, réponse en texte brut).
- Tests :
  - `test_ai_engine_private.py` (refus avant approbation, réponse après, budget, cloisonnement, `allow_ranges`) ;
  - `test_ai_engine_policy.py` ;
  - vitest `engines.test.tsx`.

### 2026-10-23 — Session 13 (suite) : clôture de la phase 8 et guide de mise en service

- Merge request 8C fusionnée : la phase 8 est terminée.
- `docs/DEPLOYMENT.md` : prérequis, `.env` de production, démarrage, premier administrateur, configuration dans l'interface, liste blanche de sortie, sauvegardes, mises à jour, limites connues.

### 2026-10-23 — Session 13 (suite) : écrans du portail et fin de la phase 8 (merge request 8C)

- Portail : liste avec recherche et filtres dans l'URL, détail assaini, historique, exports, impression (feuille de style d'impression), page « Notifications », en-tête aux couleurs de l'émetteur (prop `brand` d'`AppShell`).
- Back-office : page « Charte du portail » (nom de l'émetteur, logo avec authentification renforcée).
- Tests : vitest (portail 7, back-office 2 nouveaux) ; `test_phase8_exit.py` dans Chromium. `browser.py` sert aussi le portail (`served(..., "portal")`).

### 2026-10-23 — Session 13 (suite) : PDF, e-mails et charte (merge request 8B)

- Migration 0020 : `platform_branding` (ligne unique) et `portal_notification_preferences` (RLS sur l'utilisateur, `vv_app` sans accès).
- PDF WeasyPrint sans aucune ressource externe ; logo réencodé par Pillow ; e-mails HTML + texte + PDF joint, un par destinataire, avis de retrait, idempotents. Dépendances système (Pango, HarfBuzz-Subset, polices DejaVu) dans l'image et la CI.
- Tests : 16 tests unitaires (logo, PDF, règle d'adressage, messages) ; 1 test d'intégration (charte, préférences, destinataires par organisation, TLP et choix, mise à jour, retrait, idempotence, export PDF) ; matrice d'autorisation.

### 2026-10-22 — Session 12 (suite) : modèles de bulletins (merge request 6A)

- Migration 0015 : modèles de bulletins versionnés (spécification validée, immuable), réglages d'espace (préfixe de référence, double validation, modèle par défaut).
- Rendu sûr (ADR-029), sélection du modèle par règles et priorité avec explication, aperçu côté serveur sur une vraie vulnérabilité, trois modèles livrés.
- CI rouge sur `Main` pour deux avis publiés le jour même (opentelemetry-api, dompurify) : correctifs embarqués dans la merge request 5D avec des exceptions ciblées au délai de publication (PROCEDURES §8).
- Tests : 16 tests unitaires (spécification, rendu, sélection) ; 2 tests d'intégration (modèles livrés, sélection, aperçu, versions, activation, réglages, cloisonnement, permissions) ; matrice d'autorisation.

### 2026-10-22 — Session 12 (suite) : versions des workflows et fin de la phase 5 (merge request 5D)

- Serveur : restauration d'une version (nouvelle version, revalidée, auditée), export d'une version choisie.
- Interface : comparaison de deux versions ou du brouillon (canvas annoté et diff JSON), restaurer et exporter depuis l'historique, import d'un fichier comme nouveau workflow ou dans l'éditeur (annulable), export du brouillon, changements listés avant publication, cron expliqué en clair.
- Critère de sortie de la phase 5 atteint : test navigateur contre la vraie API (agent « Forums techniques » ajouté après l'analyse, filtre de notification modifié, filtre testé seul sur une CVE du catalogue, version 2 publiée, brouillon supprimé).
- Tests : test d'intégration de la restauration et de l'export ; 6 nouveaux tests frontend (diff, cron, fichiers, comparaison, restauration et export, import dans l'éditeur, planification) ; test navigateur.

### 2026-10-22 — Session 12 (suite) : éditeur, expressions, test de nœud et vue d'exécution (merge request 5C)

- Serveur : aperçu d'une expression ou d'un gabarit sur un élément d'exemple, CVE du catalogue comme donnée épinglée, sorties récentes d'un nœud, coût IA par nœud et mode de l'exécution dans son détail.
- Interface : champs CodeMirror avec complétion et aperçu, onglet « Tester » (CVE réelle, sortie amont d'un test ou d'une exécution, confirmation avant un appel IA facturé, résultat en texte inerte, statut sur le canvas), page d'exécution avec le graphe en direct.
- Vérifié dans Chromium sous la CSP de production : complétion, styles de CodeMirror appliqués sans balise `<style>`, aperçu, aucune violation.
- Tests : 2 tests d'intégration de l'éditeur (aperçu, échantillon de CVE, sorties, coût IA, permissions) ; 3 nouveaux tests frontend (test d'un nœud sur une CVE avec aperçu, confirmation d'un test IA et sortie amont, vue d'exécution en direct).

### 2026-10-22 — Session 12 (suite) : couche 2 de X activée par défaut

- Réponse à la question en suspens (Q36) : la recherche web du moteur IA restreinte à x.com est activée par défaut sur les nouveaux connecteurs `x_reader` ; l'espace peut la désactiver. ADR-028 et specs 03 et 07 mis à jour ; le test de couverture de X s'appuie désormais sur la valeur par défaut.

### 2026-10-22 — Session 12 (suite) : éditeur visuel, canvas et paramètres (merge request 5B)

- Canvas React Flow (`@xyflow/react`, chargé seulement sur la route de l'éditeur) : palette, glisser-déposer, connexions validées par port, mini-carte, annuler/rétablir, nœuds en texte inerte. Vérifié dans Chromium sous la CSP de production : ni balise `<style>`, ni `innerHTML`, ni violation.
- Panneau de paramètres généré depuis le JSON Schema, avec sélecteurs de connecteurs (filtrés par famille et type) et d'agents ; `reference_fields` ajouté au registre des nœuds.
- Brouillon côté serveur, erreurs localisées sur les nœuds, publication d'une version, détection d'un brouillon périmé et d'une publication concurrente.
- Tests : test backend du registre, 10 tests frontend de l'éditeur (modèle du graphe, schémas, ajout et paramétrage d'un nœud, brouillon, erreurs, annuler/rétablir, sélecteur de connecteurs, publication, conflit, brouillon périmé).

### 2026-10-22 — Session 12 (suite) : phase 5, partie serveur de l'éditeur (merge request 5A)

- Migration 0014 : brouillons de workflow (un par workflow, RLS par espace) et exécutions de test (graphe édité, nœud testé, entrées épinglées, sans version).
- Orchestrateur : en mode test, seul le nœud testé est mis en file ; il tourne en dry-run sur le worker de sa file et ses écritures en base sont annulées après coup.
- API : brouillon (lecture, enregistrement avec erreurs, détection d'une publication concurrente), test d'un nœud, flux SSE des événements d'exécution.
- Tests : 351 tests backend (dont brouillon périmé, test de trois nœuds sans trace en base ni e-mail, flux SSE).

### 2026-10-22 — Session 12 (suite) : interfaces de la phase 4 et jalon 1 (merge request 4G)

- Écrans : moteurs IA et budget, agents et bac à sable, traces d'exécution d'agent, banc d'évaluation, couverture de X ; navigation selon les permissions de l'espace.
- `run_if` sur les nœuds IA ; la re-veille limite l'agent réseaux sociaux aux CVE KEV, P1 ou P2 (spec 07 §2.1). Schémas OpenAPI du banc et de la couverture renommés (collision de noms avec les workflows).
- Critère de sortie du jalon 1 testé sans moteur factice : vrais adaptateurs Gemini (SDK officiel) puis compatible OpenAI derrière des serveurs simulés, bascule du moteur préféré par l'API entre deux CVE, synthèses sourcées enregistrées sur des vulnérabilités non qualifiées.
- Tests : 350 tests backend, 26 tests frontend (dont trace d'exécution hostile affichée en texte et changement de moteur bloqué par le rapport de compatibilité).

### 2026-10-22 — Session 12 (suite) : découverte de X par le moteur IA et couverture (merge request 4F)

- Paramètre abstrait `web_search` d'`AIEngine` : outil serveur `web_search` de Claude (domaines autorisés), ancrage Google Search de Gemini, refus explicite côté compatible OpenAI ; usage et coût des recherches comptés (migration 0013 : prix par millier de recherches).
- `x_discover`, couche 2 : recherche restreinte à x.com sur l'identifiant CVE seul, consommant les quotas du connecteur X, URL candidates vérifiées ensuite par l'oEmbed ; désactivée par défaut (ADR-028).
- Indicateur de couverture de X et échantillon vérifié à la main (rappel, précision, CVE manquées).
- Tests : adaptateurs (paramètres envoyés, lecture des résultats), indicateur, et parcours complet de l'agent « Réseaux sociaux » (une URL inventée n'est pas comptée).

### 2026-10-22 — Session 12 : corpus d'injection en CI et banc d'évaluation (merge request 4E)

- Corpus de 8 charges piégées (consignes en anglais et en français, faux conteneur, marqueurs de rôle, exfiltration, caractères invisibles, faux PoC) dans 6 lieux de lecture (recherche et README GitHub, page éditeur, post X, description NVD, entrée), joué par un modèle compromis derrière les trois adaptateurs simulés : aucune requête hors domaine, aucun outil hors liste, aucune écriture, signaux enregistrés.
- Corrections trouvées par le corpus : l'entrée d'un agent est analysée chaîne par chaîne (l'échappement JSON masquait un `system:` en début de ligne) ; un marqueur de rôle est signalé aussi en début de phrase (le lecteur X met le post sur une seule ligne).
- Banc d'évaluation (migration 0012) : cas de référence, exécutions budgétées sur un modèle candidat, métriques et rapport comparatif, évaluation citée lors d'un changement de moteur préféré.
- Tests : 343 tests backend (dont le corpus sur les trois moteurs et le banc de bout en bout).

### 2026-10-21 — Session 11 (suite) : agents prédéfinis, nœuds IA et workflows d'investigation (merge request 4D)

- Six agents prédéfinis par espace : triage, chasseur de PoC GitHub, réseaux sociaux, forums techniques, avis éditeurs, synthèse (schéma d'investigation de la spec 03 §7). Ils sont rattachés aux connecteurs de l'espace, et désactivés si un connecteur manque.
- Nœuds `ai.agent` (agent de l'espace ou prédéfini), `ai.summarize`, `ai.classify`, `ai.extract`, `ai.relevance` (périmètre de veille ou profil rédigé) ; migration 0011 pour les exécutions de tâches sans agent.
- Sources `source.github_search`, `source.x` (posts cités, lus par l'oEmbed officiel), `source.stackexchange`, `source.social` (Mastodon, Bluesky, Reddit, Hacker News) ; la recherche GitHub est partagée avec l'outil d'agent. Nœud `vuln.attach_analysis`.
- Workflows livrés : « Nouvelle CVE NVD → investigation » (triage, quatre agents de veille en parallèle, synthèse, alerte si KEV, exploitée ou P1) et « Re-veille des vulnérabilités ouvertes » (toutes les 6 heures et à l'ajout KEV ou d'une référence d'exploit). Livraison des mises à jour de seeds non modifiés.
- Tests : 11 tests unitaires (nœuds IA, sources, presets, seeds) et le critère de sortie de 4.14 en intégration (investigation complète avec moteur simulé, CVE non pertinente arrêtée au triage, synthèse enregistrée avec ses signaux, alerte) ; 335 tests backend au total.

### 2026-10-21 — Session 11 (suite) : agents, runtime, outils, garde-fous et budgets (merge request 4C)

- Migration 0010 : agents et versions immuables, exécutions et étapes (journal append-only), plafonds et dépenses mensuelles ; RLS par espace sur chaque table, droits restreints (le worker ne crée pas d'agent, l'API n'écrit pas les dépenses).
- Runtime d'agent : boucle d'outils pilotée par notre code (budget et coût par exécution avant chaque appel, outil autorisé et arguments validés par JSON Schema, résultats regroupés en un message, sortie validée avec une relance, refus enregistrés avec leur catégorie, délai global, relances sur 429/5xx).
- 13 outils en lecture seule sur le catalogue local, les données de l'espace et les connecteurs autorisés de l'agent ; `github_get` refuse binaires et archives.
- Garde-fous : documents non fiables en JSON avec provenance, suppression des caractères invisibles, détection des consignes injectées, des tentatives d'exfiltration et des indices de faux PoC, URL citées hors sources signalées, URL non http(s) refusées.
- Rapport de compatibilité agent ↔ modèle (outils, sortie structurée, contexte, tokens de sortie, raisonnement, classes de données), vérifié aussi à l'enregistrement d'un agent épinglé et avant chaque exécution.
- API : agents (versions, activation d'une version), bac à sable de test (30 par heure et par utilisateur), traces d'exécution, budget mensuel ; ADR-027.
- Tests : 43 tests unitaires (spécification, garde-fous, compatibilité, coûts, outils sur connecteurs dont `github_get`, `web_fetch`, `social_search`, `x_read`) et deux scénarios d'intégration (boucle complète avec signaux, alerte à 50 %, arrêt dur, refus, cloisonnement et versions ; outils sur les données locales limités à l'espace) ; 323 tests backend au total.
- Tests : la séquence des références `VV-AAAA-NNNN` est remise à zéro entre les tests d'intégration (elle n'appartient à aucune colonne, `RESTART IDENTITY` ne la touche pas).

### 2026-10-21 — Session 11 : phase 4, moteurs IA (merge request 4A)

- Couche moteur IA neutre (`app/ai/types.py`) et vérification automatique des capacités (complétion, sortie JSON conforme, aller-retour d'outil ; rétrogradation des capacités qui échouent).
- Adaptateurs : Gemini (SDK `google-genai`, palier gratuit, quotas prudents), Claude (SDK `anthropic`, effort, sortie structurée, outils stricts, refus et repli `fallbacks: "default"`, cache du prompt système), compatible OpenAI (outils natifs ou émulés, `response_format`, décodage guidé). Les SDK passent par `SafeHttpClient` (ADR-026).
- Moteurs comme connecteurs `ai_engine` : modèles déclarés, politique de données (Q6), catalogue `ai_models`, capacités vérifiées par le worker ; moteur préféré plateforme et espace (migration 0009, API, audit).
- Tests : 266 tests backend (SDK réels contre serveurs simulés, refus, quotas, sortie de domaine refusée, cloisonnement des modèles entre équipes).

### 2026-10-21 — Session 11 (suite) : connecteurs de veille gratuits (merge request 4B)

- Huit connecteurs gratuits : X (oEmbed officiel et découverte des liens déjà collectés), Stack Exchange, Mastodon, Bluesky, Reddit (RSS publics), Hacker News (Algolia), OSV, pages web d'éditeurs (domaines déclarés, robots.txt, texte seul). Résultats normalisés `Found`, en texte brut et non fiables.
- Le parseur de flux passe de `app/workflows/` à `app/watch/feeds.py` (les connecteurs n'importent pas le moteur de workflows).
- Tests : 11 tests de connecteurs contre un faux web (formats réels des services, refus des URL hors domaine, profils X jamais lus).

### 2026-10-21 — Session 10 (suite) : `Main` devient la branche principale

- `Main` (branche par défaut créée par le porteur) devient la seule branche durable ; développement sur des branches courtes et merge requests vers `Main` (CLAUDE.md, PROCEDURES §0, gabarit de merge request).
- CI : déclenchée par les fusions sur `Main` et par les merge requests qui la ciblent (plus de déclenchement sur les poussées des branches `claude/**`).
- Correctifs de déploiement découverts par le test de démarrage de la pile : Go 1.27.3 pour Caddy et smokescreen (CVE-2026-111943), environnement complet du service `migrate` pour `seed-workflows`.

### 2026-10-21 — Session 10 : phase 3, moteur de workflows

- Schéma 0008 : workflows, versions immuables, déclencheurs, exécutions, exécutions de nœuds, validations, clés de déduplication ; RLS par espace sur chaque table.
- Graphe v1 et validation (acyclicité, ports, paramètres, permissions de l'éditeur, connecteurs du même espace, validation humaine avant tout effet externe, limites) ; registre de nœuds exporté en JSON Schema ; expressions JMESPath et gabarits Liquid sans `include`/`render`, avec limites.
- Exécuteur : orchestration sous verrou, une tâche par nœud dans la file de son type, retries, `on_error` (`stop`, `continue`, `route`), idempotence, annulation et révocation, échéance, concurrence (5 par workflow, 20 par espace), balayage de reprise.
- Déclencheurs : manuel, cron (5 minutes au minimum, fuseau explicite), outbox (`cve.published`, `cve.updated` diffusés à chaque espace abonné, `vuln.created`), webhook signé HMAC.
- 24 types de nœuds (déclencheurs, sources `nvd`, `cisa_kev`, `rss`, `http`, `github_advisories`, transformations, `vuln.*`, `control.if`, `control.approval`, `notify.email`) ; connecteurs `rss`, `http_api`, `github`.
- API des workflows (versions, activation, lancements, exécutions, validations, import et export, rotation du secret de webhook), auditée ; seeds « Nouvelle CVE NVD » et « Veille quotidienne » ; écrans de liste, de détail (graphe, éditeur JSON provisoire, versions, déclencheurs) et d'exécution (journal par nœud, sorties en texte brut, validations).
- Tests : 256 tests backend (dont le critère de sortie, la reprise après perte de worker, le rejeu, la concurrence et le webhook) ; 23 tests frontend.

### 2026-10-24 — Session 9 : phase 2, interfaces et clôture

- Back-office : sélecteur d'équipe (VOC/CERT) mémorisé, file des vulnérabilités (à qualifier, qualifiées, en surveillance, filtres, pagination), fiche vulnérabilité (qualification de l'équipe avec transitions autorisées, « Reprendre cette qualification », fiche partagée, CVE, technos, preuves, synthèses, commentaires privés, chronologie), catalogue CVE (état des synchronisations, décision de périmètre par équipe, promotion), périmètre de veille avec aperçu, sources, catalogue des technos (recherche approchée, suggestions CPE, fusion), connecteurs par famille (formulaire généré depuis le schéma du type, test, santé), secrets en écriture seule (espace et globaux).
- Composants : `TextArea`, `Checkbox`, `Tabs`, `ExternalLink` et `safeHttpUrl`.
- Correctif : analyse NVD tolérante aux nouvelles familles de métriques (SSVC), découverte par une synchronisation réelle.
- Tests : 21 tests frontend (liens hostiles, file et fiche vulnérabilité, reprise de qualification, navigation par permissions) ; 230 tests backend.

### 2026-10-22 — Session 8 : phase 2, coffre de secrets et sortie réseau

- `SafeHttpClient` (`app/net/`) : politique d'URL, validation des adresses (unicast public seulement, jamais loopback ni métadonnées même sur exception), épinglage d'IP en mode direct, résolution laissée à smokescreen en mode proxy, redirections revalidées sans fuite d'identifiants, décompression bornée (gzip et deflate seulement), échéance totale ; proxy obligatoire en production.
- Cadre des connecteurs : types et registre (refus à l'import des types payants, des identifiants en configuration, des domaines invalides), migration `0004_connectors` (connecteurs, curseurs, RLS), API par famille et par portée, test de connexion exécuté par le worker de la famille, quotas Redis, génération de la liste blanche du proxy.
- NVD : migration `0005_catalog` (`cve_records`, `cve_changes`, `outbox_events`), analyse défensive des enregistrements, détection des changements (CVSS ajouté, sévérité relevée, CPE ajoutées, KEV, référence d'exploit, rejet), synchronisation par fenêtres (rattrapage silencieux, incrémental avec recouvrement, curseur par fenêtre, pause, backoff, verrou), planification par le scheduler.
- Sources globales : CISA KEV (premier import silencieux, entrées récentes annoncées), FIRST EPSS (CVE du catalogue seulement), CVE.org (détection précoce par `delta.json`, rattrapage par `deltaLog.json`, NVD jamais écrasé) ; tâche générique de synchronisation et planification commune.
- Domaine vulnérabilités : migrations `0006_watch` (technos, périmètre, sources, éléments collectés) et `0007_vulnerabilities` (fiches partagées, évaluations par équipe, technos, preuves, synthèses IA, commentaires privés, chronologie) ; moteur de périmètre (KEV, CWE exclues, technos par CPE puis nom, éditeurs, mots-clés, seuil CVSS, CVE sans score) ; API du catalogue CVE (filtre par décision de périmètre, état des synchronisations), des technos (recherche approchée, fusion, suggestions CPE), du périmètre (aperçu), des sources et des vulnérabilités (promotion d'une CVE, création sans CVE, qualification avec transitions contrôlées, reprise de la qualification de l'autre équipe, commentaires, preuves, rattachement aux technos) ; récupération à la demande d'une CVE absente du catalogue par le worker.
- Tests : suite SSRF hors ligne (adresses piégées, écritures numériques, rebinding, redirections, bombes de décompression), test TLS réel de l'épinglage (SNI et nom du certificat), garde « aucune bibliothèque réseau hors `app/net/` » ; vérification sur la pile réelle (refus par smokescreen d'un domaine non autorisé, pas de route directe).

- ADR-013 révisée : chaque secret a sa clé de données AES-256-GCM, enveloppée pour la clé publique X25519 de son usage. L'API du back-office ne détient que les clés publiques : elle écrit les secrets sans pouvoir les lire.
- Migration `0003_vault` : table `secrets`, RLS (un administrateur VOC ne voit pas les secrets du CERT ; les workers lisent et ré-enveloppent mais ne créent ni ne suppriment).
- API : secrets d'espace (`secret.manage`) et globaux (`connector.global.manage`), step-up à chaque écriture, audit sans valeur.
- Exploitation : trousseaux en secrets Docker par worker, `scripts/vault-keygen.sh`, `vault-rotate`, service `vault-admin` (profil `tools`), `.dockerignore` racine.
- Tests : 84 tests backend (cryptographie, liaison des données associées, rotation, isolation VOC/CERT, écriture seule, step-up).

### 2026-10-21 — Session 7 : phase 1, interfaces

- Paquet partagé `@vv/auth` : connexion, vérification et enrôlement MFA (QR code), invitation, mot de passe oublié et réinitialisation (jeton dans le fragment d'URL, effacé de la barre d'adresse), « Mon compte » (mot de passe, MFA, codes de secours, sessions), dialogue de step-up qui rejoue l'action une fois, garde de route, page d'erreur générique (aucun détail technique affiché).
- Back-office : utilisateurs (recherche, pagination, invitation), fiche utilisateur (statut, déverrouillage, réinitialisation MFA, fermeture des sessions, accès VOC/CERT, rôle d'administrateur), espaces, organisations clientes et leurs utilisateurs, journal d'audit (filtres, vérification de la chaîne, export JSON Lines). Navigation masquée selon les permissions ; l'API reste la seule autorité.
- Portail : page des bulletins (en attente de la phase 6), « Mon organisation » pour les référents (rôles, invitations, désactivation), « Mon compte ».
- API portail : la liste des membres de l'organisation expose désormais leur rôle (`OrgUserOut`).
- Images : modules Go de Caddy et smokescreen figés (`go.mod`/`go.sum` commités) après deux échecs CI transitoires de `sum.golang.org` ; manifeste `@vv/auth` ajouté à l'étape SPA de l'image Caddy ; test de fumée de la pile complète vert en local.
- Tests : 16 tests frontend (redirection des anonymes, navigation selon les permissions, refus d'accès, échec de connexion, step-up) ; 60 tests backend.

### 2026-10-21 — Session 6 : phase 1, backend

- Migration `0002_iam` : utilisateurs, rôles globaux, sessions, jetons à usage unique (avec audience), TOTP et codes de secours, espaces VOC/CERT (seed), organisations clientes et appartenances, audit chaîné écrit uniquement via `audit_append` (SECURITY DEFINER), politiques RLS (rôle portail limité au contexte de requête), droits.
- Primitives : AES-256-GCM, HMAC à séparation de domaine, Argon2id, politique de mot de passe (liste SecLists de 10 000 mots de passe courants, motif « mot courant + chiffres »), TOTP avec anti-rejeu.
- API : connexion, MFA (vérification, enrôlement, codes de secours), invitation, mot de passe oublié et réinitialisation, step-up, compte (mot de passe, sessions, codes de secours, désactivation MFA client), administration (utilisateurs, rôles, espaces, clients), organisation (référent client), audit (liste, export JSON Lines, vérification, audit d'espace), CLI `bootstrap-admin`.
- Sécurité : cookies `__Host-`, jeton CSRF dérivé de la session, middleware Origin, limitation Redis, verrouillage progressif, matrice d'autorisation sur six profils.
- Correctif : le test « toute route déclare une politique » ne voyait aucune route depuis la phase 0 (FastAPI 0.142) ; corrigé et durci.


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

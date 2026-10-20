# Spec 02 — Moteur de workflows et éditeur

## 1. Concepts

- **Workflow** : objet d'un espace, avec un nom, un statut et des versions.
- **Version** : graphe JSON **immuable**. Une seule version est active ; les exécutions sont figées sur la version qui les a lancées.
- **Nœud** : instance d'un **type de nœud** (registre côté backend) avec des paramètres.
- **Élément (item)** : unité de données qui circule entre les nœuds : `{ "json": {...}, "meta": {...} }`. `meta` porte la provenance (`source`, `url`, `fetched_at`), le niveau de confiance (`trust`) et la lignée (identifiants des éléments parents).
- **Exécution (run)** : une exécution d'une version, composée d'exécutions de nœuds (`node_runs`).

## 2. Format du graphe (schema_version 1)

```json
{
  "schema_version": 1,
  "nodes": [
    {
      "id": "n_rss",
      "type": "source.rss",
      "type_version": 1,
      "name": "Avis CERT-FR",
      "params": {
        "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "max_items": 50
      },
      "settings": {
        "retry": { "max_attempts": 3, "backoff_seconds": 30 },
        "timeout_seconds": 120,
        "on_error": "stop"
      },
      "position": { "x": 120, "y": 80 }
    },
    {
      "id": "n_filter",
      "type": "transform.filter",
      "type_version": 1,
      "name": "Contient une CVE",
      "params": { "condition": { "$expr": "length(json.cve_ids) > `0`" } },
      "position": { "x": 360, "y": 80 }
    }
  ],
  "edges": [
    { "id": "e1", "from": { "node": "n_rss", "port": "out" }, "to": { "node": "n_filter", "port": "in" } }
  ]
}
```

Règles de validation à l'enregistrement :

- graphe acyclique (les boucles passent uniquement par des nœuds de contrôle dédiés, plus tard) ;
- types et versions de nœuds connus, paramètres conformes à leur JSON Schema ;
- ports existants, au moins un déclencheur ;
- références (secrets, connecteurs, agents, modèles, sources) appartenant au **même espace** ;
- l'éditeur possède les permissions requises par chaque nœud (par exemple, `publish.api` exige `connector.publish.push`) ;
- tout `publish.api` est précédé d'un `control.approval` sur chaque chemin ;
- limites : 200 nœuds au maximum, 64 Kio de paramètres par nœud.

## 3. Valeurs dynamiques

- `{"$expr": "<JMESPath>"}` : évalué sur le contexte `{ json, meta, run, nodes }`, où `nodes.<id>.items` donne accès aux sorties des nœuds amont. Aucun effet de bord, aucune fonction système.
- `{"$tpl": "<Liquid>"}` : pour les chaînes (sujet d'e-mail, prompt complémentaire), rendu avec le même contexte, filtres en liste blanche, limites (boucles, taille de sortie).
- Les valeurs issues de contenu non fiable restent des données : elles ne sont jamais réinterprétées comme expression ou gabarit.

## 4. Interface d'un type de nœud (backend)

```python
class NodeType(Protocol):
    type: ClassVar[str]                 # "source.rss"
    version: ClassVar[int]              # 1
    category: ClassVar[NodeCategory]    # trigger | source | transform | ai | vuln | bulletin | output | control | integration
    queue: ClassVar[str]                # default | collect | ai | publish
    Params: ClassVar[type[BaseModel]]   # source du JSON Schema exposé à l'éditeur
    inputs: ClassVar[list[Port]]
    outputs: ClassVar[list[Port]]
    required_permissions: ClassVar[set[Permission]]
    uses_egress: ClassVar[bool]

    async def execute(self, ctx: NodeContext, params: BaseModel,
                      inputs: dict[str, list[Item]]) -> dict[str, list[Item]]: ...
```

`NodeContext` expose uniquement des capacités contrôlées : `ctx.http` (SafeHttpClient avec quotas), `ctx.secrets.get(ref)`, `ctx.repo` (repositories à périmètre), `ctx.llm` (runtime d'agent), `ctx.log`, `ctx.limits`, `ctx.dedupe`. Pas d'accès direct à la session SQL, à l'environnement ou au système de fichiers.

## 5. Exécution

1. Un déclencheur crée un `workflow_run` (`queued`) figé sur une version.
2. L'**orchestrateur** (tâche de la file `default`) calcule les nœuds prêts (toutes les entrées disponibles) et publie une tâche par nœud dans la file de son type.
3. Le **worker** charge les entrées depuis `node_runs`, exécute, puis écrit la sortie (plafonnée) et le statut dans une transaction ; il notifie ensuite l'orchestrateur.
4. L'orchestrateur avance jusqu'à la fin ou jusqu'à un `control.approval` (statut `waiting_approval`, notification aux analystes).
5. Erreur : retries selon `settings.retry`, puis `on_error` : `stop` (échec de l'exécution), `continue` (sortie vide), ou `route` (port `error`).
6. Idempotence : unique (`run_id`, `node_id`, `attempt`) ; une tâche rejouée après un crash détecte une sortie déjà écrite et ne refait rien. Les nœuds à effet externe (publication, e-mail) utilisent des clés d'idempotence.
7. Annulation : drapeau en base vérifié entre les nœuds et dans les boucles longues ; les tâches en cours reçoivent une révocation Celery.
8. Reprise : au démarrage, un balayage remet en file les nœuds `running` dont la tâche a expiré.

Limites par défaut (configurables par espace) : 5 000 éléments par sortie, 256 Kio par élément, 5 Mio de sortie stockée par nœud (au-delà : troncature signalée), 30 minutes par exécution, 5 exécutions simultanées par workflow et 20 par espace.

## 6. Déclencheurs

| Type | Détail |
|---|---|
| `trigger.manual` | Bouton « Exécuter » avec données d'entrée optionnelles (formulaire défini dans le nœud) |
| `trigger.schedule` | Cron (intervalle minimal de 5 minutes par défaut), fuseau horaire explicite |
| `trigger.cve_published` | **Vecteur d'entrée n°1** : nouvelle CVE détectée par la synchronisation NVD (événement global diffusé à l'espace, spec 07 §3), filtre JMESPath optionnel |
| `trigger.cve_updated` | Changement significatif d'une CVE sur NVD (`cvss_added`, `severity_raised`, `cpe_added`, `kev_added`, `exploit_reference_added`, `rejected`), filtre sur les types de changement |
| `trigger.event` | Événement de l'outbox de l'espace (`vuln.created`, `vuln.qualified`, `bulletin.approved`…) avec un filtre JMESPath |
| `trigger.webhook` | URL unique par déclencheur, HMAC-SHA256 obligatoire, anti-rejeu, 256 Kio au maximum, débit limité |

## 7. Catalogue des nœuds

Les nœuds marqués (MVP) sont livrés en phases 3, 4, 6 et 7 ; les autres viennent ensuite. Tout nœud qui contacte un service externe le fait par un connecteur de l'espace ou global (spec 07), sélectionné dans ses paramètres.

### Sources (file `collect`)

| Type | Description |
|---|---|
| `source.rss` (MVP) | Flux RSS ou Atom (CERT-FR, éditeurs, blogs) |
| `source.catalog` (MVP) | Itère sur les sources de veille de l'espace filtrées par tag |
| `source.nvd` (MVP) | Lecture du catalogue CVE local alimenté par le connecteur NVD (recherche par critères) ; la synchronisation elle-même est une tâche globale, pas un nœud |
| `source.cisa_kev` (MVP) | Nouvelles entrées du catalogue KEV |
| `source.epss` | Scores EPSS (mise à jour du catalogue) |
| `source.github_advisories` (MVP) | GitHub Security Advisories (GHSA) |
| `source.github_search` (MVP, ph. 4) | Dépôts, code et commits mentionnant une CVE (détection de PoC) |
| `source.stackexchange` (MVP, ph. 4) | Questions et réponses Stack Overflow ou Security StackExchange par tags et mots-clés |
| `source.x` (MVP, ph. 4) | Lecture gratuite de X : découverte des URL de posts puis lecture par l'oEmbed officiel (spec 07 §2.1) ; aucune API payante |
| `source.social` (MVP, ph. 4) | Mastodon et Bluesky via leurs API gratuites, Reddit via ses flux RSS publics |
| `source.hackernews` | Hacker News (API Algolia) |
| `source.osv` | Base OSV (écosystèmes open source) |
| `source.http` (MVP) | Requête HTTP générique et extraction (sélecteurs CSS, chemins JSON) |
| `source.web_page` | Page rendue par un navigateur headless isolé (plus tard) |

### Transformation (file `default`)

`transform.filter`, `transform.map` (définir ou renommer des champs), `transform.dedupe` (clé JMESPath, mémoire entre exécutions avec TTL), `transform.extract_cve` (regex CVE et GHSA), `transform.merge` (concaténation ou jointure par clé), `transform.split_batches`, `transform.limit`, `transform.sort` : tous MVP.

### IA (file `ai`)

`ai.agent` (agent configuré de l'espace, avec ses connecteurs et outils ; moteur hérité ou épinglé), `ai.summarize`, `ai.classify` (étiquettes définies), `ai.extract` (schéma JSON défini), `ai.relevance` (score par rapport au catalogue des technos ou à un profil) : tous MVP en phase 4.

### Vulnérabilités (file `default`)

`vuln.scope_match` (périmètre de veille de l'espace, ports `in_scope` et `out_of_scope`, spec 07 §3.4), `vuln.upsert` (crée ou met à jour une vulnérabilité `new` et rattache les preuves), `vuln.enrich` (CVSS, EPSS, KEV depuis le catalogue), `vuln.match_technologies` (CPE, purl, puis IA en repli), `vuln.list` (vulnérabilités de l'espace selon des critères, pour la re-veille), `vuln.attach_analysis` : tous MVP.

### Bulletins et sorties

| Type | Description |
|---|---|
| `bulletin.generate_draft` (MVP, ph. 6) | Crée un draft à partir d'une vulnérabilité et d'un modèle (sélection automatique ou fixée) |
| `notify.email` (MVP) | E-mail aux analystes de l'espace |
| `notify.webhook` | Teams, Slack ou Mattermost |
| `publish.api` (MVP, ph. 7) | Pousse un bulletin **approuvé** via un connecteur ; `control.approval` obligatoire en amont |

### Contrôle et intégration

`control.if`, `control.switch`, `control.approval` (MVP), `control.wait`, `control.sub_workflow` (plus tard), `integration.n8n_webhook` (appel d'un workflow n8n externe, plus tard).

## 8. Workflows livrés en exemple (seeds, désactivés par défaut)

1. **Nouvelle CVE NVD → investigation** (flux principal, détail dans la spec 07 §5) : `trigger.cve_published` → `vuln.scope_match` → `vuln.upsert` → `vuln.enrich` → `vuln.match_technologies` → agent de triage → agents de veille en parallèle (PoC GitHub, réseaux sociaux, forums, avis éditeurs) → agent de synthèse → `vuln.attach_analysis` → `notify.email` (si KEV, exploitation ou P1). Livré en version sans IA en phase 3, puis complet en phase 4.
2. **Saisie manuelle** : `trigger.event(vuln.created, origin=user)` → même chaîne à partir de `vuln.enrich`.
3. **Re-veille** : `trigger.schedule` (toutes les 6 h) → `vuln.list` (ouvertes, moins de 14 jours) → agents PoC et réseaux sociaux → mise à jour de la synthèse → notification ; et `trigger.cve_updated(kev_added | exploit_reference_added)` → même traitement immédiat.
4. **Entrée dans le périmètre** : `trigger.cve_updated(cpe_added | cvss_added)` → `vuln.scope_match` → si la CVE entre dans le périmètre, même chaîne que le flux principal.
5. **Veille complémentaire** : `trigger.schedule` → (`source.catalog[tag=vendors]`, `source.github_advisories`, flux RSS) → `transform.extract_cve` → `transform.dedupe` → `vuln.upsert` (rattache les preuves aux vulnérabilités existantes ou en crée).
6. **Draft automatique pour KEV** : `trigger.cve_updated(kev_added)` ou `trigger.event(vuln.qualified, kev=true)` → `bulletin.generate_draft` → `notify.email` (draft prêt à relire).

## 9. API

```
GET    /api/v1/node-types                              # registre et JSON Schema des paramètres
GET    /api/v1/workspaces/{ws}/workflows
POST   /api/v1/workspaces/{ws}/workflows
GET    /api/v1/workspaces/{ws}/workflows/{id}
PATCH  /api/v1/workspaces/{ws}/workflows/{id}          # métadonnées, If-Match
POST   /api/v1/workspaces/{ws}/workflows/{id}/versions # nouvelle version (graphe validé)
POST   /api/v1/workspaces/{ws}/workflows/{id}/versions/{v}/activate
POST   /api/v1/workspaces/{ws}/workflows/{id}/runs     # lancement manuel
POST   /api/v1/workspaces/{ws}/workflows/{id}/test-node   # exécuter un nœud avec des données épinglées
GET    /api/v1/workspaces/{ws}/runs/{run_id}           # détail et node_runs
GET    /api/v1/workspaces/{ws}/runs/{run_id}/events    # SSE
POST   /api/v1/workspaces/{ws}/runs/{run_id}/cancel
POST   /api/v1/workspaces/{ws}/runs/{run_id}/approvals/{node_id}
GET    /api/v1/workspaces/{ws}/workflows/{id}/export
POST   /api/v1/workspaces/{ws}/workflows/import
POST   /hooks/{trigger_id}                             # webhook entrant (signé)
```

## 10. Éditeur (frontend)

- Canvas React Flow : palette par catégorie, recherche, glisser-déposer, connexions validées par type de port, mini-carte, annuler et rétablir.
- Panneau de nœud : formulaire généré depuis le JSON Schema, avec des widgets spécialisés (sélecteur de secret, d'agent, de connecteur, de modèle ; éditeur JMESPath ou Liquid avec aperçu ; cron avec explication en clair).
- « Tester ce nœud » : exécute le nœud seul avec les données épinglées de l'amont ou un exemple ; les nœuds de sortie sont en dry-run.
- Vue d'exécution : couleur par statut, compteurs d'éléments, entrées et sorties (tableau et JSON), erreurs, durées, coût IA.
- Versions : brouillon local enregistré côté serveur, publication avec commentaire, historique, diff visuel et JSON, restauration.
- Concurrence : `If-Match` sur la version ; en cas de conflit, la fusion est proposée ou l'édition est rechargée.

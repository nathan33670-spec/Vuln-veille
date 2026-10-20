# Spec 05 — Connecteurs de publication (push API)

## 1. Problème

Les analystes doivent pousser les bulletins vers des serveurs distants dont on ne connaît **ni les endpoints, ni les champs, ni l'authentification**. La solution doit permettre d'ajouter une cible **par configuration**, depuis l'interface, sans développement.

## 2. Connecteur HTTP générique

```yaml
name: "Portail partenaire X"
kind: http_generic
request:
  base_url: "https://api.partenaire.example"   # https obligatoire (sauf exception admin)
  method: POST                                  # POST, PUT ou PATCH
  path: "/v2/advisories"                        # gabarit Liquid autorisé : "/v2/advisories/{{ remote_id }}"
  update:                                       # optionnel : mise à jour si un identifiant distant existe déjà
    method: PUT
    path: "/v2/advisories/{{ remote_id }}"
  headers:
    Content-Type: "application/json"
    X-Source: "vuln-veille"
  timeout_seconds: 20
  tls:
    verify: true                                # toujours vrai ; bundle d'AC personnalisé possible
    ca_bundle_secret: null
auth:
  type: oauth2_client_credentials               # none | api_key | bearer | basic | oauth2_client_credentials | mtls | hmac
  token_url: "https://auth.partenaire.example/oauth/token"
  client_id_secret: "sec_…"                     # référence au coffre, jamais la valeur
  client_secret_secret: "sec_…"
  scope: "advisories:write"
body:
  format: json
  mapping:                                      # arbre JSON ; chaque feuille est une constante, un chemin ou un gabarit
    title:       { path: "bulletin.title" }
    severity:    { path: "bulletin.severity", map: { critical: "P1", high: "P2", medium: "P3", low: "P4" } }
    cves:        { path: "bulletin.fields.cves" }
    content:     { path: "revision.rendered_markdown" }
    published:   { path: "bulletin.published_at", format: "iso8601" }
    source:      { const: "VOC" }
    summary:     { template: "{{ bulletin.fields.summary | truncate: 500 }}" }
    references:  { path: "bulletin.fields.references[].url" }
response:
  success_status: [200, 201, 202]
  remote_id_path: "data.id"                     # JMESPath sur la réponse JSON
idempotency:
  header: "Idempotency-Key"                     # valeur : hachage (bulletin, révision, connecteur)
retry:
  max_attempts: 5
  backoff_seconds: [10, 30, 120, 600, 1800]
  retry_on: [429, 500, 502, 503, 504, "network"]
rate_limit_per_minute: 30
```

Le payload est **construit comme un objet JSON** puis sérialisé : aucune injection possible par concaténation de chaînes. Le contexte du mapping ne contient que des données publiables (bulletin, révision, technos, CVE), jamais de secret ni de donnée interne non prévue.

## 3. Authentifications prises en charge

| Type | Détail |
|---|---|
| `none` | Aucune |
| `api_key` | En-tête ou paramètre de requête (nom configurable) |
| `bearer` | Jeton statique |
| `basic` | Identifiant et mot de passe |
| `oauth2_client_credentials` | Jeton mis en cache jusqu'à expiration, renouvelé automatiquement |
| `mtls` | Certificat et clé client (coffre) |
| `hmac` | Signature du corps (algorithme, en-tête et format configurables) |

## 4. Fonctionnalités

- **Dry-run** : affiche la requête exacte (méthode, URL, en-têtes avec les secrets masqués, corps) pour un bulletin donné, sans l'envoyer.
- **Test** : envoi vers un serveur d'écho intégré (en développement) ou vers la cible, sur un bulletin de test marqué comme tel.
- **Journal** : chaque tentative est enregistrée dans `publications` (aperçu expurgé, statut HTTP, extrait de réponse plafonné à 4 Kio, erreur, durée).
- **Création ou mise à jour** : l'identifiant distant extrait est mémorisé ; une republication utilise le bloc `update`.
- **Préréglages** : des connecteurs prédéfinis (MISP, OpenCTI, TheHive, Jira, ServiceNow, webhook Teams ou Slack) seront de simples jeux de valeurs par défaut, ajoutés quand les cibles seront connues.
- **Formats standards** : export CSAF 2.0 (format OASIS des avis de sécurité) et plus tard STIX 2.1, utilisables comme corps d'un connecteur.

## 5. Règles de sécurité

- Permissions : `connector.publish.manage` pour configurer, `connector.publish.push` pour envoyer ; le bulletin doit être `approved` ou `published`.
- Ré-authentification MFA pour créer ou modifier un connecteur et pour le premier envoi d'un bulletin vers un connecteur.
- SafeHttpClient : l'hôte de `base_url` est épinglé, aucune redirection vers un autre hôte, les plages privées sont refusées. L'exception `allow_private_network` (cible interne) exige un admin plateforme, une liste de CIDR explicite et laisse une trace dans l'audit.
- Secrets en écriture seule ; masqués dans le dry-run et les journaux ; filtrés des réponses journalisées si l'API distante les renvoie en écho.
- Toute modification d'un connecteur incrémente sa `version` ; chaque publication enregistre la version utilisée.
- Dans un workflow, `publish.api` est toujours précédé de `control.approval` (validation à l'enregistrement du graphe).

## 6. Interfaces

- Liste des connecteurs (statut, dernier envoi, taux de succès).
- Éditeur : sections Requête, Authentification, Mapping (éditeur arborescent avec, pour chaque feuille, le choix constante, chemin ou gabarit, et l'autocomplétion des chemins disponibles), Réponse, Retries.
- Aperçu en direct du payload sur un bulletin choisi.
- Sur un bulletin : bouton « Pousser vers… » avec choix du connecteur, dry-run, confirmation, puis suivi.

# Spec 04 — Modèles de bulletins et drafts

## 1. Modèle de bulletin (par espace, versionné)

Un modèle décrit **quoi produire** (champs), **comment le générer** (consignes IA par champ), **comment le rendre** (gabarit Liquid) et **quand l'appliquer** (règles de sujet).

```yaml
name: "Bulletin vulnérabilité critique éditeur"
language: fr
priority: 100                 # la plus haute priorité gagne quand plusieurs modèles correspondent
match_rules:                  # toutes les conditions d'un bloc doivent être vraies ; blocs en OU
  - technologies_any: ["microsoft/windows", "microsoft/exchange_server"]
    severity_min: high
  - kev: true
style_guide: |
  Ton factuel, phrases courtes, pas de spéculation. Toujours citer les sources.
fields:
  - key: title
    label: "Titre"
    type: text
    required: true
    max_length: 160
    generation: { mode: ai, instructions: "Titre court : produit, type de vulnérabilité, impact." }
  - key: severity
    type: enum
    options: [critical, high, medium, low]
    generation: { mode: computed, from: "vuln.severity" }
  - key: summary
    type: markdown
    max_length: 2000
    generation: { mode: ai, instructions: "Résumé en 5 lignes pour un RSSI." }
  - key: affected_products
    type: list
    item_schema: { vendor: text, product: text, versions: text }
    generation: { mode: ai, instructions: "Uniquement les produits confirmés par les sources." }
  - key: cves
    type: list
    generation: { mode: computed, from: "vuln.cve_ids" }
  - key: cvss
    type: cvss
    generation: { mode: computed, from: "vuln.cvss" }
  - key: exploitation
    type: markdown
    generation: { mode: ai, instructions: "État de l'exploitation et disponibilité de PoC, avec sources." }
  - key: recommendations
    type: markdown
    generation: { mode: ai, instructions: "Actions concrètes : correctifs, contournements, détection." }
  - key: references
    type: references
    generation: { mode: computed, from: "evidence.references" }
  - key: analyst_note
    type: markdown
    generation: { mode: manual }
render_template: |
  # {{ fields.title }}

  **Sévérité** : {{ fields.severity | severity_label }} — **CVE** : {{ fields.cves | join: ", " }}

  ## Résumé
  {{ fields.summary }}

  ## Produits concernés
  {% for p in fields.affected_products %}- {{ p.vendor }} {{ p.product }} ({{ p.versions }})
  {% endfor %}
  ## Exploitation
  {{ fields.exploitation }}

  ## Recommandations
  {{ fields.recommendations }}

  ## Références
  {% for r in fields.references %}- [{{ r.title }}]({{ r.url }})
  {% endfor %}
example: "…bulletin de référence pour guider le style (few-shot)…"
```

Types de champs : `text`, `markdown`, `enum`, `list`, `cvss`, `date`, `references`, `products`, `boolean`.
Modes de génération : `ai` (rempli par le LLM selon la consigne), `computed` (copié depuis les données de la vulnérabilité, sans LLM), `manual` (laissé vide pour l'analyste).

État en phase 6 (merge request 6A) : modèles versionnés (`bulletin_templates`, `bulletin_template_versions`, une `spec` validée par version), `tlp` par modèle (AMBER par défaut, Q38), réglages d'espace (`bulletin_settings` : préfixe de référence Q37, double validation désactivée par défaut, modèle par défaut), trois modèles livrés (Q39). Sources des champs `computed` : liste fermée (`app/bulletins/spec.py`, `COMPUTED_SOURCES` : `vuln.*`, `evidence.references`, `synthesis.*`), compatible avec le type du champ. Conditions des règles : `technologies_any` (« éditeur » ou « éditeur/produit »), `severity_min`, `kev`, `exploitation_in`, `priority_in`, `cwe_any`, `epss_min`. Le gabarit reçoit `fields`, `tlp` et `language` ; filtres ajoutés : `severity_label` (langue en argument) et `tlp_label`. API : `/workspaces/{ws}/bulletin-templates` (versions, activation, `preview`, `match`) et `/workspaces/{ws}/bulletin-settings`. Rendu : ADR-029.

## 2. Sélection du modèle

1. L'analyste choisit explicitement un modèle, **ou**
2. le système évalue les `match_rules` des modèles actifs de l'espace sur la vulnérabilité (technos, éditeur, catégorie, sévérité, KEV, statut d'exploitation, tags) et propose celui de plus haute priorité ; le modèle « par défaut » de l'espace sert de repli.
3. L'interface montre pourquoi un modèle a été retenu (règle satisfaite) et permet de changer.

## 3. Demande unitaire de draft

Entrées possibles : une ou plusieurs vulnérabilités, un identifiant CVE (créé à la volée en `new` s'il n'existe pas), une liste d'URL, ou un texte libre ; plus le modèle et des consignes complémentaires optionnelles.

Déroulement (file `ai`) :

1. Construction du contexte : données du catalogue CVE, enrichissements, synthèse IA existante, preuves (extraits plafonnés et balisés comme non fiables), technos.
2. Dérivation d'un JSON Schema à partir des champs `ai` du modèle (types, longueurs, énumérations).
3. Appel LLM en sortie structurée, avec le guide de style, l'exemple et les consignes par champ.
4. Validation Pydantic : en cas d'échec, une relance ciblée, sinon `generation_failed` avec la raison.
5. Calcul des champs `computed`, puis rendu Liquid → Markdown → HTML assaini (markdown-it-py sans HTML brut, nh3, liens `http(s)` uniquement).
6. Création du bulletin (`draft`) et de la révision 1 (`created_by_type = ai`, `agent_run_id`).
7. Progression diffusée en SSE ; notification au demandeur.

## 4. Édition, relecture, publication

- Éditeur à deux volets : formulaire des champs (Markdown avec CodeMirror) et aperçu rendu côté serveur.
- Chaque enregistrement crée une révision immuable ; diff entre révisions ; on peut régénérer **un seul champ** avec une consigne.
- `in_review` (facultatif) : la double validation est **désactivée par défaut** (décision Q4) ; un analyste peut approuver et publier son propre bulletin. Si un espace l'active, le relecteur doit être différent de l'auteur.
- `published` : ré-authentification MFA récente ; la révision publiée est figée (`published_revision_id`, `content_hash`) ; elle devient visible sur le portail selon l'audience et le TLP.
- Mise à jour d'un bulletin publié : nouvelle révision, nouvelle relecture, puis republication (historique visible des clients : « mis à jour le … »).
- `withdrawn` : retrait du portail avec un motif ; audité.

## 5. Langues, formats et exports

Bulletins en **français et en anglais** (Q10) : chaque modèle a une langue ; une action « Générer la version EN/FR » crée un bulletin lié (`translation_of`) à partir de la version validée, à relire avant publication.

Visibilité inter-équipes : un bulletin publié est lisible par l'autre équipe (ADR-024).


Markdown et HTML, **PDF** (WeasyPrint dans un worker isolé, gabarit sobre avec logo configurable) et **e-mail** aux clients (Q11) dès le MVP ; JSON (champs), CSAF 2.0 (phase 7).

## 6. Sécurité spécifique

- Le gabarit est écrit par un analyste, les valeurs viennent du LLM ou des données : le rendu Liquid ne réinterprète jamais une valeur comme gabarit.
- Filtres Liquid en liste blanche ; limites de boucles et de taille de sortie ; temps de rendu borné.
- Les liens et les images du HTML final sont filtrés (schémas autorisés, pas d'images distantes chargées automatiquement sur le portail).
- L'aperçu de modèle est calculé côté serveur avec les mêmes règles que la production.

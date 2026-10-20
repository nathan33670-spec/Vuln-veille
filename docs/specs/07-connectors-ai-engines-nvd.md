# Spec 07 — Connecteurs, moteurs IA et vecteur d'entrée NVD

## 1. Cadre commun des connecteurs

Un **connecteur** est la configuration d'accès à un service externe, gérée depuis l'interface. Trois familles partagent le même cadre :

| Famille | Exemples | Spec |
|---|---|---|
| `source` (veille) | NVD, CISA KEV, EPSS, GitHub, X (lecture gratuite), Stack Exchange, Mastodon, Bluesky, Reddit (RSS), Hacker News, RSS, web, OSV | ce document, §2 et §3 |
| `ai_engine` (moteur IA) | Claude (Anthropic), LLM open source (OpenLLM, vLLM, Ollama), Mistral, Azure OpenAI | ce document, §4 |
| `publish` (publication) | Connecteur HTTP générique, CSAF | spec 05 |

Propriétés communes :

| Propriété | Description |
|---|---|
| `family`, `kind` | Famille et type (`nvd`, `github`, `anthropic`, `openai_compatible`, `http_generic`…) |
| Portée | **Globale** (`workspace_id` nul, gérée par un admin : NVD, KEV, EPSS, moteur IA de plateforme) ou **espace** (gérée par les analystes de l'espace) |
| `config` | Paramètres non secrets, validés par un schéma Pydantic propre au type (qui génère aussi le formulaire de l'interface) |
| `secret_refs` | Références vers le coffre (jamais les valeurs) |
| `quotas` | Débit maximal, plafond de requêtes par jour ou par mois, plafond par exécution |
| `cost_class` | Déclarée dans le code par le type : `free` (gratuit sans compte), `free_account` (compte ou clé gratuits), `ai_billed` (facturé sur l'abonnement IA existant, budget obligatoire). **Aucun type `paid` n'est accepté** (ADR-023) : un test bloquant vérifie la classe de chaque type enregistré. |
| `egress_domains` | Domaines contactés, déclarés par le type ; ils alimentent la liste blanche du proxy de sortie |
| Santé | `last_check_at`, `last_success_at`, `last_error`, `consecutive_failures` ; alerte au-delà d'un seuil |
| `enabled`, `version` | Activation ; version incrémentée à chaque modification (auditée) |

Actions communes : **Tester la connexion** (appel sans effet de bord, par exemple une requête d'un seul résultat), activer ou désactiver, voir l'historique des modifications, voir la consommation des quotas.

Implémentation : `backend/app/connectors/` contient le cadre (`base.py` : `ConnectorType` avec `ConfigModel`, `secret_slots`, `egress_domains`, `health_check()`) et un sous-module par type. Les outils d'agents et les nœuds de workflows n'accèdent aux services externes **que** par un connecteur de leur espace (ou global), jamais avec des identifiants en paramètre.

## 2. Catalogue des connecteurs de veille

| Type | Portée | Authentification | Usage | Notes |
|---|---|---|---|---|
| `nvd` | Globale | Clé API (recommandée, une seule pour l'organisation) | **Vecteur d'entrée n°1**, enrichissement | Voir §3 ; NVD recommande une synchro incrémentale au plus toutes les 2 h |
| `cisa_kev` | Globale | Aucune | Statut « exploitée activement » | Flux JSON officiel |
| `epss` | Globale | Aucune | Probabilité d'exploitation | Mise à jour quotidienne |
| `cve_org` | Globale | Aucune | **Détection précoce (retenue, Q24)** : nouvelles CVE publiées par les CNA, souvent avant leur arrivée sur NVD | Dépôt public cvelistV5 (fichiers delta) ; émet `cve.published` avec la source `cve_org`, NVD complète ensuite l'enrichissement |
| `osv` | Globale | Aucune | Écosystèmes open source (purl) | — |
| `github` | Espace | Jeton (lecture seule, sans droit sur des dépôts privés) | GHSA, recherche de dépôts, code, commits et issues ; lecture de fichiers en texte | Quotas de l'API de recherche GitHub |
| `x_reader` | Espace | Aucune | **Lecture gratuite de X** : découverte de posts puis lecture par l'oEmbed officiel (§2.1) | Pas d'API X payante, pas de scraping |
| `stackexchange` | Espace | Clé gratuite optionnelle | Stack Overflow, Security StackExchange | Quotas journaliers |
| `mastodon` | Espace | Jeton optionnel, instance (par exemple infosec.exchange) | Posts et hashtags | Gratuit ; une grande partie de la communauté sécurité y publie |
| `bluesky` | Espace | Compte gratuit et mot de passe d'application (la recherche de posts exige une session) | Recherche de posts | Gratuit |
| `reddit` | Espace | Aucune | Flux RSS publics des subreddits choisis (r/netsec…) | L'API Data de Reddit n'est utilisée que si un usage gratuit est confirmé pour notre cas (Q31) |
| `hackernews` | Globale | Aucune | API Algolia de Hacker News | Gratuit |
| `searxng` | Globale | Aucune (instance auto-hébergée) | Recherche web gratuite, utilisée notamment pour découvrir des posts X quand le moteur IA n'a pas de recherche web | Option, conditions d'usage à valider (Q30) |
| `rss` | Espace | Aucune | Flux RSS ou Atom (CERT-FR, éditeurs, blogs) | — |
| `web` | Espace | Aucune | Pages d'avis éditeurs | Liste de domaines obligatoire, respect du robots.txt |
| `http_api` | Espace | Clé, bearer, basic, OAuth2 | API JSON générique | Mapping de la réponse en éléments |

Tous ces connecteurs sont gratuits (clé ou compte gratuits au plus). Les seuls coûts acceptés sont ceux de l'abonnement IA (ADR-023).

### 2.1 Lecture de X sans abonnement

Contrainte : aucun abonnement payant hors IA. L'API X est payante à l'usage depuis février 2026, et les conditions d'utilisation de X interdisent le scraping sans accord écrit, avec des dommages-intérêts forfaitaires annoncés pour les gros volumes. Le connecteur `x_reader` combine donc des moyens gratuits et autorisés, en trois couches :

| Couche | Comment | Coût | Disponibilité |
|---|---|---|---|
| **1. Découverte indirecte** | On récupère les liens `x.com` ou `twitter.com` cités dans les sources déjà collectées : références NVD, avis GHSA, README et issues GitHub, posts Mastodon et Bluesky, blogs et flux RSS, Hacker News | Gratuit | Toujours |
| **2. Recherche web du moteur IA** | L'agent « Réseaux sociaux » utilise la recherche web du moteur IA, restreinte à `x.com` et `twitter.com` (par exemple `CVE-2026-XXXX site:x.com`). Avec Gemini (démarrage), c'est la **recherche Google intégrée** (grounding) | Quota gratuit de Gemini (sans facturation activée) ; avec Claude via l'API, facturé sur l'abonnement IA et plafonné | Tant que le moteur IA fournit cette recherche (Gemini et Claude oui ; un LLMaaS probablement non : on garde alors la couche 1) |
| **3. Recherche auto-hébergée (option)** | Instance SearXNG interne interrogée avec `site:x.com` | Gratuit | Option, conditions d'usage des moteurs interrogés à valider (Q30) |

**Lecture d'un post** : une fois l'URL connue, le texte est obtenu par l'**oEmbed officiel** de X (`publish.x.com/oembed`), gratuit, sans authentification et documenté par X pour les traitements en masse. On garde le texte, l'auteur, la date et l'URL ; le HTML renvoyé est réduit à du texte puis assaini. Le résultat est mis en cache selon `cache_age` et marqué non fiable. Un post supprimé ou devenu privé (échec de l'oEmbed) est marqué « retiré ». Le respect de la politique développeur de X (affichage, suppression) est revérifié à l'implémentation.

**Principe du strict nécessaire** (consigne du porteur, s'applique à toutes les couches) :
- **Requêtes** : uniquement l'identifiant CVE, plus éditeur et produit si l'identifiant ne donne rien, toujours restreintes à `x.com` et `twitter.com`. Une requête par CVE dans le périmètre à sa publication ; la re-veille n'en relance que pour les CVE KEV, P1 ou P2.
- **Résultats** : on ne garde que l'URL, le titre et l'extrait. L'extrait suffit souvent à juger de la pertinence, sans aucun appel à X.
- **Lecture** : oEmbed uniquement pour les posts jugés pertinents, au plus 5 par CVE (configurable). Jamais de profil, de timeline, de liste d'abonnés, de réponses en cascade ni de média.
- **Conservation** : URL, identifiant public de l'auteur, date et texte, sans autre donnée personnelle ; durée alignée sur les éléments collectés (Q17) ; purge des posts retirés.
- **Plafonds** : nombre de requêtes et de lectures par CVE, par jour et par espace ; arrêt dur une fois le plafond atteint.

**Recherche Google, évaluée le 2026-10-20 à la demande du porteur, non retenue en l'état** :
- L'API officielle (Custom Search JSON API avec un Programmable Search Engine restreint à `x.com`, 100 requêtes gratuites par jour) **n'accepte plus de nouveaux clients et s'arrête le 1er janvier 2027**. Le remplaçant proposé par Google (Vertex AI Search) est payant.
- Interroger google.com par automate, directement ou via SearXNG, va à l'encontre des conditions de Google, qui interdisent l'accès automatisé contraire au robots.txt ; il se heurte aussi rapidement aux captchas et aux blocages d'IP.
- Brave Search API (alternative proche) exige désormais une carte bancaire et facture au-delà des crédits gratuits, ce qui est contraire à la règle « zéro abonnement payant ».
- **Décision du porteur (Q32, 2026-10-20) : couches 1 et 2 uniquement**, avec le principe du strict nécessaire. La couche 3 (SearXNG) est abandonnée.

**Exclus** :
- l'API X payante ;
- le scraping de x.com, y compris avec un navigateur headless ;
- les jetons de session de comptes X (Nitter auto-hébergé, twscrape…) ;
- les services tiers payants qui revendent des données X.

**Limites assumées** : la couverture de X sera partielle. Il n'y a pas de recherche exhaustive en temps réel ni de suivi de comptes : les timelines par oEmbed ne sont rendues que dans le navigateur. On compense en suivant sur Mastodon et Bluesky les chercheurs qui y publient aussi. En phase 4, un indicateur mesure la couverture : part des CVE pour lesquelles une discussion X pertinente est trouvée, comparée à un échantillon vérifié à la main.

## 3. NVD, vecteur d'entrée n°1

### 3.1 Synchronisation

- Tâche globale `catalog.nvd_sync` (file `collect`), lancée par le scheduler selon l'intervalle du connecteur (**120 minutes par défaut**, conformément à la recommandation NVD ; l'admin peut le réduire en connaissance de cause).
- Fenêtre : `lastModStartDate` = fin de la dernière synchro réussie moins 5 minutes de recouvrement, `lastModEndDate` = maintenant. Les deux bornes sont toujours envoyées.
- Pagination (`resultsPerPage` au maximum, `startIndex`), pause entre les requêtes, backoff exponentiel sur 403, 429 et 503, reprise sur le curseur en cas d'échec : aucune fenêtre n'est perdue.
- **Rattrapage initial** : profondeur configurable (par exemple 90 jours), découpé en fenêtres de 120 jours au maximum, **sans** émettre d'événements, pour ne pas lancer des centaines d'investigations d'un coup.
- Les limites exactes (requêtes par fenêtre de 30 secondes avec et sans clé, taille de page, durée maximale d'une fenêtre) sont vérifiées dans la documentation NVD au moment de l'implémentation, puis paramétrées.

### 3.2 Détection des nouveautés et changements

Pour chaque CVE reçue, on compare avec l'état connu dans `cve_records` :

| Situation | Événement | Usage typique |
|---|---|---|
| CVE inconnue | `cve.published` | **Lance l'investigation** |
| CVSS ajouté (NVD ou CNA) ou sévérité relevée | `cve.updated` (`cvss_added`, `severity_raised`) | Re-évaluer le périmètre et la priorité |
| Configurations CPE ajoutées | `cve.updated` (`cpe_added`) | Re-évaluer le périmètre : une CVE peut y entrer quand NVD l'enrichit |
| Champs KEV renseignés | `cve.updated` (`kev_added`) | Alerte, priorité relevée, draft automatique possible |
| Référence étiquetée « Exploit » ajoutée | `cve.updated` (`exploit_reference_added`) | Re-veille ciblée |
| Statut « Rejected » | `cve.updated` (`rejected`) | Proposer la clôture de la vulnérabilité |

Les événements sont écrits dans l'outbox dans la même transaction que la mise à jour du catalogue, et chaque changement est historisé dans `cve_changes` (chronologie visible sur la fiche).

### 3.3 Diffusion vers les espaces

Les événements NVD sont globaux. Le dispatcher les diffuse à chaque espace qui a au moins un workflow actif avec `trigger.cve_published` ou `trigger.cve_updated` (filtre JMESPath optionnel). L'exécution a lieu **dans l'espace**, avec ses agents, ses connecteurs, son moteur IA et son budget. Le débit est borné (par exemple 20 investigations simultanées par espace, le reste en file).

### 3.4 Périmètre de veille de l'espace

Le nœud `vuln.scope_match` décide si une CVE mérite une investigation :

- **mode** : `all` (toutes les nouvelles CVE) ou `scoped` (filtré, par défaut) ;
- technos suivies (catalogue) : correspondance par CPE, purl, puis éditeur et produit dans la description ;
- éditeurs et mots-clés supplémentaires ;
- seuil CVSS (les CVE sans score encore publié peuvent être incluses ou mises en attente) ;
- KEV : toujours inclus ;
- CWE inclus ou exclus ;
- option (phase 9) : inclure les technos suivies par les clients.

Sorties `in_scope` et `out_of_scope`. Une CVE hors périmètre reste consultable dans le **catalogue CVE**, avec un bouton « Promouvoir en vulnérabilité ». Le mécanisme est économe : les agents coûteux ne tournent que sur les CVE pertinentes, mais rien n'est perdu.

### 3.5 Saisie manuelle

Un analyste peut saisir un identifiant CVE (récupéré à la volée sur NVD s'il est absent du catalogue) ou une vulnérabilité sans CVE. L'événement `vuln.created` (origine `user`) lance le même workflow d'investigation.

## 4. Moteurs IA

### 4.1 Principe : moteur préféré interchangeable

- Un **moteur IA** est un connecteur `ai_engine` : type (`gemini`, `openai_compatible` ou `anthropic`), URL de base, authentification, liste de modèles avec leurs capacités.
- **Moteur préféré** à trois niveaux : plateforme (admin), surchargé par espace (analystes de l'espace), puis par agent (« hériter » ou « épingler » un moteur et un modèle).
- **Au démarrage (ADR-025, budget 0 €)** : **Gemini, palier gratuit** de Google AI Studio, adaptateur `gemini` (SDK `google-genai`), sans facturation activée.
- **Ensuite** : un **LLMaaS** compatible OpenAI (adaptateur `openai_compatible`), puis éventuellement **Claude** via l'API (adaptateur `anthropic`, modèle `claude-opus-5-5`) si un budget existe. L'abonnement Claude Pro ne donne pas accès à l'API.
- Le changement se fait en modifiant le moteur préféré, sans toucher au code ; les admins décident librement, le banc d'évaluation (§4.6) est facultatif (Q26).

### 4.2 Capacités d'un modèle

| Capacité | Valeurs | Effet |
|---|---|---|
| `tools` | `native`, `emulated`, `none` | `emulated` : le runtime demande l'appel d'outil sous forme d'un JSON contraint (`{tool, arguments}`), validé par schéma |
| `structured_output` | `native`, `guided_json`, `none` | `guided_json` : décodage guidé par schéma (proposé par vLLM, par exemple) ; `none` : JSON demandé par le prompt, validé puis relancé une fois |
| `context_window`, `max_output_tokens` | entiers | Le constructeur de contexte tronque les preuves de façon déterministe (les plus pertinentes d'abord) |
| `reasoning_levels` | sous-ensemble de `low`, `medium`, `high`, `max` | Correspondance avec le paramètre du fournisseur |
| `streaming`, `prompt_cache` | booléens | Optimisations activées si disponibles |

Les capacités sont **déclarées** puis **vérifiées** par un test automatique (complétion simple, sortie JSON conforme à un schéma, aller-retour d'appel d'outil), relancé à chaque modification du connecteur.

### 4.3 Paramètres abstraits des agents

Les agents se configurent avec des paramètres indépendants du fournisseur, que chaque adaptateur traduit :

| Paramètre abstrait | Claude (adaptateur `anthropic`) | LLM open source (adaptateur `openai_compatible`) |
|---|---|---|
| `reasoning_level` | `output_config.effort` (réflexion adaptative, toujours active sur Claude Opus 5.5) | `reasoning_effort` si le modèle le prend en charge, sinon ignoré |
| `output_schema` | `output_config.format` et outils `strict` | `response_format` JSON Schema ou décodage guidé |
| `max_output_tokens` | `max_tokens` (streaming pour les sorties longues) | `max_tokens` |
| Outils | Outils natifs, `tool_choice: auto` | Outils natifs ou émulés |
| Refus | `stop_reason: refusal` géré, fallback serveur | Détection heuristique (réponse vide ou refus explicite) |

Les prompts sont rédigés pour être portables (consignes claires, balisage des documents, schéma explicite). Une **variante de prompt par moteur** reste possible si le banc d'évaluation montre un écart.

### 4.4 Rapport de compatibilité

Avant de changer le moteur préféré (plateforme ou espace), l'interface affiche pour chaque agent concerné si le modèle cible couvre ses besoins (outils, sortie structurée, taille de contexte, niveau de raisonnement). Les agents incompatibles doivent être épinglés sur l'ancien moteur ou adaptés avant validation.

### 4.5 Politique de données par moteur

- Chaque moteur déclare sa localisation (`external_cloud` ou `self_hosted`) et les classes de données qu'il peut recevoir (`public`, `tlp_clear`, `tlp_green`, `tlp_amber`, `tlp_red`, `client_data`).
- Le constructeur de contexte refuse d'envoyer une donnée de classe supérieure à celle autorisée. Par exemple, le CERT peut réserver les sujets TLP:AMBER à un modèle auto-hébergé.
- Par défaut (Q6) : un palier **gratuit** (Gemini) reçoit uniquement des données publiques et TLP:CLEAR ; Claude via l'API reçoit tout sauf TLP:RED ; un LLMaaS se configure selon son contrat. Les abonnements clients et les secrets ne sont jamais envoyés à un LLM.

### 4.6 Banc d'évaluation

- Jeu de référence : 30 à 50 CVE variées, avec pour chacune la synthèse attendue et/ou un bulletin validé par les analystes.
- Critères : taux de sorties valides (schéma), validité des citations (URL présentes dans les sources consultées), exactitude des champs clés (produits, statut d'exploitation, correctifs), notation par grille (relecture en aveugle par un analyste, ou un LLM juge, au choix), latence, coût par CVE, taux de refus.
- Rapport comparatif entre moteur actuel et moteur candidat, conservé avec la décision de bascule (audit).
- Lancement manuel et budgété (jamais en CI, sauf avec un moteur simulé).

### 4.7 Sécurité d'un moteur auto-hébergé

- Accès en TLS avec jeton, sur un réseau privé ; l'exception réseau privé est autorisée par un admin et auditée.
- Jamais exposé sur Internet ; débit limité.
- Modèles chargés au format `safetensors`, depuis une source vérifiée (empreinte notée dans la configuration).

## 5. Agents de veille prédéfinis (seeds par espace)

| Agent | Connecteurs et outils | Sortie |
|---|---|---|
| **Triage** | `nvd_lookup`, `epss_lookup`, `kev_lookup`, `technology_lookup`, `internal_vuln_search` | Pertinence, catégorie, technos probables, doublon éventuel, priorité suggérée |
| **Chasseur de PoC GitHub** | `github_search`, `github_get` | PoC trouvés, crédibilité, **signaux de PoC piégé** (binaires, code obfusqué, dépôt récent sans historique, demande d'exécution de commandes) |
| **Réseaux sociaux** | `x_discover`, `x_read` (lecture gratuite de X, §2.1), `social_search` (Mastodon, Bluesky) | Signalements d'exploitation, chercheurs impliqués, liens utiles |
| **Forums techniques** | `stackexchange_search`, `social_search` (flux RSS Reddit, Hacker News) | Contournements, problèmes liés aux correctifs |
| **Avis éditeurs** | `web_fetch` (domaines des éditeurs), `osv_lookup` | Correctifs, versions corrigées, contournements officiels |
| **Synthèse** | Aucun outil externe (travaille sur les sorties des autres et les preuves) | Synthèse d'investigation (schéma de la spec 03 §7) avec citations |
| **Rédacteur de bulletin** | Aucun outil externe | Champs du modèle de bulletin (spec 04) |

Chaque agent est un objet ordinaire de l'espace : les analystes VOC et CERT modifient leurs copies (prompt, moteur, modèle, connecteurs, limites) indépendamment.

Workflow seed « Nouvelle CVE NVD → investigation » :

```
trigger.cve_published
  → vuln.scope_match ──(out_of_scope)──► fin (reste dans le catalogue CVE)
  → (in_scope) vuln.upsert (new) → vuln.enrich → vuln.match_technologies
  → ai.agent[Triage] → control.if(pertinent)
  → en parallèle : ai.agent[PoC GitHub] | ai.agent[Réseaux sociaux] | ai.agent[Forums] | ai.agent[Avis éditeurs]
  → transform.merge → ai.agent[Synthèse] → vuln.attach_analysis
  → control.if(KEV ou exploitation ou P1) → notify.email
```

Workflow seed « Re-veille » : `trigger.schedule` (toutes les 6 h) → `vuln.list` (vulnérabilités ouvertes de moins de 14 jours) → agents PoC et réseaux sociaux (fenêtre depuis la dernière recherche) → mise à jour de la synthèse si du nouveau est trouvé → notification. Et `trigger.cve_updated(kev_added | exploit_reference_added)` → même traitement immédiat.

## 6. Interfaces

- **Connecteurs** : onglets Veille, Moteurs IA, Publication ; pour chacun : formulaire généré, secrets en écriture seule, test, santé, quotas et consommation, historique.
- **Moteurs IA** : moteur préféré (plateforme, espace), modèles et capacités, test de capacités, rapport de compatibilité, lancement et historique du banc d'évaluation.
- **Agents** : liste par espace, édition (identité, moteur hérité ou épinglé, modèle, niveau de raisonnement, prompt, connecteurs et domaines, schéma de sortie, limites), bac à sable (lancer sur une CVE, voir les étapes, le coût et les signaux d'injection), versions et diff.
- **Catalogue CVE** : nouveautés NVD (filtrables : dans ou hors du périmètre de chaque espace), état de la synchronisation (dernière réussite, retard), promotion manuelle.

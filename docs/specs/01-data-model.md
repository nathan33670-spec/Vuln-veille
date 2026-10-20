# Spec 01 — Modèle de données

Conventions : clé primaire `id` UUIDv7 (sauf mention contraire), `created_at` et `updated_at` en `timestamptz`, `version` (entier) pour le verrouillage optimiste sur les objets édités. Les colonnes `*_enc` sont chiffrées par le coffre de secrets. Toute table marquée **[E]** porte `workspace_id NOT NULL` et une politique RLS ; **[C]** porte `client_org_id` et une politique RLS ; **[G]** est globale.

## 1. Identité et accès

| Table | Colonnes principales |
|---|---|
| `users` [G] | `email` (citext, unique), `display_name`, `user_type` (`internal`, `client`), `status` (`invited`, `active`, `disabled`, `locked`), `password_hash`, `password_changed_at`, `failed_login_count`, `locked_until`, `last_login_at`, `locale` |
| `user_global_roles` [G] | `user_id`, `role` (`platform_admin`), `granted_by`, `granted_at` |
| `user_mfa_totp` [G] | `user_id` (PK), `secret_enc`, `confirmed_at`, `last_used_step` |
| `user_recovery_codes` [G] | `user_id`, `code_hash`, `used_at` |
| `webauthn_credentials` [G] | phase 10 |
| `sessions` [G] | `id_hash` (PK), `user_id`, `audience` (`backoffice`, `portal`), `created_at`, `last_seen_at`, `idle_expires_at`, `absolute_expires_at`, `mfa_verified_at`, `step_up_at`, `ip`, `user_agent`, `revoked_at` |
| `auth_tokens` [G] | `token_hash`, `user_id`, `purpose` (`invitation`, `password_reset`, `email_change`), `expires_at`, `used_at` |
| `workspaces` [G] | `slug` (`voc`, `cert`), `name`, `settings` (JSONB : double validation, budgets, politique LLM, rétention) |
| `workspace_memberships` [G] | `user_id`, `workspace_id`, `role` (`analyst`, `viewer`), unique (`user_id`, `workspace_id`) |
| `client_organizations` [G] | `name`, `status`, `settings` (MFA obligatoire…) |
| `client_memberships` [G] | `user_id`, `client_org_id`, `role` (`client_user`, `client_admin`) |

## 2. Transverse

| Table | Colonnes principales |
|---|---|
| `audit_events` [G] | `id` (bigserial), `occurred_at`, `actor_type` (`user`, `system`, `workflow`), `actor_user_id`, `action`, `target_type`, `target_id`, `workspace_id`, `client_org_id`, `ip`, `request_id`, `details` (JSONB, expurgé), `prev_hash`, `hash` |
| `secrets` [E ou G] | `workspace_id` (null = global), `purpose` (`llm`, `source`, `connector`, `webhook`), `name`, `ciphertext`, `dek_enc`, `kek_id`, `nonce`, `hint_last4`, `created_by`, `rotated_at` |
| `outbox_events` [G] | `id` (bigserial), `type`, `workspace_id`, `payload`, `created_at`, `dispatched_at`, `attempts` |
| `notifications` [G] | `user_id`, `type`, `payload`, `read_at` |

## 3. Catalogues

| Table | Colonnes principales |
|---|---|
| `cve_records` [G] | `cve_id` (PK, texte), `published_at`, `last_modified_at`, `description`, `cvss` (JSONB : v4.0, v3.1 avec vecteurs, scores et source NVD ou CNA), `cwes` (text[]), `references` (JSONB, avec étiquettes NVD), `cpe_configurations` (JSONB), `kev` (JSONB : date d'ajout, échéance, action requise, ransomware), `epss_score`, `epss_percentile`, `epss_date`, `vuln_status` (statut NVD : Received, Awaiting Analysis, Analyzed, Rejected…), `first_seen_at` (première détection par la plateforme), `from_backfill` (booléen), `synced_at` |
| `cve_changes` [G] | `id` (bigserial), `cve_id`, `detected_at`, `change_types` (text[] : `published`, `cvss_added`, `severity_raised`, `cpe_added`, `kev_added`, `exploit_reference_added`, `rejected`), `diff` (JSONB) |
| `sync_cursors` [G] | `connector_id` (PK), `cursor` (JSONB : fin de la dernière fenêtre réussie…), `last_success_at`, `last_error`, `running_since` |
| `technologies` [G] | `vendor`, `product`, `display_name`, `aliases` (text[]), `cpe_prefixes` (text[]), `purls` (text[]), `category`, `status` (`active`, `deprecated`, `merged`), `merged_into`, `created_from_request_id` ; index trigramme pour la recherche approchée |
| `technology_requests` [C] | `client_org_id`, `requested_by`, `vendor`, `product`, `url`, `justification`, `status` (`pending`, `approved`, `rejected`, `duplicate`), `resolved_technology_id`, `reviewer_id`, `review_comment`, `resolved_at` |
| `subscriptions` [C] | `client_org_id`, `user_id` (null = toute l'organisation), `technology_id`, `min_severity`, `channels` (JSONB) |

## 4. Collecte

| Table | Colonnes principales |
|---|---|
| `watch_scopes` [E] | Périmètre de veille (un par espace) : `mode` (`all`, `scoped`), `technology_ids` (uuid[]), `vendors`, `keywords` (text[]), `cvss_min`, `include_unscored` (`include`, `wait`, `exclude`), `always_include_kev`, `cwe_include`, `cwe_exclude` (text[]), `include_client_subscriptions` (phase 9), `version` |
| `watch_sources` [E] | `name`, `type` (`rss`, `x_account`, `github_repo`, `mastodon_account`, `website`…), `config` (JSONB), `tags` (text[]), `trust_level`, `enabled` |
| `collected_items` [E] | `run_id`, `node_id`, `source_type`, `source_ref`, `url`, `url_hash`, `title`, `content_text` (plafonné), `author`, `published_at`, `fetched_at`, `content_hash`, `cve_ids` (text[]), `language`, `raw` (JSONB plafonné), `trust` (toujours `untrusted`) ; unique (`workspace_id`, `content_hash`) |
| `dedupe_keys` [E] | `namespace`, `key_hash`, `first_seen_at`, `expires_at` |

## 5. Vulnérabilités

| Table | Colonnes principales |
|---|---|
| `vulnerabilities` [E] | `ref` (`VV-2026-0001`, séquence par espace), `cve_id` (nullable), `aliases` (text[] : GHSA, identifiants éditeur), `title`, `summary`, `status`, `duplicate_of`, `priority` (`P1`…`P4`), `severity`, `cvss_override` (JSONB), `exploitation_status` (`unknown`, `poc_public`, `exploited_itw`, `not_exploitable`), `patch_status` (`unknown`, `available`, `partial`, `none`, `workaround`), `assignee_id`, `first_seen_at`, `qualified_at`, `qualified_by`, `origin` (`workflow`, `user`), `source_run_id` |
| `vulnerability_technologies` [E] | `vulnerability_id`, `technology_id`, `matched_by` (`cpe`, `purl`, `ai`, `manual`), `confidence` |
| `vulnerability_evidence` [E] | `vulnerability_id`, `collected_item_id`, `kind` (`advisory`, `poc`, `exploit`, `patch`, `discussion`, `mention`, `news`), `note`, `confidence`, `added_by_type`, `added_by` |
| `vulnerability_analyses` [E] | `vulnerability_id`, `agent_run_id`, `content` (JSONB conforme au schéma de synthèse), `injection_flags` (JSONB), `created_at` |
| `vulnerability_comments` [E] | `vulnerability_id`, `author_id`, `body` (Markdown assaini) |
| `vulnerability_events` [E] | `vulnerability_id`, `type`, `actor`, `data`, `occurred_at` (chronologie) |

Statuts d'une vulnérabilité :

```
new ──► triage ──► qualified
  │        ├────► rejected      (non pertinente, faux positif)
  │        ├────► duplicate     (duplicate_of renseigné)
  │        └────► monitoring    (en attente d'information) ──► triage
  └───────────────► (mêmes transitions directes depuis new)
```

« Non qualifiée » = `new` ou `triage`. Le passage à `qualified` exige au minimum une priorité et un titre.

## 6. Workflows

| Table | Colonnes principales |
|---|---|
| `workflows` [E] | `name`, `description`, `status` (`draft`, `active`, `paused`, `archived`), `active_version_id`, `tags`, `created_by`, `version` |
| `workflow_versions` [E] | `workflow_id`, `version_no`, `graph` (JSONB), `graph_hash`, `comment`, `created_by`, `created_at` ; **immuable** |
| `workflow_triggers` [E] | `workflow_id`, `type` (`schedule`, `webhook`, `event`, `manual`), `config`, `next_fire_at`, `webhook_secret_id`, `enabled` |
| `workflow_runs` [E] | `workflow_id`, `version_id`, `trigger_type`, `triggered_by`, `status` (`queued`, `running`, `waiting_approval`, `succeeded`, `failed`, `cancelled`, `timed_out`), `started_at`, `finished_at`, `error`, `stats` |
| `node_runs` [E] | `run_id`, `node_id`, `attempt`, `status`, `started_at`, `finished_at`, `input_count`, `output` (JSONB plafonné), `output_truncated`, `error`, `logs` (JSONB), `metrics` (durée, tokens, coût) ; unique (`run_id`, `node_id`, `attempt`) |
| `workflow_approvals` [E] | `run_id`, `node_id`, `requested_at`, `decided_by`, `decision`, `comment`, `decided_at` |

## 7. IA

Les moteurs IA sont des connecteurs de famille `ai_engine` (section 9).

| Table | Colonnes principales |
|---|---|
| `ai_models` [E ou G] | `connector_id` (moteur), `model_id` (par exemple `claude-opus-5-5`), `display_name`, `capabilities` (JSONB : `tools`, `structured_output`, `context_window`, `max_output_tokens`, `reasoning_levels`, `streaming`, `prompt_cache`), `capabilities_verified_at`, `price_input_per_mtok`, `price_output_per_mtok`, `enabled` |
| `ai_engine_preferences` [G] | `scope` (`platform` ou un `workspace_id`), `connector_id`, `model_id`, `changed_by`, `changed_at`, `evaluation_report_id` (rapport du banc ayant justifié la bascule) |
| `ai_evaluations` [E ou G] | `dataset_id`, `candidate` (moteur et modèle), `baseline`, `status`, `metrics` (JSONB), `report`, `cost`, `created_by`, `created_at` |
| `ai_eval_datasets` [E ou G] | `name`, `items` (JSONB : CVE et sorties attendues validées par les analystes) |
| `ai_agents` [E] | `name`, `description`, `active_version_id`, `enabled`, `preset` (agent prédéfini d'origine, le cas échéant) |
| `ai_agent_versions` [E] | `agent_id`, `version_no`, `engine_mode` (`inherit`, `pinned`), `engine_connector_id`, `model_id`, `reasoning_level`, `system_prompt`, `prompt_variants` (JSONB par moteur), `allowed_connectors` (uuid[]), `tools` (text[]), `tool_config` (JSONB : domaines autorisés…), `output_schema` (JSONB), `limits` (JSONB : tours, tokens, appels d'outils, timeout, coût maximal), `data_classes` (text[]) ; **immuable** |
| `agent_runs` [E] | `agent_version_id`, `context_type` (`node_run`, `draft_request`, `vulnerability`, `test`, `evaluation`), `context_id`, `engine_connector_id`, `model_requested`, `model_served`, `status`, `stop_reason`, `refusal_category`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `cost_estimate`, `started_at`, `finished_at`, `error` |
| `agent_steps` [E] | `agent_run_id`, `seq`, `type` (`llm_call`, `tool_call`, `tool_result`), `payload` (JSONB plafonné, expurgé), `created_at` |
| `llm_budgets` [E] | `period` (mois), `limit_usd`, `spent_usd`, `hard_stop` |

## 8. Bulletins

| Table | Colonnes principales |
|---|---|
| `bulletin_templates` [E] | `name`, `description`, `status` (`draft`, `active`, `archived`), `active_version_id` |
| `bulletin_template_versions` [E] | `template_id`, `version_no`, `match_rules` (JSONB), `priority`, `fields` (JSONB), `render_template` (Liquid), `style_guide`, `example`, `language` ; **immuable** |
| `draft_requests` [E] | `requested_by`, `input` (JSONB : identifiants de vulnérabilités, CVE, URL, texte), `template_version_id`, `extra_instructions`, `status` (`queued`, `running`, `succeeded`, `failed`), `bulletin_id`, `agent_run_id`, `error` |
| `bulletins` [E] | `ref` (`VOC-2026-0042`), `title`, `status`, `severity`, `tlp`, `audience_type` (`all_clients`, `selected`), `template_version_id`, `current_revision_id`, `published_revision_id`, `author_id`, `reviewer_id`, `approved_at`, `published_at`, `withdrawn_at`, `version` |
| `bulletin_revisions` [E] | `bulletin_id`, `rev_no`, `fields` (JSONB), `rendered_markdown`, `rendered_html` (assaini), `content_hash`, `created_by_type` (`ai`, `user`), `created_by`, `agent_run_id`, `change_note` ; **immuable** |
| `bulletin_vulnerabilities` [E] | `bulletin_id`, `vulnerability_id` |
| `bulletin_technologies` [E] | `bulletin_id`, `technology_id` |
| `bulletin_audiences` [E] | `bulletin_id`, `client_org_id` |

Statuts d'un bulletin :

```
generating ──► draft ◄──► in_review ──► approved ──► published ──► withdrawn
     │                                      │              │
     └──► generation_failed                 └─► draft      └─► (nouvelle révision → in_review → published)
```

## 9. Connecteurs et publication

| Table | Colonnes principales |
|---|---|
| `connectors` [E ou G] | `workspace_id` (nul = global, géré par un admin), `family` (`source`, `ai_engine`, `publish`), `kind` (`nvd`, `cisa_kev`, `epss`, `github`, `x`, `stackexchange`, `mastodon`, `bluesky`, `reddit`, `rss`, `web`, `osv`, `http_api`, `anthropic`, `openai_compatible`, `http_generic`, `csaf_export`…), `name`, `config` (JSONB non secret, validé par le schéma du type), `secret_refs` (JSONB), `quotas` (JSONB : débit, budget mensuel, plafond par exécution), `usage_current_period` (JSONB), `egress_domains` (text[]), `allow_private_network`, `private_network_cidrs`, `private_network_approved_by`, `data_policy` (JSONB, moteurs IA : localisation, classes de données), `last_check_at`, `last_success_at`, `last_error`, `consecutive_failures`, `enabled`, `version` |
| `publications` [E] | `bulletin_id`, `revision_id`, `connector_id`, `connector_version`, `status` (`pending`, `sending`, `succeeded`, `failed`, `dry_run`), `attempt`, `idempotency_key`, `remote_id`, `request_preview` (JSONB expurgé), `response_status`, `response_excerpt`, `error`, `triggered_by` |

## 10. Portail

- Vue `portal_bulletins_v` : bulletins `published`, non retirés, avec uniquement les colonnes exposables (`id`, `ref`, `title`, `severity`, `tlp`, `published_at`, `updated_at`, `rendered_html`, technos, espace émetteur) ; filtrage par `client_org_id` (audience) via RLS.
- Le rôle `vv_portal` a `SELECT` sur cette vue et des droits limités sur `subscriptions` et `technology_requests` de son organisation, et rien d'autre.

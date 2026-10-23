# RBAC — Rôles, périmètres et permissions

## 1. Principes

- **Refus par défaut** : une action n'est permise que si une permission explicite l'accorde dans le bon périmètre.
- **Trois périmètres** : global (plateforme), espace (VOC, CERT…), organisation cliente.
- **Rôles = paquets de permissions**. Le code vérifie toujours des **permissions**, jamais des noms de rôle, ce qui permet de faire évoluer les rôles sans toucher au code.
- **Séparation des tâches** : le rôle admin plateforme seul ne donne **pas** accès aux données métier d'un espace. Un admin qui doit qualifier des vulnérabilités VOC doit aussi être membre de l'espace VOC.
- **Admin = analystes VOC** (décision Q1) : l'espace VOC porte `grants_platform_admin = true` ; toute appartenance `analyst` à cet espace donne aussi les permissions `platform_admin`. Le rôle `platform_admin` peut en plus être attribué nominativement (compte de secours).
- Un compte est soit **interne**, soit **client** (`user_type`), jamais les deux. Un compte client ne peut pas se connecter au back-office, et inversement.

## 2. Rôles

| Rôle | Périmètre | Description |
|---|---|---|
| `platform_admin` | Global | Utilisateurs internes, rôles, espaces, organisations clientes, paramètres de sécurité, audit global, catalogue des technos (suppression et fusion), connecteurs globaux (NVD, KEV, EPSS), moteur IA préféré de la plateforme |
| `analyst` | Espace | Toutes les capacités métier de l'espace : vulnérabilités (y compris non qualifiées), périmètre de veille, workflows, agents et moteurs IA de l'espace, connecteurs de veille et de publication, modèles, bulletins, configuration de l'espace |
| `viewer` (optionnel, plus tard) | Espace | Lecture seule de l'espace (stagiaires, auditeurs) |
| `client_user` | Organisation cliente | Lecture des bulletins publiés destinés à l'organisation ; plus tard, abonnements et demandes de technos |
| `client_admin` (MVP) | Organisation cliente | Référent : invite et gère les utilisateurs de son organisation, plus tard ses abonnements |

Correspondance avec les profils exprimés :

| Profil exprimé | Attribution |
|---|---|
| Analyste VOC | `analyst` sur l'espace `voc`, qui donne automatiquement `platform_admin` |
| Rôle CERT | `analyst` sur l'espace `cert`, sans `platform_admin` |
| Client | `client_user` sur son organisation ; le référent a `client_admin` |

## 3. Catalogue des permissions

| Code | Périmètre | Objet |
|---|---|---|
| `iam.users.manage` | Global | Créer, inviter, désactiver des comptes internes, réinitialiser leur MFA |
| `iam.roles.manage` | Global | Attribuer des rôles et des appartenances aux espaces |
| `iam.workspaces.manage` | Global | Créer et configurer les espaces |
| `iam.clients.manage` | Global | Organisations clientes et comptes clients |
| `security.settings.manage` | Global | Politique de mots de passe, durées de session, IP autorisées… |
| `audit.read_global` | Global | Journal d'audit complet |
| `technology.manage` | Global | Créer et éditer les technos du catalogue |
| `technology.merge_delete` | Global | Fusionner et supprimer des technos |
| `technology_request.review` | Global | Traiter les demandes de technos des clients |
| `connector.global.manage` | Global | Connecteurs globaux : NVD (clé, intervalle de synchronisation, rattrapage), KEV, EPSS, CVE.org, OSV, moteurs IA de plateforme |
| `ai.default_engine.manage` | Global | Moteur IA préféré de la plateforme (bascule soumise au banc d'évaluation) |
| `workspace.settings.manage` | Espace | Configuration de l'espace (double validation, budgets, politique LLM) |
| `workspace.audit.read` | Espace | Audit restreint à l'espace |
| `watch_scope.manage` | Espace | Périmètre de veille de l'espace (quelles nouvelles CVE NVD déclenchent une investigation) |
| `connector.source.manage` | Espace | Connecteurs de veille de l'espace (GitHub, X, Stack Exchange, réseaux, RSS, web…) |
| `source.manage` | Espace | Sources de veille de l'espace |
| `secret.manage` | Espace | Créer et remplacer les secrets de l'espace (écriture seule) |
| `vuln.read` | Interne | Lire les fiches vulnérabilités partagées (ADR-024), **y compris non qualifiées**, preuves et synthèses IA des deux équipes |
| `vuln.qualify` | Espace | Qualifier pour son équipe (évaluation de l'espace), reprendre la qualification de l'autre équipe, assigner, commenter |
| `workflow.read` | Espace | Lire workflows et exécutions |
| `workflow.edit` | Espace | Créer et modifier des workflows, publier une version |
| `workflow.run` | Espace | Lancer ou annuler une exécution, approuver une étape |
| `ai.engine.manage` | Espace | Moteurs IA propres à l'espace et moteur préféré de l'espace |
| `ai.agent.manage` | Espace | Agents IA de l'espace (paramétrage complet) |
| `ai.agent.run` | Espace | Tester ou lancer un agent |
| `ai.evaluation.run` | Espace | Lancer le banc d'évaluation des moteurs (coûteux) |
| `template.manage` | Espace | Modèles de bulletins |
| `bulletin.draft` | Espace | Demander un draft, éditer un bulletin |
| `bulletin.review` | Espace | Relire et approuver (jamais son propre bulletin si la double validation est active) |
| `bulletin.publish` | Espace | Publier ou retirer un bulletin du portail |
| `connector.publish.manage` | Espace | Créer et modifier des connecteurs de publication |
| `connector.publish.push` | Espace | Pousser un bulletin approuvé via un connecteur de publication |
| `connector.allow_private_network` | Global | Autoriser un connecteur à joindre une adresse privée (admin uniquement) |
| `platform.branding.manage` | Global | Nom de l'émetteur et logo du portail et des PDF clients (Q46) |
| `portal.bulletins.read` | Organisation | Bulletins publiés destinés à l'organisation |
| `portal.subscriptions.manage` | Organisation | Abonnements aux technos (phase 9) |
| `portal.technology_request.create` | Organisation | Demander une techno absente (phase 9) |
| `portal.org_users.manage` | Organisation | Inviter, désactiver et gérer les comptes de son organisation (`client_admin`, MVP) |

## 4. Matrice

✅ = accordé. « Espace » = uniquement dans l'espace dont l'utilisateur est membre.

| Permission | platform_admin | analyst (VOC ou CERT) | client_user |
|---|:-:|:-:|:-:|
| `iam.*`, `security.settings.manage`, `audit.read_global` | ✅ | | |
| `technology.manage` | ✅ | ✅ | |
| `technology.merge_delete` | ✅ | | |
| `technology_request.review` | ✅ | ✅ (espaces désignés, par défaut VOC) | |
| `connector.allow_private_network` | ✅ | | |
| `platform.branding.manage` | ✅ | | |
| `connector.global.manage`, `ai.default_engine.manage` | ✅ | | |
| `workspace.settings.manage`, `workspace.audit.read` | | ✅ espace | |
| `watch_scope.manage`, `connector.source.manage`, `source.manage`, `secret.manage` | | ✅ espace | |
| `vuln.read`, `vuln.qualify` | | ✅ espace | |
| `workflow.read`, `workflow.edit`, `workflow.run` | | ✅ espace | |
| `ai.engine.manage`, `ai.agent.manage`, `ai.agent.run`, `ai.evaluation.run` | | ✅ espace | |
| `template.manage`, `bulletin.draft`, `bulletin.review`, `bulletin.publish` | | ✅ espace | |
| `connector.publish.manage`, `connector.publish.push` | | ✅ espace | |
| `portal.bulletins.read` | | | ✅ organisation |
| `portal.subscriptions.manage`, `portal.technology_request.create` | | | ✅ organisation (phase 9) |
| `portal.org_users.manage` | | | ✅ `client_admin` uniquement |

Conséquences :

- L'analyste CERT a exactement les mêmes capacités que l'analyste VOC, limitées à l'espace CERT. Il gère ses agents IA, ses connecteurs de veille, son périmètre de veille, son moteur IA préféré et sa configuration, mais n'a aucune permission globale.
- Le connecteur NVD est global (une seule clé et une seule synchronisation pour l'organisation, comme le recommande NVD) : seul un admin le configure. Chaque espace décide ensuite, par son périmètre de veille et ses workflows, ce qu'il fait des nouvelles CVE.
- Les agents, workflows, modèles, connecteurs, secrets, périmètres de veille, sources, commentaires et bulletins non publiés du CERT sont invisibles depuis l'espace VOC, et inversement. Les évaluations sont lisibles par l'autre équipe mais modifiables seulement par la sienne. Les **fiches vulnérabilités, preuves et synthèses IA sont partagées** ; les bulletins publiés sont lisibles par l'autre équipe (ADR-024).

## 5. Implémentation

- `app/iam/permissions.py` : énumération `Permission` et table `ROLE_PERMISSIONS`, définies dans le code et versionnées (pas en base, pour éviter l'escalade par modification de données).
- Dépendance FastAPI : `require(Permission.VULN_READ, scope=WorkspaceFromPath)`. Elle résout l'espace depuis le chemin (`/api/v1/workspaces/{ws}/…`), vérifie l'appartenance et ouvre la transaction avec la RLS positionnée.
- Chaque route déclare sa permission par la dépendance. Le test `tests/security/test_route_permissions.py` parcourt toutes les routes des deux applications et échoue si une route n'a pas de permission, à part une liste blanche explicite (login, healthz…).
- Tests de matrice générés : pour chaque route et chaque profil (anonyme, client A, client B, analyste VOC, analyste CERT, admin seul), on vérifie le code attendu (401, 403, 404 ou 2xx). Une ressource d'un autre périmètre renvoie **404**, pas 403, pour ne pas révéler son existence.
- Les actions sensibles exigent une ré-authentification MFA récente (moins de 10 minutes) : changement de rôle, gestion des secrets et connecteurs, autorisation du réseau privé, publication vers les clients.

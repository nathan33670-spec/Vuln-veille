# Spec 06 — Portail client, abonnements et demandes de technos

## 1. Principes

- Application **séparée** (ASGI et SPA), exposée sur Internet ; le back-office n'y existe pas.
- Un client ne voit que les **bulletins publiés** destinés à son organisation, filtrés par l'audience et le TLP. Il ne voit jamais les vulnérabilités, preuves, synthèses IA, sources, workflows, auteurs internes ni commentaires.
- Comptes créés **uniquement sur invitation** (pas d'inscription libre) : les admins plateforme créent l'organisation et son référent `client_admin`, qui invite ensuite ses utilisateurs (Q15).
- MFA **facultative** pour les clients (Q16), proposée à chaque connexion tant qu'elle n'est pas activée ; une organisation peut l'imposer.
- L'équipe émettrice (VOC ou CERT) est affichée sur chaque bulletin (Q3).
- Lecture via le rôle PostgreSQL `vv_portal`, limité à la vue `portal_bulletins_v` et aux tables du portail de son organisation (RLS).

## 2. MVP (phase 8)

| Écran | Contenu |
|---|---|
| Connexion | E-mail, mot de passe, MFA (selon Q16), mot de passe oublié |
| Bulletins | Liste paginée : référence, titre, sévérité, TLP, technos, date de publication et de mise à jour |
| Recherche et filtres | Texte intégral (titre et contenu), sévérité, techno, période |
| Détail | HTML assaini, CVE, technos, historique des mises à jour, export Markdown ou HTML, impression |
| Mon compte | Mot de passe, MFA, sessions actives |
| Mon organisation (`client_admin`) | Inviter, désactiver, renvoyer une invitation ; liste des utilisateurs |
| Réception par e-mail | Chaque utilisateur choisit de recevoir les bulletins par e-mail (HTML assaini + PDF joint) |

API : `/api/portal/v1/bulletins`, `/api/portal/v1/bulletins/{id}`, `/api/portal/v1/me`. Les schémas de sortie sont des listes blanches.

## 3. Abonnements aux technos (phase 9, « à venir »)

- Un client (ou son organisation) s'abonne à des technos du catalogue global, avec une sévérité minimale et des canaux (e-mail d'abord).
- Le portail propose alors une vue « Mes technos » (les bulletins concernant ses abonnements en premier) et des notifications filtrées.
- Le rattachement bulletin ↔ techno vient de `bulletin_technologies`, renseigné par l'analyste ou proposé automatiquement à partir des technos de la vulnérabilité (CPE, purl, IA).
- **Confidentialité** : les abonnements révèlent le parc du client. Ils ne sont visibles que de son organisation et, côté interne, des rôles qui en ont besoin (statistiques agrégées pour les analystes, détail pour les admins). Ils ne sont jamais envoyés à un LLM.

Le modèle de données (`technologies`, `subscriptions`) est créé dès la phase 2, pour que cette fonctionnalité se branche sans migration lourde.

## 4. Demande d'une techno absente (phase 9)

Parcours client :

1. Le client cherche une techno ; la recherche est approchée (trigrammes, alias, CPE) pour éviter les doublons (« Vouliez-vous dire… ? »).
2. Rien ne convient : il ouvre le formulaire « Demander l'ajout » avec éditeur, produit, URL optionnelle et justification optionnelle (longueurs bornées, texte brut).
3. La demande est enregistrée (`technology_requests`, `pending`), avec une limite de 10 demandes en attente par organisation et un débit borné.
4. Le client suit le statut de ses demandes.

Parcours interne (`technology_request.review`) :

- File des demandes, avec suggestion de technos proches et de correspondances CPE (dictionnaire NVD).
- **Approuver** : création de la techno (ou rattachement à une techno existante si c'est un doublon), abonnement automatique du demandeur, notification.
- **Rejeter** : motif obligatoire, visible du client.
- **Fusionner** : marquer comme doublon d'une techno existante et abonner le demandeur.
- Toutes ces décisions sont auditées.

## 5. Sécurité spécifique au portail

- Exposé sur Internet : limitation de débit stricte, WAF optionnel devant Caddy, aucune page d'erreur détaillée.
- Les cookies et sessions du portail ne sont pas acceptés par le back-office, et inversement.
- Isolation entre organisations : RLS sur `client_org_id`, plus des tests de non-fuite (client A ne voit ni les bulletins ciblés vers B, ni les abonnements, ni les demandes de B).
- Le contenu des bulletins est servi déjà assaini ; la CSP interdit les scripts inline et les ressources externes.
- Les ressources ont des identifiants UUID ; toute ressource hors périmètre renvoie 404.

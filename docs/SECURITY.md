# SECURITY — Modèle de menace et mesures

Référentiels : OWASP ASVS 5.0 (niveau 2, niveau 3 visé pour l'authentification, les sessions et la cryptographie), OWASP Top 10, OWASP API Security Top 10, OWASP Top 10 for LLM Applications 2025, recommandations ANSSI (authentification multifacteur et mots de passe, sécurité des systèmes d'IA générative).

## 1. Actifs à protéger

| Actif | Pourquoi c'est critique |
|---|---|
| Vulnérabilités non qualifiées et bulletins non publiés | Informations sous embargo ou TLP:AMBER/RED ; une fuite aide un attaquant |
| **Intégrité des bulletins publiés** | Un bulletin altéré (fausse mitigation, lien piégé) envoyé à tous les clients aurait un impact majeur |
| Liste des clients, abonnements et demandes de technos | Révèle le parc technologique des clients, donc leur surface d'attaque |
| Secrets : clés des moteurs IA, NVD, GitHub, Stack Exchange, Bluesky, connecteurs de publication, webhooks | Usage frauduleux, rebond vers des systèmes tiers |
| Comptes, sessions, MFA | Point d'entrée de toutes les autres attaques |
| Définitions de workflows, d'agents et de connecteurs | Leur modification permet d'exfiltrer ou d'injecter des données |
| Disponibilité et budget | Déni de service, explosion des coûts LLM ou API |

## 2. Acteurs de menace

1. Attaquant externe non authentifié (portail exposé sur Internet).
2. Compte client malveillant ou compromis (accès à d'autres clients, élévation).
3. Compte interne compromis (vol de session, hameçonnage) ou initié malveillant.
4. **Contenu collecté piégé** : injection de prompt indirecte, XSS, SSRF par redirection, bombes de décompression, XML malveillant. C'est le vecteur spécifique de cette application : on lit volontairement du contenu écrit par des attaquants (PoC, posts, issues).
5. Serveur distant malveillant (réponses de connecteurs ou de sources).
6. Chaîne d'approvisionnement (dépendances, images, actions CI).

## 3. Scénarios principaux (STRIDE) et mesures

| # | Scénario | Mesures |
|---|---|---|
| S1 | Usurpation de compte par bourrage d'identifiants ou force brute | Argon2id, MFA obligatoire en interne, limitation par compte et par IP, verrouillage progressif, refus des mots de passe compromis, messages génériques |
| S2 | Vol de session (XSS, réseau) | Cookie `__Host-` `HttpOnly` `Secure` `SameSite=Strict`, CSP stricte avec Trusted Types, HSTS, rotation de l'identifiant, expirations, liste et révocation des sessions |
| S3 | CSRF | SameSite=Strict, jeton CSRF lié à la session dans un en-tête, vérification de l'`Origin` sur les méthodes non sûres, aucune action d'état en GET |
| S4 | IDOR ou fuite entre espaces ou clients | Repositories à périmètre obligatoire, RLS PostgreSQL, rôle `vv_portal` restreint, 404 hors périmètre, matrice de tests d'autorisation |
| S5 | Élévation de privilèges | Rôles définis dans le code, step-up MFA, audit des changements de rôle, aucun mass-assignment (schémas d'entrée explicites) |
| S6 | Injection SQL ou de commande | ORM et requêtes paramétrées uniquement ; aucun appel shell avec des données utilisateur |
| S7 | SSTI ou exécution de code via gabarits ou expressions | Liquid (pas Jinja2), JMESPath (pas d'`eval`), pas de nœud « Code », sorties LLM jamais traitées comme gabarit, limites de rendu (boucles, taille) |
| S8 | XSS stockée via contenu collecté, sortie LLM ou bulletin | React échappe par défaut ; Markdown rendu côté serveur sans HTML brut puis nh3 ; DOMPurify côté client ; CSP ; schémas d'URL limités à `http(s)` et `mailto` dans les liens |
| S9 | SSRF via sources, outil `web_fetch` d'un agent ou connecteur | `SafeHttpClient`, proxy smokescreen, isolation réseau des workers, réseau privé seulement sur autorisation admin et par connecteur |
| S10 | Injection de prompt indirecte (contenu collecté) | Agents sans outils à effet de bord, contenu non fiable isolé et balisé, sorties validées par schéma, citations obligatoires, validation humaine avant toute publication, listes de domaines par agent |
| S11 | Exfiltration via un agent (contenu piégé qui pousse l'agent à envoyer des données dans une URL) | `web_fetch` limité aux domaines autorisés de l'agent, aucun secret ni donnée client dans le contexte LLM, journal des appels d'outils |
| S12 | Altération d'un bulletin avant diffusion | Révisions immuables, double validation configurable, audit, ré-authentification pour publier, empreinte de la révision publiée |
| S13 | Webhook entrant forgé ou rejoué | HMAC-SHA256 sur horodatage et corps, tolérance de 5 minutes, cache anti-rejeu, limite de taille et de débit |
| S14 | DoS ou explosion des coûts | Limitation de débit par IP et par utilisateur, quotas de workflows, budgets LLM avec arrêt dur, limites de taille et de durée, timeouts partout |
| S15 | Bombes XML ou de décompression, fichiers géants | defusedxml, plafonds de taille décompressée, lecture en streaming avec coupure |
| S16 | Fuite de secrets (le **dépôt est public**) | Chiffrement d'enveloppe, API en écriture seule, filtre de redaction des logs, gitleaks en pre-commit et en CI (bloquant), aucun secret dans les images, aucune donnée interne (noms de clients, IP, comptes) dans le dépôt |
| S17 | Répudiation | Journal d'audit append-only chaîné par hachage, horodatage serveur, identifiant de requête |
| S18 | Dépendance compromise | Lockfiles avec hachages, Renovate, pip-audit et osv-scanner, pnpm audit, SBOM CycloneDX, Trivy, actions CI épinglées par SHA |
| S19 | Compromission d'un conteneur | Non-root, FS en lecture seule, `no-new-privileges`, capacités supprimées, réseaux séparés, secrets limités à chaque worker, rôles DB distincts |
| S20 | Énumération de comptes ou d'objets | Réponses identiques et temps constant au login et à la réinitialisation, UUID, 404 hors périmètre |
| S21 | Faux PoC piégés (dépôt GitHub contenant un malware qui cible les chercheurs) | Aucun code récupéré n'est exécuté ; `github_get` ne renvoie que du texte borné, ni binaire ni archive ; l'agent PoC signale les indices de piège ; l'interface avertit avant d'ouvrir un lien de PoC (`rel="noopener noreferrer"`) |
| S22 | Moteur IA auto-hébergé exposé ou compromis | TLS et jeton, réseau privé, exception réseau autorisée par un admin et auditée, jamais exposé sur Internet, modèles en `safetensors` d'une source vérifiée (empreinte) |
| S23 | Inondation d'événements NVD (rattrapage, pic de publications, CVE en masse) | Rattrapage sans événements, périmètre de veille en amont des agents, débit de diffusion borné par espace, budget par CVE et par mois |
| S24 | Données sensibles envoyées au mauvais moteur IA | Politique de données par moteur (localisation, classes autorisées) vérifiée par le constructeur de contexte avant chaque appel ; abonnements clients jamais envoyés à un LLM |
| S25 | Dérive de coût sur la facture IA (boucle d'agent, recherches web en masse) ou introduction involontaire d'un service payant | Budgets mensuels et plafonds par exécution et par CVE, sous-budget pour la recherche web, arrêt dur, alertes ; classe de coût obligatoire par type de connecteur et test bloquant contre les types payants (ADR-023) |
| S26 | Contenu X falsifié ou trompeur (faux compte, post supprimé, HTML oEmbed piégé) | HTML oEmbed réduit à du texte puis assaini, aucun script exécuté, post marqué non fiable, auteur et URL affichés, post supprimé marqué « retiré », recoupement par l'agent de synthèse |

## 4. Mesures détaillées

### 4.1 Authentification

- Argon2id (argon2-cffi), au moins m=64 Mio, t=3, p=4, paramètres recalibrés sur le serveur cible ; rehachage transparent si les paramètres changent.
- Mots de passe : 12 caractères minimum, pas de règle de composition imposée (NIST 800-63B, ANSSI), refus des mots de passe présents dans une liste de mots de passe compromis embarquée.
- MFA : TOTP (RFC 6238) obligatoire pour tous les comptes internes, avec anti-rejeu (dernier pas utilisé mémorisé) et 10 codes de secours hachés à usage unique. WebAuthn/passkeys en phase 10. MFA client : facultative (Q16), proposée à chaque connexion, imposable par organisation.
- Invitations et réinitialisations : jeton aléatoire de 256 bits stocké haché, usage unique, expiration de 24 h (invitation) ou 30 min (réinitialisation), invalidation des sessions à la réinitialisation.
- Limitation : 5 tentatives par minute par compte, 20 par IP, puis délais exponentiels ; verrouillage temporaire et notification à l'utilisateur.
- Pas de compte par défaut : le premier admin est créé en CLI (`app.cli bootstrap-admin`) avec MFA à enrôler à la première connexion.
- SSO OIDC (phase 10) : PKCE, validation stricte de l'`iss`, de l'`aud` et du `nonce`, correspondance explicite des groupes vers les rôles.

### 4.2 Sessions

- Identifiant opaque de 256 bits ; seul son hachage SHA-256 est stocké (table `sessions`, cache Redis).
- Cookie `__Host-vv_bo` (back-office) et `__Host-vv_portal` (portail) : `Secure; HttpOnly; SameSite=Strict; Path=/`.
- Back-office : 30 min d'inactivité, 12 h au maximum. Portail : 2 h d'inactivité, 7 jours au maximum (à confirmer).
- Rotation à la connexion, à la validation MFA et au changement de privilèges. Révocation de toutes les sessions au changement de mot de passe ou de MFA.
- Audience : une session émise par le portail est refusée par le back-office, et inversement.

### 4.3 Autorisation

Voir RBAC.md. Refus par défaut, permissions déclarées par route et vérifiées par test, RLS en seconde barrière, 404 hors périmètre.

### 4.4 Entrées et sorties

- Pydantic strict, `extra="forbid"`, longueurs bornées sur toutes les chaînes, taille de requête maximale (1 Mio par défaut).
- Schémas de sortie dédiés ; les schémas du portail sont des listes blanches de champs.
- Erreurs RFC 9457 sans trace de pile ni détail interne.

### 4.5 En-têtes HTTP (Caddy et middleware, en double)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self';
  frame-ancestors 'none'; require-trusted-types-for 'script'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store            (réponses d'API authentifiées)
```

Pas de CORS : les SPA et les API partagent la même origine. Les images externes dans les bulletins ne sont pas chargées (le lien est affiché à la place), ce qui évite le pistage et les fuites de référent.

### 4.6 SafeHttpClient (toute requête sortante)

1. Schémas autorisés : `https` (et `http` seulement pour les sources explicitement marquées) ; ports 443/80 sauf configuration.
2. Résolution DNS par le client, puis refus si **une** des adresses est loopback, privée (RFC 1918), lien-local (169.254.0.0/16, y compris les métadonnées cloud), CGNAT (100.64.0.0/10), multicast, réservée, `0.0.0.0/8`, IPv6 `::1`, `fc00::/7`, `fe80::/10`, IPv4 mappée en IPv6.
3. Connexion à l'IP validée (épinglage) avec SNI et `Host` d'origine : protège du DNS rebinding.
4. Redirections suivies manuellement (5 au maximum), chacune revalidée.
5. Plafonds : 10 Mio par défaut, taille décompressée bornée, timeouts de connexion et de lecture, types de contenu attendus.
6. Passage par le proxy smokescreen (seconde barrière réseau) ; exception pour le réseau privé uniquement par connecteur autorisé par un admin, avec une liste d'IP ou de CIDR explicite.
7. TLS toujours vérifié ; un bundle d'AC personnalisé est possible par connecteur.

### 4.7 Secrets et cryptographie

- Chiffrement d'enveloppe : une clé de données AES-256-GCM par secret, enveloppée pour la **clé publique X25519 de son usage** (`llm`, `source`, `connector`, `webhook` ; ECDH éphémère, HKDF-SHA256, AES-256-GCM). Données associées (AAD) : usage, `secret_id`, `workspace_id` et identifiant de clé.
- L'API ne détient que les clés publiques : elle écrit les secrets sans pouvoir les lire. Les trousseaux privés sont des secrets Docker montés uniquement dans le worker de leur usage. Les secrets TOTP ont leur propre clé symétrique (`VV_KEK_TOTP`).
- RLS : un administrateur VOC ne voit jamais les secrets du CERT ; les workers ne créent ni ne suppriment de secret.
- Rotation : `scripts/vault-keygen.sh` puis `vault-rotate` (ré-enveloppement des clés de données) ; `kek_id` stocké avec chaque secret (PROCEDURES §9).
- API en écriture seule : seuls l'indice (4 derniers caractères) et la date de mise à jour sont renvoyés.
- Aléa : module `secrets` uniquement. Comparaisons en temps constant (`hmac.compare_digest`).

### 4.8 Sécurité de l'IA (OWASP LLM Top 10)

| Risque | Mesure |
|---|---|
| LLM01 Injection de prompt | Contenu collecté passé comme document balisé avec sa provenance, consigne système explicite (ces blocs sont des données), mélange par messages système en cours de conversation pour les consignes opérateur, détection heuristique d'injection signalée à l'analyste sans blocage silencieux |
| LLM02 Divulgation d'informations sensibles | Aucune donnée client, aucun secret ni aucune donnée TLP:RED envoyés au LLM sans politique l'autorisant ; chaque moteur IA déclare sa localisation (cloud externe ou auto-hébergé) et les classes de données qu'il peut recevoir, ce qui est vérifié avant chaque appel |
| LLM05 Traitement non sûr des sorties | Sorties structurées validées par Pydantic ; Markdown assaini ; liens vérifiés (schéma, domaine affiché) ; jamais exécutées ni rendues comme gabarit |
| LLM06 Agentivité excessive | Outils en lecture seule ; les écritures en base sont faites par des nœuds déterministes après validation ; publication uniquement par un humain |
| LLM09 Désinformation | Citations obligatoires vers les preuves, niveau de confiance, relecture humaine, mention « généré par IA » dans l'interface interne |
| LLM10 Consommation non bornée | Limites de tours, de tokens et d'appels d'outils, timeouts, budgets mensuels avec arrêt dur, quotas par utilisateur |

Les sujets de vulnérabilités et d'exploits peuvent déclencher les classifieurs de sécurité du fournisseur (stop reason `refusal`, catégorie `cyber`). Le runtime les gère sans planter : fallback serveur activé, statut explicite, possibilité de relancer, journalisation.

Ces mesures sont indépendantes du moteur : le corpus de tests d'injection tourne avec l'adaptateur Claude et l'adaptateur compatible OpenAI, et un changement de moteur préféré exige de repasser le banc d'évaluation.

### 4.9 Journal d'audit

- Table `audit_events` append-only : le rôle applicatif n'a ni `UPDATE` ni `DELETE`. Chaque ligne contient `hash = SHA-256(prev_hash || ligne canonique)`, et une CLI vérifie la chaîne.
- Événements : connexions (succès et échec), MFA, sessions, changements de rôle et d'appartenance, création et modification de secrets et de connecteurs, publication de workflows, qualification, publication et retrait de bulletins, poussées API, autorisations de réseau privé, exports, décisions sur les demandes de technos.
- Export JSON et syslog vers un SIEM (phase 10).

### 4.10 Infrastructure

- Back-office accessible uniquement depuis le réseau interne ou VPN (liste d'IP ou ZTNA au niveau de Caddy) ; portail public.
- Réseaux Docker : `edge` (Caddy et API), `data` (API, workers et bases), `egress` (workers et smokescreen). PostgreSQL et Redis ne sont jamais exposés.
- Conteneurs : utilisateur non-root, `read_only: true`, `tmpfs` pour `/tmp`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, limites CPU et mémoire, healthchecks.
- PostgreSQL : TLS, rôles `vv_migrator` (DDL), `vv_app` (DML sous RLS), `vv_worker`, `vv_portal` (lecture de la vue portail), aucun superutilisateur applicatif ; sauvegardes chiffrées et restauration testée.
- Redis : mot de passe et ACL, pas d'exposition, `protected-mode`.

### 4.11 Tests de sécurité

- Unitaires : hachage, TOTP, CSRF, SafeHttpClient (suite d'adresses et de redirections piégées), rendu Liquid (gabarits malveillants), assainissement Markdown (charges XSS), signature des webhooks.
- Autorisation : route sans permission (test bloquant), matrice profils × routes, non-fuite du portail.
- IA : corpus de contenus piégés (injections directes et indirectes, tentatives d'exfiltration par URL, faux appels d'outils) ; on vérifie qu'aucune action non prévue n'est déclenchée.
- CI : Semgrep, Bandit, ruff (règles `S`), pip-audit, pnpm audit, gitleaks, Trivy (images et configuration), ZAP baseline et schemathesis (phase 10).
- Avant ouverture sur Internet : revue de code de sécurité et test d'intrusion externe.

## 5. Checklist de sécurité par changement

À relire avant chaque commit qui touche une route, un modèle, un nœud, un agent ou un connecteur :

- [ ] La route déclare une permission et son périmètre ; les tests de matrice sont à jour.
- [ ] Les requêtes passent par un repository à périmètre ; la RLS couvre la nouvelle table.
- [ ] Les entrées sont validées par un schéma strict avec des longueurs bornées ; les sorties passent par un schéma dédié.
- [ ] Aucun appel HTTP sortant hors `SafeHttpClient`.
- [ ] Aucun `eval`, aucun `exec`, aucun `subprocess` avec des données externes, aucun rendu de gabarit sur une donnée non fiable.
- [ ] Le contenu externe et les sorties LLM sont traités comme non fiables (assainissement, validation).
- [ ] Les secrets ne sont ni loggés, ni renvoyés, ni commités.
- [ ] Les actions sensibles sont auditées et exigent un step-up MFA si nécessaire.
- [ ] Les limites (taille, nombre, durée, débit) sont définies.
- [ ] Les dépendances ajoutées sont justifiées, maintenues et épinglées.

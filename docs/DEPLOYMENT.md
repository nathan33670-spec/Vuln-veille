# DEPLOYMENT — Mettre Vuln-Veille en service

Déploiement sur **un seul hôte** avec Docker Compose (ADR-017). La pile est décrite dans `deploy/docker-compose.yml`, et toutes les commandes partent de la racine du dépôt.

## 1. Prérequis

- Un serveur Linux (4 vCPU et 8 Go de RAM conseillés), avec Docker Engine ≥ 24 et le plugin Compose v2, `make` et `git`.
- **Deux noms DNS** pointant vers ce serveur, par exemple `vv-admin.exemple.fr` pour le back-office et `veille.exemple.fr` pour le portail client.
- Les ports 80 et 443 ouverts en entrée. Le port 80 sert au défi ACME et à la redirection vers HTTPS.
- En sortie :
  - HTTPS vers les services de veille et d'IA, la liste étant tenue dans `deploy/smokescreen/acl.yaml` ;
  - accès au relais SMTP.
- Un **relais SMTP** pour les invitations, les réinitialisations de mot de passe et les bulletins envoyés aux clients.
- Une clé API **Gemini** (palier gratuit, ADR-025) pour le moteur IA. Une clé **NVD** est facultative, mais elle est recommandée.

## 2. Récupérer le code

```sh
git clone https://github.com/nathan33670-spec/Vuln-veille.git
cd Vuln-veille
git checkout Main
```

## 3. Générer la configuration et les secrets

```sh
make env
```

Cette commande crée `.env` (mode 600) avec des mots de passe et des clés aléatoires, ainsi que les quatre trousseaux du coffre dans `secrets/keyrings/`. Elle refuse d'écraser un `.env` ou des trousseaux existants.

Éditer ensuite `.env` :

| Variable | Valeur en production |
|---|---|
| `VV_ENVIRONMENT` | `prod` (interdit le hachage faible des mots de passe) |
| `VV_BACKOFFICE_HOST`, `VV_PORTAL_HOST` | les deux noms DNS, par exemple `vv-admin.exemple.fr` et `veille.exemple.fr` |
| `VV_BACKOFFICE_ORIGIN`, `VV_PORTAL_ORIGIN` | `https://` + chacun de ces noms : ils servent au contrôle CSRF et aux liens des e-mails |
| `VV_TLS` | une adresse e-mail pour obtenir des certificats Let's Encrypt, ou `/certs/cert.pem /certs/key.pem` pour des certificats internes (à monter dans le conteneur `caddy`) ; `internal` est réservé aux essais |
| `VV_BACKOFFICE_ALLOWED_CIDRS` | les réseaux autorisés à joindre le back-office (VPN, réseau interne), par exemple `10.0.0.0/8 192.168.10.0/24` ; le portail reste public |
| `VV_SMTP_HOST`, `VV_SMTP_PORT`, `VV_SMTP_STARTTLS`, `VV_SMTP_USERNAME`, `VV_SMTP_PASSWORD`, `VV_SMTP_FROM` | le relais SMTP (en production, `STARTTLS=true`) |

Ne jamais commiter `.env` ni `secrets/`.

**Sauvegarder tout de suite `.env` et `secrets/` ensemble, hors ligne.** Sans eux, les secrets enregistrés dans le coffre (clés d'API, jetons de connecteurs) et les seconds facteurs des utilisateurs sont perdus.

## 4. Construire et démarrer

```sh
make up        # docker compose up -d --build : images, migrations, puis services
make logs      # suivre le démarrage (Ctrl-C pour quitter)
```

Le service `migrate` s'exécute une fois avant les autres. Il crée les rôles PostgreSQL (`vv_migrator`, `vv_app`, `vv_worker`, `vv_portal`), applique les migrations Alembic, puis crée les workflows livrés, **désactivés**, dans chaque espace.

Vérifier ensuite :

```sh
docker compose -f deploy/docker-compose.yml --env-file .env ps   # tout « healthy » ou « running », migrate « exited (0) »
VV_BACKOFFICE_HOST=vv-admin.exemple.fr VV_PORTAL_HOST=veille.exemple.fr ./scripts/smoke-test.sh
```

Le test de fumée vérifie :
- le TLS et les deux API ;
- les en-têtes de sécurité ;
- l'absence de l'API du back-office sur le nom du portail.

## 5. Premier administrateur

```sh
docker compose -f deploy/docker-compose.yml --env-file .env run --rm api-backoffice \
  python -m app.cli bootstrap-admin --email admin@exemple.fr --name "Prénom Nom"
```

La commande affiche **une seule fois** un lien d'invitation, valable 24 h. Ce lien permet de choisir un mot de passe et d'enrôler le second facteur (TOTP). Une fois qu'un administrateur existe, la commande refuse de s'exécuter de nouveau ; les autres comptes se créent depuis le back-office.

## 6. Configuration depuis le back-office

Toutes ces étapes se font dans l'interface, et aucun identifiant ne va dans `.env` :

1. **Utilisateurs** : inviter les analystes VOC et CERT et leur attribuer un rôle par espace.
2. **Secrets globaux** : enregistrer la clé NVD (facultative) et la clé Gemini, que le coffre chiffre au repos.
3. **Connecteurs globaux** : activer le catalogue NVD, ainsi que KEV, EPSS et CVE.org selon les besoins.
4. **Moteurs IA** : créer le connecteur Gemini et le choisir comme moteur préféré de l'espace (ADR-011).
5. **Périmètre** et **Sources** de chaque espace : technos suivies, connecteurs de veille.
6. **Workflows** : relire puis **activer** le workflow « Nouvelle CVE NVD → investigation » et les autres workflows utiles.
7. **Modèles de bulletins** : vérifier le préfixe de référence et le modèle par défaut.
8. **Charte du portail** : nom de l'émetteur et logo, qui apparaissent sur le portail, dans les PDF et dans les e-mails.
9. **Clients** : créer les organisations clientes et inviter leur référent (`client_admin`), qui invitera ses collègues depuis le portail.
10. **Publication** (facultatif) : connecteurs vers des API partenaires. Une cible en réseau privé passe par la file d'approbation (« Réseau privé »).

## 7. Liste blanche de sortie (smokescreen)

Les workers ne sortent que par smokescreen, qui refuse tout domaine absent de `deploy/smokescreen/acl.yaml`. La liste livrée couvre :
- NVD, CISA, FIRST, OSV, CERT-FR ;
- les connecteurs de veille gratuits ;
- Gemini et Anthropic.

Pour un **connecteur de publication** vers un nouveau domaine, régénérer la liste à partir des connecteurs enregistrés, puis reconstruire smokescreen :

```sh
docker compose -f deploy/docker-compose.yml --env-file .env run --rm -T api-backoffice \
  sh -c 'python -m app.cli egress-acl --output /tmp/acl.yaml >&2 && cat /tmp/acl.yaml' \
  > deploy/smokescreen/acl.yaml.new
mv deploy/smokescreen/acl.yaml.new deploy/smokescreen/acl.yaml
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build smokescreen
```

Relire le diff de `acl.yaml` avant de reconstruire.

## 8. Exploitation

- **Mise à jour** :

  ```sh
  git pull
  make up
  ```

  `migrate` applique les nouvelles migrations avant le redémarrage des services. Sauvegarder la base avant toute mise à jour.
- **Sauvegarde de la base** (à chiffrer et à copier hors de l'hôte) :

  ```sh
  docker compose -f deploy/docker-compose.yml --env-file .env exec -T postgres \
    sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > vv-$(date +%F).dump
  ```

  Pour restaurer : `pg_restore --clean --if-exists` dans une base vide, puis `make migrate`.

  Tester régulièrement la restauration, toujours avec le `.env` et les `secrets/` correspondants.
- **Rotation d'une clé du coffre** : `docs/PROCEDURES.md` §9.
- **Journaux** : `make logs` ; les journaux sont tournés par Docker (5 × 20 Mo par service). Le journal d'audit se consulte dans le back-office.
- **Arrêt** : `make down` ; les volumes `pg_data`, `redis_data` et `caddy_data` sont conservés.

## 9. Points d'attention connus

- **Un seul hôte** : pas de haute disponibilité. Les sauvegardes et une restauration testée en tiennent lieu.
- **smokescreen** n'identifie pas encore chaque worker par un rôle mTLS : la liste blanche est commune à tous les workers.
- Les **tests navigateur** des critères de sortie (phases 5 à 8) ne tournent pas en CI, mais en local (`docs/PROCEDURES.md` §4).
- Les modèles par défaut des moteurs IA sont des valeurs de départ : vérifier dans AI Studio la liste des modèles du palier gratuit (Q35).

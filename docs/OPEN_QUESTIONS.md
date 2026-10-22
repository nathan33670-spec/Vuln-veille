# OPEN_QUESTIONS — Questions et décisions du porteur

Tant qu'une question n'a pas de réponse, le développement applique l'**hypothèse par défaut**, conçue pour être réversible. Quand une réponse arrive : la noter, dater, mettre à jour l'ADR et la spec concernés, et passer la ligne en « Répondue ».

Les questions de cadrage ont été posées en interactif le 2026-10-20 (session 5). **La colonne « Décision » fait foi.**

| # | Question | Décision (2026-10-20) | Impact |
|---|---|---|---|
| Q1 | Qui est admin plateforme ? | **Tous les analystes VOC** sont admins plateforme (attribution automatique par l'appartenance à l'espace VOC). Le CERT n'a pas l'admin. | RBAC §2, ADR-008 |
| Q2 | Que cloisonne-t-on entre VOC et CERT ? | **Vulnérabilités partagées** (fiche commune, preuves et synthèses IA visibles par les deux). Séparés : agents, workflows, modèles, connecteurs d'espace, configuration, périmètre de veille, bulletins non publiés. | ADR-024, specs 01 et 02, RBAC |
| Q2a | Qualification commune ? | **Chaque équipe qualifie pour elle-même.** Quand une équipe qualifie, l'autre voit « qualifiée par l'autre équipe » avec sa qualification, et un **bouton rapide « Reprendre cette qualification »** la recopie. | ADR-024, spec 01 §5 |
| Q2b | Synthèses IA et preuves partagées ? | **Visibles par les deux**, avec l'équipe d'origine indiquée. | ADR-024 |
| Q2c | Bulletins partagés ? | **Séparés** ; un bulletin **publié** est consultable en lecture par l'autre équipe. | spec 04 |
| Q3 | Qui publie vers le portail ? | **VOC et CERT**, émetteur affiché au client. | spec 06 |
| Q4 | Double validation ? | **Non** : un seul analyste peut publier (avec MFA récente). La double validation reste une option d'espace, désactivée par défaut. | spec 04 §4, ADR-019 |
| Q5 | Publication automatique ? | Non, jamais (ADR-019), non remis en cause. | — |
| Q6 | Données envoyées à un moteur IA cloud ? | Vers Claude : **tout sauf TLP:RED**. Vers un **palier gratuit** (Gemini) : données publiques et TLP:CLEAR uniquement, car le fournisseur peut réutiliser les données du palier gratuit. Jamais de données clients ni de secrets. | spec 07 §4.5 |
| Q7 | Budget IA ? | **0 €** : uniquement des paliers gratuits pour l'instant. Arrêt dur et alertes sur les quotas gratuits ; aucune facturation activée sur les comptes des fournisseurs. | ADR-025 |
| Q7a | Moteur IA au démarrage ? | L'abonnement Claude Pro **n'inclut pas l'API** et ne peut pas servir une application multi-utilisateur. Moteur de démarrage : **Gemini, palier gratuit (Google AI Studio)**. Plus tard : un **LLMaaS** (pas encore disponible, compatible OpenAI attendu), puis éventuellement Claude via l'API si un budget existe. | ADR-025, ADR-011 |
| Q8 | Authentification interne ? | **Comptes locaux + MFA TOTP obligatoire** ; SSO plus tard. | ADR-007 acceptée |
| Q9 | Hébergement ? | **Serveur on-premise, Docker Compose**, accès Internet **direct** (pas de proxy d'entreprise ; chaînage du proxy de sortie laissé configurable). | ADR-017 acceptée |
| Q10 | Langues des bulletins ? | **Français et anglais** dès le départ. | spec 04 |
| Q11 | Diffusion aux clients ? | **Portail + e-mail + export PDF**. | PLAN phase 8 |
| Q12 | Cibles de publication API ? | Inconnues à ce jour : connecteur HTTP générique. | spec 05 |
| Q13 | Volumétrie ? | **Moyenne** : 20 à 100 analystes, jusqu'à 1 000 utilisateurs clients. | PLAN §5 |
| Q14 | Workflows n8n existants ? | **Non.** | — |
| Q15 | Création des comptes clients ? | **Admin client délégué dès le MVP** : un référent par organisation invite et gère ses utilisateurs (rôle `client_admin`). Les admins plateforme créent les organisations et leurs référents. | RBAC, PLAN phase 8 |
| Q16 | MFA clients ? | **Facultative** (proposée, jamais imposée). | SECURITY §4.1 |
| Q17 | Rétention ? | **Longue** : tout est conservé au moins 3 ans (éléments collectés, traces IA, exécutions, audit). | spec 01 |
| Q18 | Criticité ? | **CVSS 4.0 et 3.1 + priorité interne P1 à P4.** | spec 01 |
| Q19 | Granularité des technos ? | **Éditeur + produit** (CPE, purl) ; versions plus tard. | spec 06 |
| Q20 | Notifications des analystes ? | **E-mail (SMTP), Teams (webhook entrant) et notifications dans l'application.** | spec 02 (nœuds `notify.*`) |
| Q21 | Nom et charte ? | **Vuln-Veille**, thème sobre clair et sombre. | — |
| Q22 | TLP sur le portail ? | **TLP:CLEAR et TLP:GREEN, plus TLP:AMBER pour les organisations explicitement ciblées** ; jamais RED. | spec 06 |
| Q23 | Quelles CVE lancent les agents ? | **Périmètre de veille filtré** par espace (technos suivies, éditeurs, CVSS ≥ 7 ou sans score, KEV toujours) ; les autres restent dans le catalogue. | spec 07 §3.4 |
| Q24 | Délai de détection ? | **Ajouter le connecteur CVE.org** (gratuit) pour détecter plus tôt ; NVD reste la référence d'enrichissement. | ADR-020, PLAN 2.4 bis |
| Q25 | LLM open source visé ? | Via un **LLMaaS**, pas encore disponible. | ADR-025 |
| Q26 | Qui bascule le moteur préféré ? | **Les admins, sans contrainte** : le banc d'évaluation est disponible mais facultatif. | spec 07 §4.4 et §4.6 |
| Q27 | Comptes gratuits disponibles ? | **Clé API NVD, jeton GitHub, clé Stack Exchange, compte Bluesky.** Pas de compte Mastodon (lecture publique seulement). | spec 07 §2 |
| Q28 | Recherche web IA pour X ? | Oui (via Q32) ; avec le moteur de démarrage Gemini, ce sera la **recherche Google intégrée à Gemini**, dans la limite du quota gratuit. | spec 07 §2.1 |
| Q29 | Dépôt et CI ? | **Dépôt public** : minutes GitHub Actions illimitées. Conséquence : **aucun secret, aucune donnée interne** ne doit jamais être commité (gitleaks bloquant). | SECURITY, PROCEDURES |
| Q30 | SearXNG ? | Sans objet. | — |
| Q31 | Reddit ? | **Flux RSS publics.** | spec 07 §2 |
| Q32 | Moteur de découverte des posts X ? | **(a) recherche web du moteur IA + (d) liens déjà collectés.** | spec 07 §2.1 |
| Q37 | Référence des bulletins ? | **Préfixe configurable par espace** (`bulletin_settings.ref_prefix`, par défaut le slug de l'espace), puis l'année et un compteur annuel : `CERT-AVI-2026-0007`. | spec 04 |
| Q38 | TLP par défaut d'un bulletin ? | **Défini par le modèle** (`tlp` de la spécification), AMBER si le modèle ne le précise pas ; modifiable sur le bulletin. | spec 04 |
| Q39 | Modèles livrés ? | **Générique FR (modèle par défaut) et EN, et « Vulnérabilité exploitée ou critique »** (KEV, exploitée dans la nature ou critique), désactivables. | spec 04 §1 |
| Q36 | Couche 2 de X (recherche web du moteur IA) activée par défaut ? | **Oui** (2026-10-22) ; l'espace peut la désactiver sur son connecteur `x_reader`. | ADR-028 |

## Questions encore ouvertes

| # | Question | Hypothèse par défaut |
|---|---|---|
| Q33 | Nom du LLMaaS prévu et date de disponibilité ? | Adaptateur compatible OpenAI prêt ; bascule par configuration |
| Q34 | Charte graphique pour les PDF clients (logo, couleurs) ? | Gabarit sobre, logo configurable |
| Q35 | Quotas exacts du palier gratuit Gemini (requêtes par minute et par jour, recherche Google intégrée) sur votre compte ? | Vérifiés dans AI Studio en phase 4 ; limiteur de débit configurable |

## Historique des consignes

| Date | Sujet | Consigne |
|---|---|---|
| 2026-10-20 | Vecteur d'entrée | « Le 1er vecteur d'entrée est la saisie d'une nouvelle vuln au NVD : c'est l'initiateur qui va lancer les agents pour faire des recherches dessus. » |
| 2026-10-20 | Connecteurs et agents | Ne pas oublier les connecteurs et le paramétrage des agents de veille. |
| 2026-10-20 | Moteur IA | « Notre moteur d'IA préféré : aujourd'hui Claude, demain un LLM open source. » Révisé le même jour : budget 0 €, démarrage sur le palier gratuit Gemini (Q7a). |
| 2026-10-20 | Coûts et X | « Le moteur de lecture sur X doit être gratuit. Aucun abonnement payant en plus de ceux utilisés par l'IA. » |
| 2026-10-20 | Recherche Google | « Utilise la recherche Google pour contourner la limitation de X et accéder seulement au strict nécessaire. » |
| 2026-10-20 | Découverte X | « OK pour a + d. » |
| 2026-10-20 | Phase 0 | « Lance la phase 0 en me posant toutes les questions en interactif. » |

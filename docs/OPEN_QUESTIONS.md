# OPEN_QUESTIONS — Questions ouvertes et hypothèses par défaut

Tant qu'une question n'a pas de réponse, le développement applique l'**hypothèse par défaut**, conçue pour être réversible. Quand une réponse arrive : la noter, dater, mettre à jour l'ADR et la spec concernés, et passer la ligne en « Répondue ».

Priorité : **B** = bloquante pour la phase indiquée, **I** = importante, **P** = peut attendre.

| # | Question | Prio | Hypothèse par défaut | Statut |
|---|---|---|---|---|
| Q1 | Tous les analystes VOC sont-ils admins plateforme, ou faut-il un rôle admin attribué à quelques personnes ? | B (ph. 1) | Rôle `platform_admin` séparé et cumulable, attribué nominativement | Ouverte |
| Q2 | Au-delà des agents et workflows, qu'est-ce qui est cloisonné entre VOC et CERT : vulnérabilités, bulletins, modèles, connecteurs, sources ? Faut-il un partage explicite (par exemple, le CERT transmet une vulnérabilité au VOC) ? | B (ph. 1) | Tout est cloisonné par espace ; seuls les catalogues CVE et technos sont globaux ; partage explicite plus tard | Ouverte |
| Q3 | Le CERT publie-t-il aussi vers le portail client ? Les clients doivent-ils savoir quelle équipe a émis un bulletin ? | I (ph. 6) | Les deux espaces peuvent publier ; l'émetteur est affiché | Ouverte |
| Q4 | Double validation (un rédacteur et un valideur distincts) obligatoire avant publication aux clients ? | I (ph. 6) | Oui, configurable par espace | Ouverte |
| Q5 | Une publication automatique sans humain est-elle souhaitée dans certains cas (par exemple, KEV critique) ? | I (ph. 6) | Non, jamais (ADR-019) | Ouverte |
| Q6 | Contraintes de confidentialité sur les LLM : fournisseur cloud américain accepté ? UE uniquement ? On-premise (SecNumCloud) ? Différent entre VOC et CERT ? | B (ph. 5) | Anthropic via API, seulement pour des données publiques ou non sensibles ; abstraction prête pour Mistral, Azure UE ou un modèle local ; politique par espace | Ouverte |
| Q7 | Budgets : plafond mensuel LLM ? Accès payant à l'API X souhaité (facturation par post lu) ? Jetons GitHub disponibles ? | I (ph. 5) | Source X désactivée sans identifiants ; budget LLM configurable avec arrêt dur | Ouverte |
| Q8 | Authentification : comptes locaux, ou SSO d'entreprise (Entra ID, Keycloak, ADFS) pour les internes ? Et pour les clients ? | B (ph. 1) | Comptes locaux et TOTP obligatoire ; OIDC en phase 10 | Ouverte |
| Q9 | Hébergement : on-premise, cloud (lequel) ? Kubernetes disponible ? Accès Internet sortant direct ou via un proxy d'entreprise ? | I (ph. 0) | Docker Compose mono-hôte, sortie via smokescreen (chaînable vers un proxy d'entreprise) | Ouverte |
| Q10 | Langues des bulletins (FR, EN, les deux) ? | P | Interface en FR ; langue définie par modèle | Ouverte |
| Q11 | Formats de diffusion : Markdown, HTML, PDF avec charte graphique ? E-mail aux clients ? | P (ph. 8) | Markdown et HTML ; PDF plus tard | Ouverte |
| Q12 | Quels systèmes vont recevoir les bulletins par API (MISP, OpenCTI, ticketing, CMS, portail tiers…) ? Sont-ils sur le réseau interne ? | I (ph. 7) | Connecteur HTTP générique ; réseau privé sur autorisation admin | Ouverte |
| Q13 | Volumétrie : nombre d'analystes, de clients et d'utilisateurs clients, de sources, de vulnérabilités par jour ? | P | Moins de 100 internes, moins de 1 000 clients, environ 10 000 éléments par jour | Ouverte |
| Q14 | Existe-t-il des workflows n8n à reprendre ? | P | Non ; nœud passerelle `integration.n8n_webhook` disponible | Ouverte |
| Q15 | Qui crée les comptes clients : les admins seulement, ou un admin côté client qui gère son organisation ? | I (ph. 8) | Admins plateforme seulement ; `client_admin` plus tard | Ouverte |
| Q16 | MFA obligatoire pour les clients ? | I (ph. 8) | Proposé et fortement recommandé, rendu obligatoire par organisation si souhaité | Ouverte |
| Q17 | Rétention : éléments collectés, traces d'agents (prompts et réponses), exécutions de workflows, journaux ? | P | Éléments collectés 180 j, traces IA 90 j, exécutions 30 j, audit 1 an minimum | Ouverte |
| Q18 | Échelle de criticité : CVSS 4.0 et/ou 3.1, échelle interne (P1 à P4), statuts de qualification spécifiques ? | I (ph. 2) | CVSS 4.0 et 3.1 affichés, priorité interne P1 à P4, statuts de `specs/01-data-model.md` | Ouverte |
| Q19 | Granularité des technos pour les clients : éditeur et produit, ou aussi les versions ? | P (ph. 9) | Éditeur et produit (avec correspondance CPE et purl) ; versions plus tard | Ouverte |
| Q20 | Canaux de notification disponibles : SMTP, Teams, Slack, Mattermost ? | P | SMTP | Ouverte |
| Q21 | Nom du produit et charte graphique ? | P | « Vuln-Veille », thème sobre clair et sombre | Ouverte |
| Q22 | Marquage TLP attendu sur les bulletins, et règles de visibilité TLP pour les clients ? | I (ph. 6) | TLP 2.0 ; portail limité à TLP:CLEAR et TLP:GREEN, plus TLP:AMBER pour les organisations explicitement ciblées | Ouverte |

## Réponses reçues

_(aucune pour l'instant)_

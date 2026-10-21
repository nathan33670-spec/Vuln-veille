## Objet

<!-- Étape(s) du plan (ex. « 4.1 Interface AIEngine ») ou correctif, en une ou deux phrases. -->

## Changements

-

## Sécurité

<!-- Checklist de docs/SECURITY.md §5 : autorisation par défaut refusée, filtrage workspace_id + RLS,
     sortie réseau par connecteur et SafeHttpClient, aucun secret ni donnée interne (dépôt public),
     contenu collecté et sorties LLM non fiables, aucun service payant hors IA. -->

- [ ] Checklist de sécurité relue (SECURITY.md §5)

## Vérifications

- [ ] `make lint typecheck test` vert en local
- [ ] Tests ajoutés ou mis à jour
- [ ] `docs/PLAN.md` et `docs/PROGRESS.md` à jour (et spec, ADR si besoin)

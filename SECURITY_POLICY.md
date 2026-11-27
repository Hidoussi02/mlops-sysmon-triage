# Politique de blocage CI/CD (DevSecOps)

Le pipeline GitHub Actions bloque automatiquement l'intégration si l'une des conditions suivantes n'est pas respectée :

| Contrôle | Outil | Critère de blocage | Justification |
| :--- | :--- | :--- | :--- |
| Qualité & Tests | Flake8 + Pytest | 1 erreur de lint ou 1 test en échec | Garantir la stabilité et la maintenabilité du code |
| Détection de secrets | Gitleaks (`--redact`) | **>= 1 secret détecté** | Empêcher toute fuite d'identifiants dans le dépôt (valeurs masquées dans les logs) |
| SAST | Bandit (`-ll`) | **>= 1 faille Medium ou High** | Bloquer les vulnérabilités applicatives connues (injection, secrets en dur, chemins non sûrs) |
| Dépendances & Image | Trivy (`fs` + `image`) | **>= 1 CVE CRITICAL corrigible** | Éviter de déployer un conteneur contenant une faille critique exploitable |
| Durcissement conteneur | Docker smoke-test | Utilisateur différent de `10001` ou échec `/health` | Vérifier l'exécution non-root, `read-only` et `cap-drop ALL` |

## Limites connues
Un pipeline au vert réduit fortement le risque mais ne garantit pas une sécurité absolue (vulnérabilités logiques métier, failles zero-day ou CVE sans correctif disponible).
## Procédure de gestion d'un secret exposé (Section 4.4)
En cas de détection d'un secret par Gitleaks, l'équipe applique strictement l'ordre suivant :
1. **Révoquer et remplacer d'abord** le secret auprès du fournisseur / gestionnaire de secrets (rendre l'ancienne valeur immédiatement inutilisable).
2. **Nettoyer ensuite** le fichier dans le dépôt (et purger l'historique Git via `git filter-repo` en environnement de production).
3. **Vérifier** via un nouveau run CI que Gitleaks ne détecte plus aucune fuite.

## Procédure de gestion d'un secret exposé (Section 4.4)
En cas de détection d'un secret par Gitleaks, l'équipe applique strictement l'ordre suivant :
1. **Révoquer et remplacer d'abord** le secret auprès du fournisseur / gestionnaire de secrets (rendre l'ancienne valeur immédiatement inutilisable).
2. **Nettoyer ensuite** le fichier dans le dépôt (et purger l'historique Git via `git filter-repo` en environnement de production).
3. **Vérifier** via un nouveau run CI que Gitleaks ne détecte plus aucune fuite.

## Procédure de gestion d'un secret exposé (Section 4.4)
En cas de détection d'un secret par Gitleaks, l'équipe applique strictement l'ordre suivant :
1. **Révoquer et remplacer d'abord** le secret auprès du fournisseur / gestionnaire de secrets (rendre l'ancienne valeur immédiatement inutilisable).
2. **Nettoyer ensuite** le fichier dans le dépôt (et purger l'historique Git via `git filter-repo` en environnement de production).
3. **Vérifier** via un nouveau run CI que Gitleaks ne détecte plus aucune fuite.

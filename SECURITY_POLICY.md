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
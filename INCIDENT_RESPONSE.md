# Plan de Reponse aux Incidents - mlops-sysmon-triage

## 1. Objectif et perimetre
Ce plan definit la procedure en cas d'incident touchant l'API ML (sysmon-api), le cluster Kubernetes (mlops-sec), le pipeline CI/CD ou les secrets.

## 2. Sources de detection
| Source | Signal / Evenement | Severite |
| :--- | :--- | :--- |
| Logs API (app.py) | SECURITY_EVENT idor_blocked (acces inter-roles) | Moyenne / Haute |
| Logs API (app.py) | SECURITY_EVENT sqli_attempt_blocked (SQLi bloquee) | Haute |
| Wazuh SIEM | Regle 100901 (niv. 12) : Sysmon malveillant (XGBoost >= 0.5) | Critique |
| CI/CD GitHub Actions | Echec Gitleaks, Bandit (-ll) ou Trivy (CRITICAL) | Bloquante |
| Kubernetes / Calico | Connexion refusee par default-deny-all / CrashLoopBackOff | Moyenne / Haute |

## 3. Procedure de reponse (6 phases)
1. **Detection et triage (< 15 min)** : verifier les logs du pod (`kubectl logs -n mlops-sec deploy/sysmon-api`) et les alertes Wazuh (`/var/ossec/logs/alerts/alerts.json`), qualifier la severite et l'origine.
2. **Confinement (< 30 min)** : isoler le pod (`kubectl scale deployment/sysmon-api -n mlops-sec --replicas=0`) et, en cas de fuite de secret, **revoquer et regenerer la cle d'abord** avant de nettoyer le depot.
3. **Collecte de preuves (Forensics)** : sauvegarder `kubectl logs` et `kubectl describe pod` avant toute suppression.
4. **Eradication** : corriger la faille (code, dependances ou manifestes `k8s/`), renouveler le Secret Kubernetes et valider le passage au vert du pipeline CI/CD.
5. **Reprise (Recovery)** : redeployer l'image durcie (`kubectl rollout restart`), verifier `1/1 Running`, `UID 10001`, les en-tetes HTTP et `/health`.
6. **Post-mortem** : documenter cause racine/chronologie et ajouter un test automatise ou une regle Wazuh pour eviter la recidive.

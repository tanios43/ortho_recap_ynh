# Ortho Récap — Package YunoHost

Application de récapitulatif journalier des honoraires et kilomètres pour la Selarl Cyprien Nesme Orthoptiste.

## Installation

```bash
yunohost app install https://github.com/[votre-compte]/ortho_recap_ynh
```

## Fonctionnalités

- Saisie quotidienne des honoraires AMY (Yssingeaux & Le Puy) et actes RNO
- Calcul automatique des kilomètres parcourus selon les sites travaillés
- Récapitulatif annuel avec impression PDF
- Données stockées côté serveur dans une base SQLite
- Export/Import JSON

## Architecture

```
[Navigateur]  →  [Nginx]  →  [Flask/Python]  →  [SQLite]
   HTML/JS        SSOwat       API REST           data.db
```

- `/` → protégé par SSOwat, Flask injecte l'utilisateur et un token HMAC dans le HTML
- `/api/` → auth via token HMAC signé par Flask (valable 1h)

## Rôles

- **Admin** (choisi à l'install) : badge ✏️, peut modifier toutes les données
- **Autres utilisateurs** : badge 👁, consultation uniquement

## Base de données

Stockée dans `/home/yunohost.app/ortho_recap/data.db` (SQLite).

## Logs

```bash
journalctl -u ortho_recap -f
```

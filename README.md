# 🔐 Scan Vulnérabilité Pro — Version Finale 🔐

![Docker](https://img.shields.io/badge/Docker-✓-blue)
![Python](https://img.shields.io/badge/Python-3.9+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📌 Présentation
Outil d'audit rapide et éducatif pour détecter les services vulnérables sur un hôte IP. Interface web, cache intégré, limitation de requêtes, export HTML stylisé.

## 🚀 Fonctionnalités
- ✅ Export HTML avec CSS élégant
- 🧠 Cache LRU pour ne pas rescanner inutilement
- 🛑 Limiteur de débit via Flask Limiter (5 scans/min/IP)
- ⚠️ Gestion propre des erreurs IP avec JSON structuré

## ❗ Limites professionnelles
> Cet outil ne remplace pas Nessus ou OpenVAS. Il est adapté pour de l’audit rapide, du lab, ou de l'apprentissage.

## 🧪 Lancement rapide
```bash
docker build -t scan_vuln_ultime .
docker run -p 5000:5000 scan_vuln_ultime
```

## 📊 Exemple de rapport HTML
Accessible via `/rapport/<IP>` après un scan.

## 📚 Licence : MIT — Utilisation libre et modifiable.
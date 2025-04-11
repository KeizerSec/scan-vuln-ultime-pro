import subprocess
import re
import logging
import os
from functools import lru_cache
from jinja2 import Template
from logging.handlers import RotatingFileHandler
import shutil

# Constantes configurables
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "../scan.log")  # Chemin pour les logs
REPORT_DIR = os.getenv("REPORT_DIR", "../rapports")        # Répertoire pour les rapports HTML
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", 300))         # Timeout pour le scan Nmap (en secondes)

# Configuration du logging avec rotation
handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=5)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def verifier_nmap():
    """
    Vérifie si Nmap est installé et accessible.
    Si non, une erreur est levée.
    """
    if not shutil.which("nmap"):
        logging.error("Nmap n'est pas installé ou introuvable.")
        raise EnvironmentError("Nmap n'est pas installé ou introuvable.")

def valider_ip(ip: str) -> bool:
    """
    Vérifie si l'adresse IP est valide.
    :param ip: Adresse IP à valider.
    :return: True si valide, sinon False.
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

@lru_cache(maxsize=32)
def scan_vulnerabilites(ip: str) -> str:
    """
    Exécute un scan Nmap pour détecter les vulnérabilités sur une adresse IP.
    :param ip: Adresse IP à scanner.
    :return: Résultats du scan sous forme de chaîne.
    """
    try:
        logging.info(f"Scan démarré pour {ip}")
        resultat = subprocess.run(
            ['nmap', '--script', 'vulners', '-sV', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=NMAP_TIMEOUT,
            check=True
        )
        logging.info(f"Scan terminé pour {ip}")
        return resultat.stdout.decode()
    except subprocess.TimeoutExpired:
        logging.error(f"Scan expiré pour {ip}")
        return "Le scan a expiré (Timeout)."
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur Nmap pour {ip}: {e.stderr.decode()}")
        return f"Erreur Nmap : {e.stderr.decode()}"

def generer_html(ip: str, resultat: str) -> str:
    """
    Génère un rapport HTML basé sur les résultats du scan.
    :param ip: Adresse IP scannée.
    :param resultat: Résultats du scan.
    :return: Contenu HTML.
    """
    template_html = Template("""
    <html>
    <head>
        <title>Rapport Scan - {{ ip }}</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>Rapport de vulnérabilité pour {{ ip }}</h1>
        <pre>{{ resultat }}</pre>
    </body>
    </html>
    """)
    return template_html.render(ip=ip, resultat=resultat)

def sauvegarder_rapport(ip: str, contenu_html: str) -> str:
    """
    Sauvegarde le rapport HTML dans un fichier.
    :param ip: Adresse IP scannée.
    :param contenu_html: Contenu HTML du rapport.
    :return: Chemin du fichier sauvegardé.
    """
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)
    chemin = f"{REPORT_DIR}/{ip}_scan.html"
    with open(chemin, 'w') as fichier:
        fichier.write(contenu_html)
    logging.info(f"Rapport sauvegardé pour {ip} à l'emplacement {chemin}")
    return chemin

def lancer_scan(ip: str) -> tuple:
    """
    Lancer le processus complet de scan pour une adresse IP.
    :param ip: Adresse IP à scanner.
    :return: Résultats et chemin du rapport HTML.
    """
    if valider_ip(ip):
        verifier_nmap()
        resultat = scan_vulnerabilites(ip)
        contenu_html = generer_html(ip, resultat)
        chemin = sauvegarder_rapport(ip, contenu_html)
        return resultat, chemin
    else:
        logging.warning(f"Tentative de scan avec IP invalide : {ip}")
        return None, None

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage : python3 scan.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]
    resultat, chemin = lancer_scan(ip)

    if resultat:
        print(f"Scan terminé pour {ip}")
        print(resultat)
        print(f"Rapport HTML généré ici : {chemin}")
    else:
        print("IP invalide")

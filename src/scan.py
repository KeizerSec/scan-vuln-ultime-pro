import subprocess, re, logging, os
from functools import lru_cache
from jinja2 import Template

logging.basicConfig(filename='../scan.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

def valider_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

@lru_cache(maxsize=32)
def scan_vulnerabilites(ip):
    try:
        logging.info(f"Scan démarré pour {ip}")
        resultat = subprocess.run(['nmap', '--script', 'vulners', '-sV', ip],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  timeout=300, check=True)
        logging.info(f"Scan terminé pour {ip}")
        return resultat.stdout.decode()
    except subprocess.TimeoutExpired:
        logging.error(f"Scan expiré pour {ip}")
        return "Le scan a expiré (Timeout)."
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur Nmap pour {ip}: {e.stderr.decode()}")
        return f"Erreur Nmap : {e.stderr.decode()}"

def generer_html(ip, resultat):
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

def sauvegarder_rapport(ip, contenu_html):
    dossier_rapports = "../rapports"
    if not os.path.exists(dossier_rapports):
        os.makedirs(dossier_rapports)
    chemin = f"{dossier_rapports}/{ip}_scan.html"
    with open(chemin, 'w') as fichier:
        fichier.write(contenu_html)
    return chemin

def lancer_scan(ip):
    if valider_ip(ip):
        resultat = scan_vulnerabilites(ip)
        contenu_html = generer_html(ip, resultat)
        chemin = sauvegarder_rapport(ip, contenu_html)
        return resultat, chemin
    else:
        logging.warning(f"Tentative de scan avec IP invalide : {ip}")
        return None, None
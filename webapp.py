from flask import Flask, jsonify, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from scan import lancer_scan, valider_ip

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/scan/<ip>')
@limiter.limit("5/minute")
def scan(ip):
    if not valider_ip(ip):
        return jsonify({
            "error": "Adresse IP invalide",
            "status": "failed"
        }), 400

    resultat, chemin = lancer_scan(ip)
    if resultat is None:
        return jsonify({
            "error": "Scan non lancé (IP invalide ou erreur critique)",
            "status": "failed"
        }), 400

    return jsonify({
        "ip": ip,
        "resultat": resultat,
        "rapport_html": chemin
    })

@app.route('/rapport/<ip>')
def rapport(ip):
    chemin = f"../rapports/{ip}_scan.html"
    return send_file(chemin)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import logging
import mimetypes
import threading
import time
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import joblib  
import scapy.all as scapy  
import redis  
from datetime import datetime
from collections import deque

# Stocare loguri în memorie
MAX_LOGS = 1000  # Numărul maxim de loguri stocate în memorie
logs_in_memory = deque(maxlen=MAX_LOGS)

UPLOAD_FOLDER = './uploads'
REPORT_FOLDER = './reports'
MONITOR_LOGS = './monitor_logs'
RULES_FILE = './rules/security_rules.txt'

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})  # Permite cereri de la orice origine


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(MONITOR_LOGS, exist_ok=True)
os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)

# Conectare la serverul Redis
redis_url = os.getenv('REDIS_URL', 'redis://default:sjWXNy2qm9RjBVD9ynNePtO5mtIjrbiB@redis-15488.c233.eu-west-1-1.ec2.redns.redis-cloud.com:15488')
redis_client = redis.StrictRedis.from_url(redis_url)


try:
    redis_client.ping()  # Verifică dacă Redis este disponibil
    print("Connected to Redis!")
except redis.ConnectionError:
    print("Could not connect to Redis")

logging.basicConfig(level=logging.INFO)

seen_logs = set()  

vulnerability_labels = ['Buffer Overflow', 'Use-After-Free', 'Double-Free', 'Out-of-Bounds Access', 'Heap Spraying']

import os
import joblib

# Încărcăm modelele și vectorizatorii antrenați
try:
    model = joblib.load('./models/vulnerability_classifier_xgb.pkl')
    vectorizer = joblib.load('./models/tfidf_vectorizer.pkl')
    label_encoder = joblib.load('./models/label_encoder.pkl')
except Exception as e:
    print(f"Eroare la încărcarea modelelor: {e}")

def analyze_file(file_path):
    vulnerabilities = []

    try:
        # Deschidem fișierul SWF și citim datele binare
        with open(file_path, 'rb') as f:
            data = f.read()

            # Verificăm dacă există vulnerabilități pe baza funcției eval()
            if b"eval" in data:
                vulnerabilities.append({
                    "type": "Code Injection",
                    "severity": "Critical",
                    "description": "Detected usage of eval() function."
                })

            swf_hex_string = data.hex()  # Converim fișierul binar într-un șir hexazecimal
            swf_features = vectorizer.transform([swf_hex_string]).toarray()  # Aplicăm vectorizatorul pe fișierul SWF

            # Verificăm dacă dimensiunea vectorului este corectă
            if swf_features.shape[1] != 76:
                raise ValueError(f"Dimensiunea caracteristicilor fișierului SWF este diferită de 76: {swf_features.shape[1]}")

            # Predicția modelului
            prediction = model.predict(swf_features)
            detected_vulnerability = label_encoder.inverse_transform(prediction)

            vulnerabilities.append({
                "type": detected_vulnerability[0],
                "severity": "High",  # Aici poți ajusta severitatea în funcție de regulile tale
                "description": f"Potential {detected_vulnerability[0]} detected based on file analysis."
            })

    except Exception as e:
        print(f"Eroare la analiza fișierului {file_path}: {e}")

    return {
        "filename": os.path.basename(file_path),
        "vulnerabilities": vulnerabilities
    }


def generate_pdf(report_data, output_path):
    c = canvas.Canvas(output_path, pagesize=letter)
    c.drawString(100, 750, f"Raport pentru: {report_data['filename']}")
    c.drawString(100, 730, "Vulnerabilitati:")
    
    y = 710
    for vuln in report_data['vulnerabilities']:
        c.drawString(120, y, f"- {vuln['type']} ({vuln['severity']}): {vuln['description']}")
        y -= 20
    

    c.save()

def detect_packet(packet):
    log_entry = ""

    # Layer 2: Data Link
    if scapy.Ether in packet:
        log_entry = f"L2: MAC Address: Src={packet[scapy.Ether].src}, Dst={packet[scapy.Ether].dst}\n"

    # Layer 3: Network
    if scapy.IP in packet:
        log_entry = f"L3: IP Packet: Src={packet[scapy.IP].src}, Dst={packet[scapy.IP].dst}\n"
    if scapy.TCP in packet and packet[scapy.TCP].flags == "S":
        log_entry = "L3: TCP SYN Packet detected: Possible SYN Flood attack.\n"

    # Evita loguri duplicate
    if log_entry and log_entry not in seen_logs:
        seen_logs.add(log_entry)
        logs_in_memory.append(log_entry)  # Adaugă logul în memorie

def monitor_traffic():
    # Monitorizează traficul de rețea și detectează pachete
    scapy.sniff(prn=detect_packet, store=False)


# Funcție pentru a citi regulile de securitate dintr-un fișier
def get_security_rules():
    rules = []
    try:
            for rule in security_rules:
                if rule.strip():
                    parts = rule.split(":")
                    rule_type = parts[0].strip()
                    rule_value = parts[1].strip() if len(parts) > 1 else ""
                    rules.append({"rule_type": rule_type, "rule_value": rule_value})
    except Exception as e:
        logging.error(f"Error loading rules: {str(e)}")
    return rules


# Funcție pentru obținerea extensiei fișierului
def get_file_extension(file_data):
    # Utilizează mimetypes pentru a detecta tipul fișierului
    file_type, encoding = mimetypes.guess_type(file_data.filename)
    if file_type:
        return file_type.split('/')[1]  # returnează extensia tipului de fișier
    return file_data.filename.split('.')[-1].lower() if '.' in file_data.filename else None

# Funcție pentru limitarea cererilor pe IP
def apply_rate_limit(ip_address, redis_client, rules):
    # Extrage regula LimitRequests din lista de reguli
    limit_rule = next((rule for rule in rules if rule['rule_type'] == 'LimitRequests'), None)
    
    # Dacă nu există regula LimitRequests, se permit cereri nelimitate
    if not limit_rule:
        return None
    
    try:
        # Extrage limita din regula LimitRequests
        limit = int(limit_rule['rule_value'].split(" ")[0])  
        time_window = 60  
        current_time = datetime.now()
        user_key = f"login_attempts:{ip_address}:{current_time.minute}"

        # Incrementăm numărul de încercări pentru IP-ul respectiv
        attempts = redis_client.incr(user_key)
        if attempts > limit:
            return jsonify({"error": "Too many requests, please try again later."}), 429

        # Expiră cheia după 1 minut
        redis_client.expire(user_key, time_window)
    except Exception as e:
        logging.error(f"Error applying rate limit: {str(e)}")
    
    return None  


# Funcția principală pentru aplicarea regulilor de securitate
def apply_security_rules(file_data, request_type, ip_address=None, redis_client=None):
    # Citește regulile de securitate
    rules = get_security_rules()
    filename = secure_filename(file_data.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

      # Regula 1: Validarea fișierului
    if 'AllowFileType' in [rule['rule_type'] for rule in rules]:
        allowed_types = [rule['rule_value'] for rule in rules if rule['rule_type'] == 'AllowFileType']
        file_extension = get_file_extension(file_data)
        
        if file_extension not in allowed_types:
            return jsonify({"error": "Invalid file type. Allowed types: " + ", ".join(allowed_types)}), 400
    

    # Regula 2: Limitarea cererilor pe IP
    if ip_address and redis_client:
        rate_limit_response = apply_rate_limit(ip_address, redis_client)
        if rate_limit_response:
            return rate_limit_response

    # Regula 3: Limitarea dimensiunii fișierului
    if 'MaxFileSize' in [rule['rule_type'] for rule in rules]:
        max_file_size = [rule['rule_value'] for rule in rules if rule['rule_type'] == 'MaxFileSize'] * 1024
        print(max_file_size)
        print(os.path.getsize(file_path))
        if os.path.getsize(file_path) > int(max_file_size[0]):
            return jsonify({"error": "File size exceeds the limit"}), 400

    return None

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Vulnerabilities API!"})


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        # Aplica rate limit pe baza IP-ului utilizatorului
        ip_address = request.remote_addr
        rules = get_security_rules()
        rate_limit_response = apply_rate_limit(ip_address, redis_client, rules)
        if rate_limit_response:
            return rate_limit_response

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Aplica regulile de securitate
        security_check_response = apply_security_rules(file, "upload")
        if security_check_response:
            return security_check_response

        report_data = analyze_file(file_path)
        report_filename = f"{os.path.splitext(filename)[0]}_report.pdf"
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
        generate_pdf(report_data, report_path)

        return jsonify({
            "report_url": f"https://web-vulnerabilities-client-f6a362108440.herokuapp.com/reports/{report_filename}",
            "vulnerabilities": report_data['vulnerabilities']
        })
    except Exception as e:
        logging.exception("Error during analysis.")
        return jsonify({"error": str(e)}), 500


@app.route('/reports/<filename>', methods=['GET'])
def download_report(filename):
    report_path = os.path.join(app.config['REPORT_FOLDER'], filename)
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not found"}), 404
    return send_file(report_path, as_attachment=True)


sample_logs = [
        "L2: MAC Address: Acest proces functioneaza doar cand este rulat local",
        "L2: MAC Address: Src=00:11:22:33:44:55, Dst=AA:BB:CC:DD:EE:FF",
        "L2: MAC Address: Src=00:11:22:33:44:55, Dst=AA:BB:CC:DD:EE:FF",
        "L3: IP Packet: Acest proces functioneaza doar cand este rulat local",
        "L3: IP Packet: Src=192.168.0.1, Dst=192.168.0.2",
        "L3: IP Packet: Src=192.168.0.1, Dst=192.168.0.2",
        "L3: TCP SYN Packet detected: Possible SYN Flood attack."
    ]

@app.route('/monitor', methods=['GET'])
def monitor():
    if not logs_in_memory:
        return jsonify({"logs": sample_logs})

    return jsonify({"logs": list(logs_in_memory)})

security_rules = []  # Regulile de securitate vor fi stocate în memorie

@app.route('/security-rules', methods=['POST'])
def save_security_rules():
    try:
        rules = request.json.get("rules", "").strip()
        if not rules:
            return jsonify({"error": "No rules provided"}), 400

        security_rules.clear()
        security_rules.extend(rules.splitlines())  # Split pe linii pentru a putea avea mai multe reguli
        return jsonify({"message": "Security rules saved successfully."}), 200
    except Exception as e:
        logging.exception("Error saving security rules.")
        return jsonify({"error": str(e)}), 500

@app.route('/security-rules', methods=['GET'])
def show_security_rules():
    return jsonify({"rules": security_rules})  



def remove_duplicate_logs():
    # Curăță periodic fișierul de loguri duplicat
    while True:
        log_path = os.path.join(MONITOR_LOGS, 'traffic.log')
        if os.path.exists(log_path):
            with open(log_path, 'r') as log_file:
                lines = log_file.readlines()
            
            unique_lines = list(dict.fromkeys(lines))
            
            # Rescrie fișierul doar cu loguri unice
            with open(log_path, 'w') as log_file:
                log_file.writelines(unique_lines)

        # Rulează curățarea la fiecare 10 de secunde
        time.sleep(10)


# Rulează curățarea într-un thread separat
cleanup_thread = threading.Thread(target=remove_duplicate_logs, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    # Pornește monitorizarea traficului într-un thread separat
    monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
    monitor_thread.start()    
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
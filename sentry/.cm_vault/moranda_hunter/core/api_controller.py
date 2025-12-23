# core/api_controller.py
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import os

app = Flask(__name__)
CORS(app) # ताकि आपका Android UI इसे एक्सेस कर सके

DB_PATH = "hunter_intel.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "status": "ONLINE",
        "architect": "Moranda",
        "system": "CyberMoranda Defense v1.0"
    })

@app.route('/api/loot', methods=['GET'])
def get_loot():
    conn = get_db_connection()
    # हालिया 10 'Critical' या 'High' फाइंडिंग्स प्राप्त करें
    query = "SELECT * FROM scans ORDER BY id DESC LIMIT 10"
    findings = conn.execute(query).fetchall()
    conn.close()
    
    loot_list = [dict(row) for row in findings]
    return jsonify(loot_list)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = get_db_connection()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    conn.close()
    return jsonify({"total_scans": total_scans})

if __name__ == '__main__':
    # पोर्ट 5000 पर सर्वर शुरू करें
    print("[+] Moranda Mode API: Starting on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)


import sqlite3
from datetime import datetime

class HunterDB:
    def __init__(self, db_name="hunter_intel.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        # स्कैन की समरी और फाइंडिंग्स के लिए टेबल
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                timestamp DATETIME,
                findings_count INTEGER,
                ai_report TEXT
            )
        ''')
        self.conn.commit()

    def save_scan(self, target, findings, ai_report):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.cursor.execute('''
            INSERT INTO scans (target, timestamp, findings_count, ai_report)
            VALUES (?, ?, ?, ?)
        ''', (target, timestamp, len(findings), ai_report))
        self.conn.commit()
        print(f"\n[+] Intel stored in CyberMoranda Database.")


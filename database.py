import firebase_admin
from firebase_admin import credentials, firestore
import os

# Path ke file kredensial Anda
cred_path = os.path.join(os.path.dirname(__file__), 'firebase-credentials.json')

try:
    # Inisialisasi Firebase Admin SDK
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)
    print("Firebase App Initialized Successfully.")
except Exception as e:
    print(f"Error initializing Firebase App: {e}")
    # Jika sudah diinisialisasi, jangan error
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)

# Dapatkan instance klien Firestore
db = firestore.client()

def save_search_history(url, vt_summary, whois_registrar):
    """
    Menyimpan riwayat pencarian ke koleksi 'history' di Firestore.
    """
    try:
        # Tentukan status berdasarkan hasil VirusTotal
        malicious_count = vt_summary.get('malicious', 0)
        suspicious_count = vt_summary.get('suspicious', 0)
        
        status = "Aman"
        if malicious_count > 0:
            status = "Berbahaya"
        elif suspicious_count > 0:
            status = "Mencurigakan"

        # Buat dokumen baru dengan ID otomatis
        doc_ref = db.collection('history').document()
        doc_ref.set({
            'url': url,
            'status': status,
            'registrar': whois_registrar,
            'malicious_count': malicious_count,
            'timestamp': firestore.SERVER_TIMESTAMP # Simpan waktu server saat ini
        })
        print(f"Successfully saved history for: {url}")
        return True
    except Exception as e:
        print(f"Error saving history: {e}")
        return False

def get_search_history(limit=10):
    """
    Mengambil riwayat pencarian dari Firestore, diurutkan dari yang terbaru.
    """
    try:
        # Ambil dokumen dari koleksi 'history', urutkan berdasarkan timestamp
        history_ref = db.collection('history').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
        docs = history_ref.stream()

        history_list = []
        for doc in docs:
            data = doc.to_dict()
            data['id'] = doc.id # Simpan ID dokumen jika diperlukan
            # Konversi timestamp ke format yang bisa dibaca jika ada
            if 'timestamp' in data and data['timestamp']:
                 data['timestamp_human'] = data['timestamp'].strftime('%d %B %Y, %H:%M')
            history_list.append(data)
        
        return history_list
    except Exception as e:
        print(f"Error getting history: {e}")
        return []
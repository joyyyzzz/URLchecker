import requests
import base64

# Simpan API Key Anda di sini
API_KEY = "a6796d355cb47cfe283020c4da75354757f0ba4fca72228d8d89a381b4b1b805"

def check_virustotal(url):
    """
    Mengecek URL menggunakan VirusTotal API v3 dan mengembalikan data atribut.
    """
    try:
        # Encode URL ke format base64 yang aman untuk URL
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "x-apikey": API_KEY,
            "accept": "application/json"
        }
        
        # Lakukan request ke VirusTotal API
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        
        # Pastikan request berhasil
        response.raise_for_status()
        
        # Ambil seluruh bagian 'attributes' dari data JSON
        attributes = response.json().get('data', {}).get('attributes', {})
        return attributes

    except requests.exceptions.HTTPError as err:
        # Tangani error jika URL tidak ditemukan (404) atau error lainnya
        print(f"HTTP Error: {err}")
        if err.response.status_code == 404:
            return {"error": "URL tidak ditemukan di database VirusTotal."}
        return {"error": f"Gagal mendapatkan data: {err}"}
    except Exception as e:
        # Tangani error umum lainnya
        print(f"An error occurred: {e}")
        return {"error": "Terjadi kesalahan saat memproses permintaan."}
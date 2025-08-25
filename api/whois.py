import requests

# Ganti dengan API Key Anda dari WhoisXML API
API_KEY = "at_1eRYEGDmM122Pp2cmkQGBJ4xxfAly" 

def get_whois_data(domain):
    """
    Mengambil data WHOIS untuk sebuah domain menggunakan WhoisXML API.
    """
    # PERBAIKAN DI SINI: Gunakan endpoint yang benar
    api_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    
    params = {
        "apiKey": API_KEY,
        "domainName": domain,
        "outputFormat": "JSON" # Meminta output dalam format JSON
    }

    try:
        # Lakukan request ke API
        response = requests.get(api_url, params=params)
        response.raise_for_status() # Akan memunculkan error jika request gagal

        data = response.json()
        
        # Periksa jika ada error dari API itu sendiri
        if 'ErrorMessage' in data:
            return {"error": data['ErrorMessage']['msg']}
            
        # Kembalikan data WhoisRecord jika berhasil
        return data.get('WhoisRecord', {})

    except requests.exceptions.HTTPError as err:
        return {"error": f"HTTP Error: Gagal menghubungi server WHOIS API. ({err})"}
    except Exception as e:
        return {"error": f"Terjadi kesalahan: {e}"}

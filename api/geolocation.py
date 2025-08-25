import requests
import socket # Library bawaan Python untuk interaksi jaringan

# Ganti dengan Access Token Anda dari ipinfo.io
ACCESS_TOKEN = "3a6a7fce0dc0b2"

def get_ip_geolocation(domain):
    """
    Mendapatkan alamat IP dari domain dan mencari data geolokasinya.
    """
    try:
        # 1. Dapatkan alamat IP dari nama domain
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        # Terjadi jika domain tidak bisa di-resolve (misalnya, domain tidak valid)
        return {"error": "Tidak dapat menemukan alamat IP untuk domain ini."}
    except Exception as e:
        return {"error": f"Terjadi kesalahan saat mencari IP: {e}"}

    # 2. Jika IP berhasil didapat, cari geolokasinya
    try:
        api_url = f"https://ipinfo.io/{ip_address}"
        params = {"token": ACCESS_TOKEN}
        
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        
        data = response.json()
        return data

    except requests.exceptions.HTTPError as err:
        return {"error": f"Gagal menghubungi server geolokasi. ({err})"}
    except Exception as e:
        return {"error": f"Terjadi kesalahan saat mengambil data geolokasi: {e}"}


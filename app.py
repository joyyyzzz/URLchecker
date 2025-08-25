from flask import Flask, render_template, request, redirect, url_for, flash, session
from api.virustotal import check_virustotal
from api.whois import get_whois_data
from api.geolocation import get_ip_geolocation # <-- 1. Impor fungsi baru
from database import save_search_history, get_search_history # <-- 1. Impor fungsi database
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='static')
app.secret_key = 'your_secret_key'

USER = {'username': 'admin', 'password': 'admin'}

@app.route('/', methods=['GET'])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Ambil 5 riwayat terakhir untuk ditampilkan di halaman utama
    history = get_search_history(limit=5)
    return render_template('index.html', history=history)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == USER['username'] and password == USER['password']:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Username atau password salah', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/check', methods=['POST'])
def check():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    url_to_check = request.form['url']
    if not url_to_check:
        flash('URL tidak boleh kosong!', 'warning')
        return redirect(url_for('index'))

    # Panggil semua API
    vt_results = check_virustotal(url_to_check)
    domain_name = url_to_check.split("://")[-1].split("/")[0]
    whois_results = get_whois_data(domain_name)
    geo_results = get_ip_geolocation(domain_name) # <-- 2. Panggil fungsi geolokasi

    # Simpan riwayat ke database
    if vt_results and not vt_results.get('error'):
        vt_summary = vt_results.get('last_analysis_stats', {})
        whois_registrar = whois_results.get('registrarName', 'N/A')
        save_search_history(url_to_check, vt_summary, whois_registrar)
    
    # Proses data untuk ditampilkan
    if vt_results and 'last_analysis_date' in vt_results:
        timestamp = vt_results['last_analysis_date']
        vt_results['last_analysis_date_human'] = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    gsb_results = None 
    
    return render_template(
        'results.html', 
        url=url_to_check, 
        vt_results=vt_results, 
        whois_results=whois_results,
        geo_results=geo_results, # <-- 3. Kirim hasilnya ke template
        gsb_results=gsb_results
    )

if __name__ == '__main__':
    app.run(debug=True)
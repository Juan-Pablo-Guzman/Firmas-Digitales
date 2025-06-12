import os
import signal
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session, send_file, flash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from pyhanko.sign import signers, fields, PdfSignatureMetadata, PdfSigner
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.images import PdfImage
from pyhanko import stamp
import tempfile
import threading
import webbrowser
import requests
import time
import sys
from PyPDF2 import PdfReader, PdfWriter


# Configuration
APP_SECRET_KEY = os.environ.get('APP_SECRET_KEY', 'dev_secret')
MASTER_KEY_PATH = r"C:\Users\roy_l\OneDrive\Documentos\Cripto 6to\firma_digital-main\firma_digital-main\master.key"
UPLOAD_FOLDER = 'uploads'
DB_PATH = r"C:\Users\roy_l\OneDrive\Documentos\Cripto 6to\firma_digital-main\firma_digital-main\key_store.db"
USERS_FILE = r"C:\Users\roy_l\OneDrive\Documentos\Cripto 6to\firma_digital-main\firma_digital-main\users.db"
ALLOWED_EXT = {'.pdf'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # cambia en cada arranque
# app.secret_key = APP_SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

with open(MASTER_KEY_PATH, 'r') as mk:
    master_key = mk.read().strip()
fernet = Fernet(master_key.encode())

users = {}
with open(USERS_FILE, 'r') as f:
    for line in f:
        if ':' in line:
            user, pwd_hash = line.strip().split(':', 1)
            users[user] = pwd_hash

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()
cur.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        username TEXT PRIMARY KEY,
        priv_enc BLOB NOT NULL,
        cert_pem BLOB NOT NULL
    )
''')
conn.commit()

def generate_and_store_keys(username, user_password):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    pem_priv = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(user_password.encode())
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    priv_enc = fernet.encrypt(pem_priv)
    cur.execute('REPLACE INTO keys(username, priv_enc, cert_pem) VALUES(?,?,?)',
                (username, priv_enc, pem_cert))
    conn.commit()


def get_signer(username, user_password):
    cur.execute('SELECT priv_enc, cert_pem FROM keys WHERE username=?', (username,))
    row = cur.fetchone()
    if not row:
        generate_and_store_keys(username, user_password)
        return get_signer(username, user_password)

    priv_enc, cert_pem = row
    pem_priv = fernet.decrypt(priv_enc)

    # Crear archivos temporales
    temp_key = tempfile.NamedTemporaryFile(delete=False)
    temp_cert = tempfile.NamedTemporaryFile(delete=False)

    temp_key.write(pem_priv)
    temp_cert.write(cert_pem)
    temp_key.close()
    temp_cert.close()

    signer = signers.SimpleSigner.load(
        key_file=temp_key.name,
        cert_file=temp_cert.name,
        key_passphrase=user_password.encode()
    )

    return signer

def flatten_pdf(input_path, output_path):
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    with open(output_path, "wb") as f:
        writer.write(f)


def allowed_file(fname):
    return os.path.splitext(fname)[1].lower() in ALLOWED_EXT

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        if user in users and check_password_hash(users[user], pwd):
            session['user'] = user
            session['pwd'] = pwd
            return redirect(url_for('upload_pdf'))
        flash('Credenciales inválidas', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@app.route('/upload', methods=['GET', 'POST'])
def upload_pdf():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files.get('pdf_file')
        if not file or file.filename == '':
            flash('Seleccione un archivo PDF', 'error')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            flash('Solo archivos PDF permitidos', 'error')
            return redirect(request.url)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        return redirect(url_for('sign_pdf', filename=filename))
    return render_template('upload.html')

@app.route('/sign/<filename>')
def sign_pdf(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    pwd = session['pwd']
    in_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    out_name = f'signed_{filename}'
    onedrive_folder = r"C:\Users\roy_l\OneDrive - Instituto Tecnologico y de Estudios Superiores de Monterrey\Cripto_Casa_Monarca\Documentos_Firmados"
    out_path = os.path.join(onedrive_folder, out_name)

    with open(in_path, 'rb') as inf:
        writer = IncrementalPdfFileWriter(inf)
        sig_field = fields.SigFieldSpec(sig_field_name='Signature1', box=(50, 50, 300, 150))
        fields.append_signature_field(writer, sig_field)

        signer = get_signer(user, pwd)

        stamp_style = None
        img_path = os.path.join(os.getcwd(), 'firma.jpg')
        if os.path.exists(img_path):
            img = PdfImage(img_path)
            stamp_style = stamp.TextStampStyle(
                stamp_text="Firmado por %(signer)s el %(ts)s",
                background=img
            )

        metadata = PdfSignatureMetadata(field_name='Signature1')
        pdf_signer = PdfSigner(signature_meta=metadata, signer=signer, stamp_style=stamp_style)

        with open(out_path, 'wb') as outf:
            pdf_signer.sign_pdf(writer, output=outf)

    # Limpia la sesión justo antes de devolver el archivo
    session.clear()
    return send_file(out_path, as_attachment=True)

def open_browser():
    webbrowser.open_new("http://localhost:5000")

@app.route('/shutdown', methods=['POST'])
def shutdown():
    print(">> Apagando servidor Flask por cierre de navegador.")
    func = request.environ.get('werkzeug.server.shutdown')
    if func is not None:
        func()
    else:
        # Alternativa forzada si Werkzeug no está disponible
        os.kill(os.getpid(), signal.SIGTERM)
    return "Servidor cerrado correctamente."


if __name__ == '__main__':
    threading.Timer(1.0, open_browser).start()
    app.run(host='0.0.0.0', port=5000, debug=False)

import os
import binascii
from flask import Flask, render_template, request, session, redirect, url_for
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- NAVIGATION ROUTES ---


@app.route('/')
def index():
    """The Landing Page: Explaining the Quantum Threat."""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """The Main Project Page: Revealing all 5 Modules."""
    return render_template('dashboard.html')

# --- LOGIC ROUTES (Redirect back to Dashboard) ---

@app.route('/rsa_encrypt', methods=['POST'])
def rsa_encrypt():
    session['m1_plaintext'] = request.form.get('plaintext', 'Secret')
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.publickey())
    ciphertext = cipher.encrypt(session['m1_plaintext'].encode('utf-8'))
    session['m1_ciphertext'] = binascii.hexlify(ciphertext).decode('utf-8')
    session['m1_priv'] = key.export_key().decode('utf-8')
    return redirect(url_for('dashboard') + "#module1")

@app.route('/rsa_attack')
def rsa_attack():
    if 'm1_priv' in session:
        key = RSA.import_key(session['m1_priv'])
        cipher = PKCS1_OAEP.new(key)
        decoded = cipher.decrypt(binascii.unhexlify(session['m1_ciphertext']))
        session['m1_result'] = decoded.decode('utf-8')
    return redirect(url_for('dashboard') + "#module1")

@app.route('/sign', methods=['POST'])
def sign():
    msg = request.form.get('signature_message', 'Contract')
    key = ECC.generate(curve='P-256')
    h = SHA256.new(msg.encode('utf-8'))
    sig = DSS.new(key, 'fips-186-3').sign(h)
    session['m2_sig'] = binascii.hexlify(sig).decode('utf-8')
    session['m2_msg'] = msg
    session['m2_priv'] = key.export_key(format='PEM')
    return redirect(url_for('dashboard') + "#module2")

@app.route('/forge')
def forge():
    if 'm2_priv' in session:
        fake_msg = "FRAUDULENT TRANSFER"
        key = ECC.import_key(session['m2_priv'])
        h = SHA256.new(fake_msg.encode('utf-8'))
        session['m2_fake_sig'] = binascii.hexlify(DSS.new(key, 'fips-186-3').sign(h)).decode('utf-8')
        session['m2_fake_msg'] = fake_msg
    return redirect(url_for('dashboard') + "#module2")

@app.route('/key_exchange')
def key_exchange():
    a, b = ECC.generate(curve='P-256'), ECC.generate(curve='P-256')
    shared = a.d * b.pointQ
    session['m3_ecc_secret'] = binascii.hexlify(shared.x.to_bytes()).decode('utf-8')[:32]
    session['m3_kyber_secret'] = "7a4f91b2... (PQ-SECURE)"
    return redirect(url_for('dashboard') + "#module3")

@app.route('/rsa_vs_kyber')
def rsa_vs_kyber():
    session['m4_active'] = True
    session['m4_rsa_eve'] = binascii.hexlify(os.urandom(16)).decode('utf-8')
    return redirect(url_for('dashboard') + "#module4")

@app.route('/performance_test')
def performance_test():
    session['m5_active'] = True
    return redirect(url_for('dashboard') + "#module5")

@app.route('/reset')
def reset():
    session.clear()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # For flash messages

KEY_DIR = 'keys'
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'issuer_private_key.pem')
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, 'issuer_public_key.pem')

# Ensure key directory exists
os.makedirs(KEY_DIR, exist_ok=True)

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

# Generate keys if not present
if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
    generate_keys()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/issue', methods=['POST'])
def issue():
    name = request.form['name']
    dob = request.form['dob']
    user_id = request.form['user_id']
    issued_at = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    expires_at = (datetime.utcnow() + timedelta(days=365)).replace(microsecond=0).isoformat() + 'Z'  # 1 year expiry
    credential = {
        'name': name,
        'dob': dob,
        'user_id': user_id,
        'issued_at': issued_at,
        'expires_at': expires_at
    }
    credential_json = json.dumps(credential, sort_keys=True).encode()
    private_key = load_private_key()
    signature = private_key.sign(
        credential_json,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()
    credential_package = {
        'credential': credential,
        'signature': signature_b64
    }
    qr = qrcode.make(json.dumps(credential_package))
    buf = BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template('issued.html', credential=json.dumps(credential_package, indent=2), qr_code=qr_b64)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    result = None
    expired = False
    expiry_info = None
    if request.method == 'POST':
        try:
            data = request.form['credential']
            credential_package = json.loads(data)
            credential = credential_package['credential']
            signature = base64.b64decode(credential_package['signature'])
            credential_json = json.dumps(credential, sort_keys=True).encode()
            public_key = load_public_key()
            public_key.verify(
                signature,
                credential_json,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Check expiry
            expires_at = credential.get('expires_at')
            if expires_at:
                try:
                    expires_dt = datetime.fromisoformat(expires_at.replace('Z',''))
                    if expires_dt < datetime.utcnow():
                        expired = True
                        expiry_info = f"Warning: Credential expired at {expires_at}"
                except Exception:
                    expiry_info = "Warning: Could not parse expiry date."
            result = 'Credential is VALID.'
            if expired:
                result += ' (EXPIRED)'
        except (InvalidSignature, Exception):
            result = 'Credential is INVALID.'
    return render_template('verify.html', result=result, expiry_info=expiry_info)

if __name__ == '__main__':
    app.run(debug=True)

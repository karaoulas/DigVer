# DigVer: Digital Credential Issuer & Verifier

DigVer is a demo web application that simulates a digital credential ecosystem, inspired by real-world eIDAS and digital identity workflows. It demonstrates:

- Asymmetric key management (issuer keypair)
- JSON-based digital credential issuance with cryptographic signature
- Credential verification with signature and expiry check
- Simple, modern web UI (Bootstrap)
- QR code generation for credential sharing

## Features

- **Issue Credentials:**
  - Enter name, date of birth, and user ID to receive a signed digital credential.
  - Credential includes `issued_at` and `expires_at` fields (1 year validity).
  - Credential is displayed as JSON and as a QR code.

- **Verify Credentials:**
  - Paste a credential JSON to verify its signature and expiry.
  - Expired credentials show a warning.

- **Modern UI:**
  - Responsive, mobile-friendly interface using Bootstrap.

## Screenshots

![Issue Credential](Screenshot%202025-06-06%20185318.png)

![Verify Credential](Screenshot%202025-06-06%20185415.png)


## How it Works

- The issuer generates an RSA keypair (if not present).
- When a credential is issued, it is signed with the issuer's private key.
- The credential can be verified by anyone with the issuer's public key (built-in to the app).
- Credentials are encoded as QR codes for easy sharing.

## Technologies Used
- Python 3
- Flask
- cryptography
- qrcode
- Bootstrap 5 (CDN)




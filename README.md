# Hybrid Cryptosystem

A Python implementation of a hybrid cryptographic system combining RSA and AES encryption for secure file handling.

## Features
- RSA-2048 for key encryption
- AES-256 in ECB mode for file encryption
- PKCS7 padding
- Base64 encoded output

## Requirements
- Python 3.x
- cryptography library

## Installation
```bash
pip install cryptography
```

## Usage
1. Place your input file in the 'new' directory
2. Update the file path in the script if needed
3. Run the script:
```bash
python hybrid_crypto.py
```

The script will:
- Generate RSA key pair
- Encrypt file using AES
- Display original, encrypted, and decrypted content in Base64

## Security Note
This is a demonstration implementation. For production use, consider:
- Using CBC/GCM mode instead of ECB
- Implementing proper key management
- Adding error handling

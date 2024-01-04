# import statements

import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_key_pair():
    # Generation an RSA key pair with a private key and corresponding public key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def read_file_content(file_path):
    # Reading the content of the specified file
    with open(file_path, 'rb') as file:
        return file.read()

def encrypt_symmetric_key(sym_key, public_key):
    # Encrypting  the symmetric key using RSA with OAEP padding
    encrypted_sym_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_sym_key

def decrypt_symmetric_key(encrypted_sym_key, private_key):
    # Decrypting the symmetric key using RSA with OAEP padding
    decrypted_sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_sym_key

def encrypt_file_symmetric(file_content, sym_key):
    # Encryption of the file content using AES in ECB mode with PKCS7 padding
    cipher = Cipher(algorithms.AES(sym_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(file_content) + padder.finalize()

    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_content

def decrypt_file_symmetric(encrypted_content, sym_key):
    # Decrypting file content using AES in ECB mode with PKCS7 unpadding
    cipher = Cipher(algorithms.AES(sym_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_content) + decryptor.finalize()

    # PKCS7 unpadding
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

def test_hybrid_cryptosystem(file_path):
    # Generation of an RSA key pair
    private_key, public_key = generate_key_pair()

    # Generation of the random symmetric key for file encryption
    sym_key = os.urandom(32)  # 256-bit key for AES-256

    # Reading the content of the file
    message = read_file_content(file_path)

    # Encrypting the symmetric key with the public key
    encrypted_sym_key = encrypt_symmetric_key(sym_key, public_key)

    # Encrypting the file content with the symmetric key
    encrypted_content = encrypt_file_symmetric(message, sym_key)

    # Decrypting the symmetric key with the private key
    decrypted_sym_key = decrypt_symmetric_key(encrypted_sym_key, private_key)

    # Decrypting the file content with the symmetric key
    decrypted_content = decrypt_file_symmetric(encrypted_content, decrypted_sym_key)

    # Asserting that the original message matches the decrypted content
    assert message == decrypted_content

    # Converting to string for printing (in base64 encoding)
    base64_message = base64.b64encode(message).decode('utf-8')
    base64_encrypted_content = base64.b64encode(encrypted_content).decode('utf-8')
    base64_decrypted_content = base64.b64encode(decrypted_content).decode('utf-8')

    # Printing the original message, encrypted content, and decrypted content
    print(f"Original message (Base64): {base64_message}")
    print(f"Encrypted symmetric key (Base64): {base64.b64encode(encrypted_sym_key).decode('utf-8')}")
    print(f"Encrypted content (Base64): {base64_encrypted_content}")
    print(f"Decrypted symmetric key (Base64): {base64.b64encode(decrypted_sym_key).decode('utf-8')}")
    print(f"Decrypted content (Base64): {base64_decrypted_content}")

if __name__ == "__main__":
    # adding the file path
    file_path = 'new\\crypt.txt'
    test_hybrid_cryptosystem(file_path)

# sab imports
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# padding functions
def pad(text, block_size):
    pad_len = block_size - len(text) % block_size
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

# AES
def aes_encrypt_decrypt(message):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message, 16)
    encrypted = cipher.encrypt(padded_message.encode())
    decrypted = unpad(cipher.decrypt(encrypted).decode())
    return base64.b64encode(encrypted), decrypted

# DES
def des_encrypt_decrypt(message):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message, 8)
    encrypted = cipher.encrypt(padded_message.encode())
    decrypted = unpad(cipher.decrypt(encrypted).decode())
    return base64.b64encode(encrypted), decrypted

# RSA
def rsa_encrypt_decrypt(message):
    key = RSA.generate(2048)
    public_key = key.publickey()
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(message.encode())

    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(encrypted).decode()
    return base64.b64encode(encrypted), decrypted

# MAIN FUNCTION
def main():
    message = "Hello Shreyas!"

    print("--- AES ---")
    encrypted_aes, decrypted_aes = aes_encrypt_decrypt(message)
    print("Encrypted:", encrypted_aes)
    print("Decrypted:", decrypted_aes)

    print("\n--- DES ---")
    encrypted_des, decrypted_des = des_encrypt_decrypt(message)
    print("Encrypted:", encrypted_des)
    print("Decrypted:", decrypted_des)

    print("\n--- RSA ---")
    encrypted_rsa, decrypted_rsa = rsa_encrypt_decrypt(message)
    print("Encrypted:", encrypted_rsa)
    print("Decrypted:", decrypted_rsa)

# ✅ MOST IMPORTANT PART:
if __name__ == "__main__":
    main()

import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Load public key server
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())
rsa_cipher = PKCS1_OAEP.new(public_key)

# 1. Buat AES key baru
aes_key = get_random_bytes(16)

# 2. Encrypt pesan dengan AES
plaintext = input("Pesan untuk server: ").encode()
iv = get_random_bytes(16)
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
enc_msg = iv + cipher_aes.encrypt(pad(plaintext, AES.block_size))

# 3. Encrypt AES key dengan RSA
enc_aes_key = rsa_cipher.encrypt(aes_key)

# 4. Kirim ciphertext AES key dan ciphertext pesan ke server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('165.22.48.119', 80))

client_socket.send(enc_aes_key)      # 256 bytes
client_socket.send(enc_msg)          # sisa bytes (ciphertext pesan)

client_socket.close()

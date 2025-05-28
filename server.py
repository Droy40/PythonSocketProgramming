import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad

# Load private key
with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
rsa_cipher = PKCS1_OAEP.new(private_key)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print('Server listening...')

conn, addr = server_socket.accept()
print('Connected by', addr)

# 1. Terima ciphertext AES key (ukuran 256 byte untuk 2048 bit)
enc_aes_key = conn.recv(256)
print("ciphertext AES Key:",enc_aes_key)
# 2. Terima ciphertext pesan (panjangnya setelah)
enc_msg = conn.recv(4096)
print("ciphertext Message:",enc_msg)
# 3. Dekripsi AES key dengan RSA private key
aes_key = rsa_cipher.decrypt(enc_aes_key)

# 4. Dekripsi pesan dengan AES
iv = enc_msg[:16]
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = unpad(cipher_aes.decrypt(enc_msg[16:]), AES.block_size)

print("Plaintext dari client:", plaintext.decode())

conn.close()
server_socket.close()

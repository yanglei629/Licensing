# 以下是一个简单的示例，演示如何使用 pycryptodome 进行对称加密和解密

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')


def decrypt(key, ciphertext):
    data = b64decode(ciphertext.encode('utf-8'))
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')


# 生成一个随机的 256 位密钥
key = get_random_bytes(32)

# 要加密的文本
plaintext = "Hello, World!"

# 加密
encrypted_text = encrypt(key, plaintext)
print(f"Encrypted Text: {encrypted_text}")

# 解密
decrypted_text = decrypt(key, encrypted_text)
print(f"Decrypted Text: {decrypted_text}")

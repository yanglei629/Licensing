# 以下是一个使用 RSA 非对称加密的简单示例

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

# 生成 RSA 密钥对
key = RSA.generate(2048)

# 获取公钥和私钥
public_key = key.publickey().export_key()
private_key = key.export_key()

print(public_key)
print(private_key)


# 使用公钥加密
def encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return b64encode(ciphertext).decode('utf-8')


# 使用私钥解密
def decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = b64decode(ciphertext.encode('utf-8'))
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext


# 要加密的文本
plaintext = "Hello, World!"

# 使用公钥加密
encrypted_text = encrypt(public_key, plaintext)
print(f"Encrypted Text: {encrypted_text}")

# 使用私钥解密
decrypted_text = decrypt(private_key, encrypted_text)
print(f"Decrypted Text: {decrypted_text}")

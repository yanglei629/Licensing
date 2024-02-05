# 以下是一个简单的数字签名示例

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode


def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return b64encode(signature).decode('utf-8')


def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = b64decode(signature.encode('utf-8'))
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# 生成 RSA 密钥对
key = RSA.generate(2048)
public_key = key.publickey().export_key()
private_key = key.export_key()

# 要签名的消息
message = "Hello, World!"

# 对消息进行签名
signature = sign_message(private_key, message)
print(f"Signature: {signature}")

# 验证签名
is_valid = verify_signature(public_key, message, signature)
print(f"Is Valid: {is_valid}")

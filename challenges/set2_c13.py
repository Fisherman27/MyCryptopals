# 2025.11.25
# 任务：实现在ECB模式下，利用cut-and-paste攻击，实现任意用户登录

from set2_c11 import random_series_generator
KEY_BYTES = random_series_generator(16)

def profile_for(email: str) -> str:
    """
    将email地址转换为用户配置文件（指定格式字符串）
    （要求能处理&=等字符，但是在本任务中可以不实现，攻击时不能利用这一漏洞即可）
    """
    return f"email={email}&uid=10&role=user"

from set1_c7 import AES_128_ECB
from set2_c9 import pkcs7_padding, pkcs7_unpadding
def encryptor(plaintext_bytes: bytes) -> bytes:
    """
    对明文进行AES-128-ECB加密
    """
    # 对明文进行PKCS7填充
    padded_plaintext_bytes = pkcs7_padding(plaintext_bytes, 16)
    aes_ecb = AES_128_ECB(KEY_BYTES)
    return aes_ecb.encrypt(padded_plaintext_bytes)
def decryptor(ciphertext_bytes: bytes) -> bytes:
    """
    对密文进行AES-128-ECB解密
    """
    aes_ecb = AES_128_ECB(KEY_BYTES)
    padded_plaintext_bytes = aes_ecb.decrypt(ciphertext_bytes)
    # 对解密后的明文进行PKCS7去填充
    plaintext_bytes = pkcs7_unpadding(padded_plaintext_bytes)
    return plaintext_bytes

if __name__ == "__main__":

    target_plain_block = b'admin' + b'\x0b' * 11
    # 构造明文
    # 'email=aaaaaaaaaa
    #  admin               # 关键是有这么独立的一个块
    #  @qq.com&uid=10&r
    #  ole=user'
    email1 = b'aaaaaaaaaa'+target_plain_block+ b'@qq.com'
    email1 = email1.decode() # 转换为字符串
    profile1 = profile_for(email1) # 字符串
    ciphertext1 = encryptor(profile1.encode())
    # 目标密文块即为第二个块
    target_cipher_block = ciphertext1[16:32] 

    # 构造新的目标明文
    #  0123456789ABCDEF
    # 'email=aaaaaa@qq.
    #  com&uid=10&role=
    #  user'               # 用刚才的目标密文块替换该密文块即可
    email2 = b'aaaaaa@qq.com'
    email2 = email2.decode() # 转换为字符串
    profile2 = profile_for(email2) # 字符串
    ciphertext2 = encryptor(profile2.encode())
    # 目标密文块即为前两个块
    target_cipher_block2 = ciphertext2[:32]

    # 构造新的密文
    #  0123456789ABCDEF
    # 'email=aaaaaa@qq.
    #  com&uid=10&role=
    #  admin'              # 用目标密文块替换该密文块即可
    ciphertext3_bytes = target_cipher_block2 + target_cipher_block
    # 解密新的密文
    plaintext3_bytes = decryptor(ciphertext3_bytes)
    plaintext3 = plaintext3_bytes.decode()
    print(plaintext3)


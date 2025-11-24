# 2025.11.24
# 任务：先造一个加密器（具有随机性），再造一个 检测器，让检测器能 100% 猜中加密器每次用的是 ECB 还是 CBC (明文的构造权限在自己：选择明文)。

import random
def random_series_generator(length:int)->bytes:
    """
    生成随机字节串(伪随机即可)
    """
    return bytes([random.randint(0,255) for _ in range(length)])

from c9 import pkcs7_padding
from c7 import AES_128_ECB
from c10 import AES_128_CBC
def encryption_oracle(plaintext_bytes:bytes)->bytes:
    """
    引入随机性的加密器
    """
    # 在明文前后各添加5-10个随机字符
    before_text_bytes = random_series_generator(random.randint(5,10))
    after_text_bytes = random_series_generator(random.randint(5,10))
    plaintext_bytes = before_text_bytes + plaintext_bytes + after_text_bytes
    # 符合规范的填充
    plaintext_bytes = pkcs7_padding(plaintext_bytes,16)


    # 产生随机密钥
    key_bytes = random_series_generator(16)

    # 随机选择加密方式
    method = random.choice(['ECB','CBC'])
    if method == 'ECB':
        # 随机选择填充方式
        encryptor = AES_128_ECB(key_bytes)
        cipertext_bytes = encryptor.encrypt(plaintext_bytes)
    else:
        # 随机选择填充方式
        IV_bytes = random_series_generator(16)
        encryptor = AES_128_CBC(key_bytes,IV_bytes)
        cipertext_bytes = encryptor.encrypt(plaintext_bytes)
    
    return cipertext_bytes,method

from collections import Counter
def detect_ECB_or_CBC1(ciphertext_bytes:bytes)->str:
    """
    检测器，判断加密器用的是ECB还是CBC（构造有重复块明文，检测密文是否有重复块）
    """
    blocks = [ciphertext_bytes[i:i+16] for i in range(0,len(ciphertext_bytes),16)]
    count = Counter(blocks)
    # print(count)
    # print(max(count.values()))
    if max(count.values()) > 1:
        return 'ECB'
    else:
        return 'CBC'

if __name__ == '__main__':
    # 测试
    feature_block = random_series_generator(16)
    plaintext = b'b'*100
    total = 1000
    success = 0
    for _ in range(total):
        ciphertext_bytes,method = encryption_oracle(plaintext)
        pred = detect_ECB_or_CBC1(ciphertext_bytes)
        if pred == method:
            success += 1
    print(f'成功率{success/total}')


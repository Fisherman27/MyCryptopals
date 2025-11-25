# 2025.11.25
# 任务: 实现 ECB 模式字节逐位解密攻击（Byte-at-a-Time ECB Decryption Attack）
#       已知有一段明文，通过攻击（构造前缀，利用ECB模式特性）解密它。

# 背景：
# ### 题目背景（应用场景）
# 该题目模拟了一类**存在设计缺陷的加密系统场景**，核心是攻击者利用系统的加密逻辑漏洞，破解系统内部的固定秘密信息，具体场景可概括为：

# #### 1. 系统设定（对应题目中的 oracle 函数逻辑）
# - 系统具备一个加密接口，功能是对“用户输入数据 + 系统内部固定秘密字符串”的组合进行加密；
# - 加密规则：采用 AES-128-ECB 模式（确定性加密，无随机性），使用一个全局固定但攻击者未知的密钥；
# - 数据拼接规则：攻击者可自由传入任意前缀字符串（记为 S），系统会自动将内部的固定秘密字符串（记为 X，Base64 编码形式存储，需解码后使用）拼接在 S 之后，形成完整明文 `S + X`，再进行加密；
# - 输出：系统返回加密后的密文，攻击者可获取该密文。

# #### 2. 现实场景映射（题目模拟的真实潜在风险）
# 该设定对应现实中“系统需将用户可控输入与内部秘密信息结合后加密”的场景，典型例子包括：
# - 带秘密标识的用户数据加密：系统为验证数据归属，在用户提交的内容后拼接固定的用户秘密标识（如 API 密钥、隐藏 ID），再加密存储/传输；
# - 简单数据完整性验证：系统在用户上传数据后拼接固定验证密钥，加密后作为“签名”返回，用于后续验证数据未被篡改；
# - 含秘密参数的链接生成：系统将用户输入（如邮箱）与重置密钥拼接后加密，生成密码重置、身份验证等链接的核心参数。

# #### 3. 场景核心缺陷（攻击成立的前提）
# 该场景存在两个致命设计缺陷，也是题目让攻击者可破解的关键：
# - 加密模式缺陷：使用 ECB 模式（相同明文块对应相同密文块，缺乏随机性，为逐字节匹配提供可能）；
# - 数据处理缺陷：将内部秘密 X 以明文形式拼接在用户可控输入 S 之后（而非作为加密密钥或通过安全方式融合），且攻击者可获取完整拼接后的加密结果。

# #### 4. 攻击者目标
# 攻击者的核心目标是：**仅通过反复调用加密接口（传入不同 S、获取对应密文），破解出系统内部的固定秘密字符串 X 的完整内容**，无需获取加密密钥或侵入系统内部。

from set2_c11 import random_series_generator
KEY_BYTES = random_series_generator(16)

PLAINTEXT_BASE64 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'

from set2_c9 import pkcs7_padding
from set1_c7 import AES_128_ECB
import base64
def encryptor(your_input_bytes:bytes)->bytes:
    """
    适用于本任务的加密器：对 your_input || true_plaintext 填充后 进行加密
    """
    # 连接并填充
    plaintext_bytes = base64.b64decode(PLAINTEXT_BASE64)
    whole_text_bytes = your_input_bytes + plaintext_bytes
    # 符合规范的填充
    whole_text_bytes = pkcs7_padding(whole_text_bytes,16)
    # 加密
    encryptor = AES_128_ECB(KEY_BYTES)
    cipertext_bytes = encryptor.encrypt(whole_text_bytes)
    return cipertext_bytes

def find_unknown_byte(target:int,known_plaintext_bytes:bytes)->bytes:
    """
    解密未知明文第target个字节
    """
    prefix = b'a' * (16-(target+1)%16) + known_plaintext_bytes
    block_position = len(prefix) // 16
    block_start = block_position * 16
    block_end = block_start + 16
    # 构造映射表
    cipher_byte_dict = {}
    for byte in range(256):
        cipher_block = encryptor(prefix + bytes([byte]))[block_start:block_end]
        cipher_byte_dict[cipher_block] = bytes([byte])
    # 获得未知明文第target个字节
    true_cipher_block = encryptor(b'a' * (16-(target+1)%16))[block_start:block_end]
    if true_cipher_block in cipher_byte_dict:
        unknown_byte = cipher_byte_dict[true_cipher_block]
        return unknown_byte
    else:
        return 'OVER'

    

from set2_c11 import detect_ECB_or_CBC1
if __name__ == '__main__':
    # 第一步确定块的大小
    print('Step1：确定block的大小（利用分组密码会补全block的特性）：')
    block_size = 0
    current_cipher_length = 0
    temp_block_size = 0
    for input_size in range(1,100):
        my_imput = b'a'*input_size
        cipertext_bytes = encryptor(my_imput)
        if current_cipher_length != len(cipertext_bytes):
            current_cipher_length = len(cipertext_bytes)
            if block_size < temp_block_size:
                block_size = temp_block_size
            temp_block_size = 1
        else:
            temp_block_size += 1
    print(f'块大小为：{block_size}\n')    

    # 第二步确定使用的是ECB模式
    print('Step2：确定使用的加密模式（利用ECB模式会重复加密相同块的特性）：')
    my_input = b'a'*100
    cipertext_bytes = encryptor(my_input)
    method = detect_ECB_or_CBC1(cipertext_bytes)
    print(f'使用的加密模式为：{method}\n')

    # 第三步，构造前缀，利用ECB模式特性，解密出明文
    print('Step3：构造前缀，利用ECB模式特性，解密出明文：')
    print("思路是，利用前缀b'a'*15,给明文补充所有可能的第16个字节获得一个‘第16个字节-密文’对应表；")
    print("然后，将未知明文第一个字节补充为前缀的第16个字节，加密后，查表获得未知明文的第一个字节。")
    print("接着构造前缀b'a'*14+unknown[0],补充所有可能的第16个字节，获得一个‘第16个字节-密文’对应表;")
    print("然后，将未知明文第二个字节补充为前缀的第16个字节，加密后，查表获得未知明文的第二个字节。")
    print("重复以上过程，直到解密出未知明文所有字节。")

    known_plaintext = b''
    for target in range(200):
        unknown_byte = find_unknown_byte(target,known_plaintext)
        if unknown_byte == 'OVER':
            known_plaintext = known_plaintext[:-1]
            break
        known_plaintext += unknown_byte
        print(f'unknown[{target}]为：{unknown_byte}')
    print(f'猜测的未知明文为：{known_plaintext}')
    print(f'原始未知明文为：{base64.b64decode(PLAINTEXT_BASE64)}')

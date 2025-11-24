# 2025.11.14
# 任务：破解维吉尼亚密码

# 注意，此时文件里的密文是Base64编码的，需要先解码
import base64
def read_and_decode_cipher(file_path: str) -> bytes:
    '''读取Base64编码的密文文件，返回解码后的字节格式密文'''
    with open(file_path, 'r', encoding='utf-8') as f:
        base64_str = ''.join(line.strip() for line in f)  # 去除换行，拼接Base64字符串
    return base64.b64decode(base64_str)  # 解码为真实密文字节
# b'\x1dB\x1fM\x0b\x0f\x02\x1fO\x13N<\x1aie'能打印出来就打印，打印不出来就用十六进制字符
# cipher[0] = b'\x1d' = 29
# cipher[1] = ord('B') = 66


# =============================================================================
# method1:借助c3.py里面的方法，计算有效字符数量作为得分
# =============================================================================

from set1_c5 import repeating_key_xor
from set1_c3 import single_byte_xor,evaluate_plaintext
def method1(cipher_hex):
    cipher_bytes = bytes.fromhex(cipher_hex)
    # 方法一：借助c3.py里面，计算有效字符数量作为得分
    print('使用c3.py的方法：')
    # 探索密钥长度为1-20时，得分的变化，留意需要平衡选取的字符长度
    BEST_SCORE = 0
    BEST_KEYSIZE = None
    BEST_KEY = None
    for keysize in range(1,31):
        print(f'Keysize: {keysize}')
        score = 0
        # 获取keysize时，一段用同一个字节XOR加密后的密文为一个block
        # 记录下所有block的十六进制表示
        blocks_hex = []
        for keyi in range(0,keysize*2,2):
            block_hex = '' 
            for i in range(keyi, len(cipher), keysize*2):
                block_hex += cipher_hex[i:i+2]
            blocks_hex.append(block_hex)
        # 下面对每一个block_hex，计算得分（取最高值）,并累加进该keysize下的总得分
        blocks_score = []
        blocks_key_int = []
        for block_index,block_hex in enumerate(blocks_hex):
            # print(f'\tBlock {block_index}')
            best_score = 0
            best_key = None
            for key_int in range(32,256):
                temp_score = evaluate_plaintext(single_byte_xor(block_hex,key_int))
                # print(f'\t\tKey: {key_int}, Score: {temp_score}')
                if temp_score > best_score:
                    best_score = temp_score
                    best_key = key_int
            blocks_score.append(best_score)
            blocks_key_int.append(best_key)
            score += best_score
            # break
        if score > BEST_SCORE:
            BEST_SCORE = score
            BEST_KEYSIZE = keysize
            BEST_KEY = blocks_key_int
        print(f'\tScore: {score}, Keysize: {keysize}')
        print(f'\tKeys: {blocks_key_int}')
    print()
    BEST_KEY = ''.join([chr(key) for key in BEST_KEY])
    print(f'Best Keysize: {BEST_KEYSIZE}, Best Key: {BEST_KEY}')
        

from set1_c5 import repeating_key_xor
from set1_c3 import single_byte_xor, evaluate_plaintext

def method1_by_bit(cipher_hex):
    # 将十六进制字符串转换为比特字符串（每个字节对应8位比特）
    def hex_to_bitstring(hex_str):
        bit_str = ""
        for c in hex_str:
            # 每个十六进制字符转换为4位比特（补前导零）
            bit_str += bin(int(c, 16))[2:].zfill(4)
        return bit_str
    
    # 将比特字符串转换为十六进制字符串（每4位比特对应1个十六进制字符）
    def bitstring_to_hex(bit_str):
        hex_str = ""
        # 确保比特数是4的倍数（补0对齐）
        if len(bit_str) % 4 != 0:
            bit_str += "0" * (4 - len(bit_str) % 4)
        for i in range(0, len(bit_str), 4):
            hex_char = hex(int(bit_str[i:i+4], 2))[2:]
            hex_str += hex_char
        return hex_str
    
    # 1. 将密文十六进制转换为比特字符串
    cipher_bits = hex_to_bitstring(cipher_hex)
    cipher_bytes_len = len(cipher_hex) // 2  # 原始密文字节长度
    print('使用比特操作提取块的方法：')
    
    BEST_SCORE = 0
    BEST_KEYSIZE = None
    BEST_KEY = None
    
    # 测试密钥长度（这里保持只测试29，可根据需要调整范围）
    for keysize in range(1, 31):
        print(f'Keysize: {keysize}')
        total_score = 0
        blocks_bit = []  # 存储每个块的比特字符串
        
        # 2. 按密钥长度（字节）从比特层面提取转置块
        # 每个密钥字节对应8位比特，转置块按比特索引间隔 keysize*8 提取
        for keyi in range(keysize):
            block_bits = ""
            # 计算当前块在比特层面的起始位置（keyi字节 → keyi*8比特）
            start_bit = keyi * 8
            # 按间隔 keysize*8 比特提取（等价于字节间隔 keysize）
            for i in range(start_bit, len(cipher_bits), keysize * 8):
                # 每次提取8比特（1字节），避免越界
                if i + 8 <= len(cipher_bits):
                    block_bits += cipher_bits[i:i+8]
            blocks_bit.append(block_bits)
        
        # 3. 将每个比特块转换为十六进制，进行单字节破解
        blocks_key_int = []
        for block_index, block_bits in enumerate(blocks_bit):
            # 比特块 → 十六进制字符串（适配single_byte_xor函数）
            block_hex = bitstring_to_hex(block_bits)
            best_score = 0
            best_key = None
            
            # 尝试所有可能的单字节密钥（32-255，包含可打印字符）
            for key_int in range(32, 256):
                temp_score = evaluate_plaintext(single_byte_xor(block_hex, key_int))
                if temp_score > best_score:
                    best_score = temp_score
                    best_key = key_int
            
            blocks_key_int.append(best_key)
            total_score += best_score
        
        # 4. 更新最佳密钥信息
        if total_score > BEST_SCORE:
            BEST_SCORE = total_score
            BEST_KEYSIZE = keysize
            BEST_KEY = blocks_key_int
        
        print(f'\t总得分: {total_score}, 密钥长度: {keysize}')
        print(f'\t密钥（整数）: {blocks_key_int}')
    
    # 5. 转换最佳密钥为字符串
    BEST_KEY_STR = ''.join([chr(key) if 32 <= key <= 126 else '?' for key in BEST_KEY])
    print(f'\n最佳密钥长度: {BEST_KEYSIZE}, 最佳密钥: {BEST_KEY_STR}')
    return BEST_KEYSIZE, BEST_KEY_STR

# =============================================================================
# method2:借助汉明距离
# =============================================================================

if __name__ == "__main__":
    cipher = read_and_decode_cipher(r't6.txt') # bytes类型 
    cipher_hex = cipher.hex()
    method1(cipher_hex)
    print()
    method1_by_bit(cipher_hex)
    print()
    print()
    print()



        # print(f'Keysize: {keysize}, Coincidence Index: {cal_coincidence_index(part)}')
    # real_keysize = 4
    # print(f'观察重合指数，猜测的密钥长度为：{real_keysize}')
    # plaintext = repeating_key_xor_decrypt(cipher,real_keysize)
    # print(f'最终解密结果为：{plaintext}')
    
###
# base64编码：有时仅支持ASCII字符的传输媒介（如电子邮件），需要将二进制数据转换为文本格式进行传输，于是进行Base64编码。
#             其编码后的字符串没有任何直接意义，只是为了传输方便。

    